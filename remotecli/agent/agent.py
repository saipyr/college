import os
import platform
import socket
import uuid
import time
import logging
import requests
from pathlib import Path
from typing import Dict, List
import psutil
from ..storage import upsert_device
from ..rule_engine import load_policy, evaluate_rules, apply_remediation
from ..security import verify_policy_signature

def device_id() -> str:
    return str(uuid.getnode())

def hostname() -> str:
    return socket.gethostname()

def os_name() -> str:
    s = platform.system().lower()
    return "windows" if "windows" in s else "linux" if "linux" in s else s

def _retry(fn, attempts: int = None, base_delay: float = 0.5):
    max_attempts = attempts or int(os.getenv("AGENT_MAX_RETRIES", "3"))
    last_exc = None
    for i in range(max_attempts):
        try:
            return fn()
        except Exception as e:
            last_exc = e
            time.sleep(base_delay * (2 ** i))
    raise last_exc

def fetch_policy(server_url: str, token: str, os_name: str, dev_id: str) -> Dict:
    if not server_url.lower().startswith("https://") and os.getenv("AGENT_ALLOW_HTTP", "0") != "1":
        raise RuntimeError("Agent requires HTTPS server_url; set AGENT_ALLOW_HTTP=1 to override")
    def _call():
        r = requests.get(
            f"{server_url}/policy?os={os_name}&device_id={dev_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        r.raise_for_status()
        return r.json()
    return _retry(_call)

def post_findings(server_url: str, token: str, payload: Dict):
    def _call():
        r = requests.post(
            f"{server_url}/agent/report",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        r.raise_for_status()
        return r.json()
    return _retry(_call)

def run_once(server_url: str, token: str, auto_remediate: bool = False):
    logger = logging.getLogger("sehcs-agent")
    logger.setLevel(logging.INFO)
    dev_id = device_id()
    upsert_device(dev_id, hostname(), os_name())
    policy_resp = fetch_policy(server_url, token, os_name(), dev_id)
    policy_text = policy_resp["policy"]
    signature = policy_resp.get("signature")
    key_id = policy_resp.get("key_id")
    if signature and key_id:
        ok = verify_policy_signature(policy_text, signature, key_id)
        if not ok:
            raise RuntimeError("Policy signature verification failed")
    policy = load_policy(policy_text)
    cpu_max = float(os.getenv("AGENT_CPU_MAX", "5"))
    backoff = float(os.getenv("AGENT_BACKOFF_SEC", "0.5"))
    while True:
        cpu = psutil.cpu_percent(interval=0.1)
        if cpu <= cpu_max:
            break
        time.sleep(backoff)
    findings = evaluate_rules(policy)
    overrides = policy_resp.get("overrides") or []
    if overrides:
        for rid in overrides:
            f = next((x for x in findings if x["rule_id"] == rid), None)
            if f:
                f["compliant"] = True
                f["details"] = (f.get("details", "") + "; waived").strip("; ")

    if auto_remediate:
        for r in policy.get("rules", []):
            f = next((x for x in findings if x["rule_id"] == r["id"]), None)
            if f and not f["compliant"]:
                try:
                    ok, details = apply_remediation(r)
                    logger.info(f"Remediation rule={r['id']} ok={ok} details={details}")
                except Exception as e:
                    logger.warning(f"Remediation error rule={r['id']} err={e}")

    payload = {
        "device_id": dev_id,
        "hostname": hostname(),
        "os": os_name(),
        "findings": findings,
        "policy_version": policy.get("version","unknown"),
        "telemetry": {"cpu_percent": psutil.cpu_percent(interval=0.0)}
    }
    return post_findings(server_url, token, payload)