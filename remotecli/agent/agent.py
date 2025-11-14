import os
import platform
import socket
import uuid
import requests
from pathlib import Path
from typing import Dict, List
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

def fetch_policy(server_url: str, token: str, os_name: str) -> Dict:
    r = requests.get(f"{server_url}/policy?os={os_name}", headers={"Authorization": f"Bearer {token}"}, timeout=10)
    r.raise_for_status()
    return r.json()

def post_findings(server_url: str, token: str, payload: Dict):
    r = requests.post(f"{server_url}/agent/report", json=payload, headers={"Authorization": f"Bearer {token}"}, timeout=15)
    r.raise_for_status()
    return r.json()

def run_once(server_url: str, token: str, auto_remediate: bool = False):
    dev_id = device_id()
    upsert_device(dev_id, hostname(), os_name())
    policy_resp = fetch_policy(server_url, token, os_name())
    policy_text = policy_resp["policy"]
    signature = policy_resp.get("signature")
    key_id = policy_resp.get("key_id")
    if signature and key_id:
        ok = verify_policy_signature(policy_text, signature, key_id)
        if not ok:
            raise RuntimeError("Policy signature verification failed")
    policy = load_policy(policy_text)
    findings = evaluate_rules(policy)

    if auto_remediate:
        for r in policy.get("rules", []):
            f = next((x for x in findings if x["rule_id"] == r["id"]), None)
            if f and not f["compliant"]:
                apply_remediation(r)

    payload = {
        "device_id": dev_id,
        "hostname": hostname(),
        "os": os_name(),
        "findings": findings,
        "policy_version": policy.get("version","unknown")
    }
    return post_findings(server_url, token, payload)