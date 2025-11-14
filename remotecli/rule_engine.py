import platform
import subprocess
import yaml
from typing import Dict, List, Tuple

def load_policy(yaml_text: str) -> Dict:
    return yaml.safe_load(yaml_text)

def detect_os() -> str:
    sys = platform.system().lower()
    if "windows" in sys:
        return "windows"
    if "linux" in sys:
        return "linux"
    return "unknown"

def run_check(cmd: List[str]) -> Tuple[bool, str]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        ok = res.returncode == 0
        out = res.stdout.strip() + ("\n" + res.stderr.strip() if res.stderr else "")
        return ok, out
    except Exception as e:
        return False, f"error: {e}"

def evaluate_rules(policy: Dict) -> List[Dict]:
    os = detect_os()
    rules = policy.get("rules", [])
    findings = []
    for r in rules:
        if r.get("os") and r["os"] != os:
            continue
        cmd = r.get("check_cmd")
        if not cmd:
            findings.append({
                "rule_id": r["id"], "category": r["category"], "compliant": False,
                "severity": r.get("severity","medium"),
                "details": "missing check_cmd"
            })
            continue
        ok, details = run_check(cmd)
        findings.append({
            "rule_id": r["id"],
            "category": r["category"],
            "compliant": ok,
            "severity": r.get("severity","medium"),
            "details": details or ""
        })
    return findings

def apply_remediation(r: Dict) -> Tuple[bool, str]:
    fix = r.get("fix_cmd")
    if not fix:
        return False, "no fix_cmd"
    return run_check(fix)