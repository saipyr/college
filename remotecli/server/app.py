from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.cors import CORSMiddleware
from fastapi import BackgroundTasks
from pathlib import Path
import os
import time
from pydantic import BaseModel
from typing import Optional, List
import asyncio
import io
import csv

from ..storage import (
    init_db, get_user, add_command, list_commands, list_users, get_credential,
    get_latest_policy, add_finding, list_findings, upsert_device,
    add_audit_event, list_policy_overrides, get_exec_allow, add_exec_allow, delete_exec_allow, list_exec_allowlist,
    add_policy, list_policy_keys, set_active_policy_key, add_policy_key, add_credential, list_credentials, delete_credential,
    add_control, map_control_rule, unmap_control_rule, list_controls
)
from ..security import verify_password, make_jwt, verify_jwt, sign_policy_with_active_key
from ..ssh_client import ssh_run_command
from ..winrm_client import winrm_run_command
from ..discovery import discover_cidr
from ..alerts import emit_alert
from ..reports import generate_pdf
from ..rule_engine import load_policy
from ..prd_import import load_prd_xlsx

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

app = FastAPI(title="SEHCS Server", version="0.3.0")
auth_scheme = HTTPBearer()

# Security middleware
app.add_middleware(HTTPSRedirectMiddleware)
trusted = (os.getenv("TRUSTED_HOSTS") or "*").split(",")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=[h.strip() for h in trusted])
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("CORS_ALLOW_ORIGINS", "").strip()] if os.getenv("CORS_ALLOW_ORIGINS") else [],
    allow_credentials=False,
    allow_methods=["GET","POST"],
    allow_headers=["Authorization","Content-Type"],
)

@app.on_event("startup")
def startup():
    init_db()
    try:
        import asyncio
        asyncio.create_task(_schedule_reports())
    except Exception:
        pass
    if os.getenv("SEED_CONTROLS", "0") == "1":
        _seed_controls()
    if os.getenv("IMPORT_CONTROLS_FROM_POLICY", "0") == "1":
        try:
            _import_controls_from_policies()
        except Exception:
            pass

def require_auth(creds: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    try:
        claims = verify_jwt(creds.credentials)
        jti = claims.get("jti")
        if jti:
            from ..storage import is_jwt_revoked
            if is_jwt_revoked(jti):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")
        return claims
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def require_role(allowed: List[str]):
    def _inner(claims=Depends(require_auth)):
        role = claims.get("role")
        if role not in allowed:
            raise HTTPException(status_code=403, detail="insufficient role")
        return claims
    return _inner

class LoginRequest(BaseModel):
    username: str
    password: str

class ExecRequest(BaseModel):
    channel: str  # ssh | winrm
    host: str
    command: str
    credential_name: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    key_file: Optional[str] = None
    port: Optional[int] = None
    timeout: Optional[int] = 30
    powershell: Optional[bool] = True
    use_https: Optional[bool] = False
    transport: Optional[str] = "ntlm"
    insecure: Optional[bool] = True

class DiscoverRequest(BaseModel):
    cidr: str

class PolicyResponse(BaseModel):
    version: str
    os: str
    policy: str
    signature: Optional[str] = None
    key_id: Optional[str] = None
    overrides: Optional[List[str]] = None

_rate_state = {}

def _rate_key(request: Request, user: Optional[str] = None) -> str:
    ip = request.client.host if request.client else "unknown"
    return f"{ip}:{user or ''}"

def _rate_limit(key: str, limit: int, window_sec: int) -> bool:
    now = int(time.time())
    w, c = _rate_state.get(key, (now, 0))
    if now - w >= window_sec:
        w, c = now, 0
    c += 1
    _rate_state[key] = (w, c)
    return c <= limit

class AgentReport(BaseModel):
    device_id: str
    hostname: str
    os: str
    policy_version: str
    findings: List[dict]
    telemetry: Optional[dict] = None

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/auth/login")
def login(body: LoginRequest, request: Request):
    rk = _rate_key(request)
    if not _rate_limit(rk, limit=int(os.getenv("RL_LOGIN_LIMIT", "20")), window_sec=60):
        raise HTTPException(status_code=429, detail="Too many login attempts")
    u = get_user(body.username)
    if not u:
        add_audit_event("login_fail", body.username, "invalid user", rk)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(body.password, u["password_hash"]):
        add_audit_event("login_fail", body.username, "bad password", rk)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = make_jwt(body.username, u["role"])
    add_audit_event("login_success", body.username, "", rk)
    return {"token": token, "role": u["role"]}

@app.post("/exec")
def exec_command(body: ExecRequest, request: Request, claims=Depends(require_role(["admin"]))):
    rk = _rate_key(request, claims.get("sub"))
    if not _rate_limit(rk, limit=int(os.getenv("RL_EXEC_LIMIT", "50")), window_sec=60):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    max_cmd = int(os.getenv("MAX_CMD_LEN", "2000"))
    if len(body.command) > max_cmd:
        raise HTTPException(status_code=413, detail="Command too long")
    actor = claims["sub"]
    allow = get_exec_allow(body.host, body.channel)
    if not allow:
        raise HTTPException(status_code=403, detail="target not allowed")
    role_order = {"readonly": 0, "auditor": 1, "admin": 2}
    if role_order.get(claims.get("role"), -1) < role_order.get(allow["min_role"], 0):
        raise HTTPException(status_code=403, detail="insufficient role for target")
    if body.credential_name:
        c = get_credential(body.credential_name)
        if not c:
            raise HTTPException(status_code=400, detail="Credential not found")
        ctype, data = c
        if body.channel != ctype:
            raise HTTPException(status_code=400, detail="Credential type mismatch")
        body.username = data.get("username")
        body.password = data.get("password")
        body.key_file = data.get("key_file")

    if body.channel == "ssh":
        code, out, err = ssh_run_command(
            host=body.host,
            port=body.port or 22,
            username=body.username,
            password=body.password,
            key_file=body.key_file,
            command=body.command,
            timeout=body.timeout,
        )
    elif body.channel == "winrm":
        if not body.use_https and os.getenv("ALLOW_WINRM_HTTP", "0") != "1":
            raise HTTPException(status_code=400, detail="WinRM over HTTP is disabled; use HTTPS or set ALLOW_WINRM_HTTP=1")
        if body.use_https and body.insecure and os.getenv("ALLOW_INSECURE_WINRM", "0") != "1":
            raise HTTPException(status_code=400, detail="Insecure WinRM HTTPS is disabled; set ALLOW_INSECURE_WINRM=1 to allow")
        code, out, err = winrm_run_command(
            host=body.host,
            username=body.username,
            password=body.password,
            command=body.command,
            powershell=body.powershell,
            use_https=body.use_https,
            port=body.port,
            transport=body.transport,
            insecure=body.insecure,
        )
    else:
        raise HTTPException(status_code=400, detail="Unsupported channel")

    add_command(actor=actor, target=body.host, channel=body.channel,
                command=body.command, exit_code=code, stdout=out, stderr=err)
    add_audit_event("exec", actor, f"{body.channel} {body.host} exit={code}", rk)
    return {"exit_code": code, "stdout": out, "stderr": err}

@app.post("/discover")
async def discover(body: DiscoverRequest, request: Request, claims=Depends(require_role(["admin","auditor"]))):
    rk = _rate_key(request, claims.get("sub"))
    if not _rate_limit(rk, limit=int(os.getenv("RL_DISCOVER_LIMIT", "10")), window_sec=60):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    result = await discover_cidr(body.cidr)
    add_audit_event("discover", claims.get("sub"), f"{body.cidr} hosts={len(result)}", rk)
    return {"hosts": result}

@app.get("/history")
def history(limit: int = 50, claims=Depends(require_role(["admin","auditor"]))):
    rows = list_commands(limit=limit, actor=None)
    return {"items": [dict(r) for r in rows]}

@app.get("/users")
def users(claims=Depends(require_role(["admin"]))):
    return {"users": [{"username": r["username"], "role": r["role"]} for r in list_users()]}

@app.get("/policy", response_model=PolicyResponse)
def get_policy(os: str, request: Request, device_id: Optional[str] = None, claims=Depends(require_role(["admin","auditor","readonly"]))):
    if os not in ("windows","linux"):
        raise HTTPException(status_code=400, detail="Unsupported OS")
    row = get_latest_policy(os)
    if not row:
        raise HTTPException(status_code=404, detail="policy not found")
    if not (row["signed"] and row["signature"] and row["key_id"]):
        raise HTTPException(status_code=409, detail="policy not signed")
    overrides = []
    if device_id:
        overrides = [o["rule_id"] for o in list_policy_overrides(device_id)]
    add_audit_event("policy_get", claims.get("sub"), f"{os} overrides={len(overrides)}", _rate_key(request, claims.get("sub")))
    return {"version": row["version"], "os": row["os"], "policy": row["content"], "signature": row["signature"], "key_id": row["key_id"], "overrides": overrides}

@app.post("/agent/report")
def agent_report(body: AgentReport, request: Request, claims=Depends(require_role(["admin","auditor","readonly"]))):
    rk = _rate_key(request, body.device_id)
    if not _rate_limit(rk, limit=int(os.getenv("RL_REPORT_LIMIT", "120")), window_sec=60):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    bound = claims.get("device_id")
    if os.getenv("ALLOW_AGENT_ANY", "0") != "1" and bound and bound != body.device_id:
        raise HTTPException(status_code=403, detail="device_id claim mismatch")
    upsert_device(body.device_id, body.hostname, body.os)
    non_compliant = []
    for f in body.findings:
        add_finding(device_id=body.device_id, rule_id=f["rule_id"], category=f["category"],
                    compliant=bool(f["compliant"]), severity=f.get("severity","medium"),
                    details=f.get("details",""))
        if not f["compliant"]:
            non_compliant.append(f)
    if non_compliant:
        high = [f for f in non_compliant if f.get("severity","").lower() == "high"]
        msg = f"{body.device_id} non-compliant: {len(non_compliant)} rules; high: {len(high)}"
        emit_alert("warning" if not high else "critical", msg, device_id=body.device_id)
    cpu = (body.telemetry or {}).get("cpu_percent", "")
    add_audit_event("agent_report", body.device_id, f"findings={len(body.findings)} noncompliant={len(non_compliant)} cpu={cpu}", rk)
    return {"status": "ok"}

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, claims=Depends(require_role(["admin","auditor"]))):
    items = list_findings(limit=500)
    # Compute compliance per device
    summary = {}
    for f in items:
        d = summary.setdefault(f["device_id"], {"total": 0, "pass": 0})
        d["total"] += 1
        if f["compliant"]:
            d["pass"] += 1
    data = [{"device_id": k, "score": (v["pass"]/v["total"]*100 if v["total"] else 0)} for k,v in summary.items()]
    return templates.TemplateResponse("dashboard.html", {"request": request, "devices": data})

@app.get("/metrics")
def metrics(claims=Depends(require_role(["admin","auditor"]))):
    items = list_findings(limit=100000)
    devices = {}
    categories = {}
    total = 0
    passed = 0
    for r in items:
        total += 1
        if r["compliant"]:
            passed += 1
        d = devices.setdefault(r["device_id"], {"total": 0, "pass": 0})
        d["total"] += 1
        if r["compliant"]:
            d["pass"] += 1
        c = categories.setdefault(r["category"], {"total": 0, "pass": 0})
        c["total"] += 1
        if r["compliant"]:
            c["pass"] += 1
    fleet_score = (passed/total*100) if total else 0
    device_scores = [{"device_id": k, "score": (v["pass"]/v["total"]*100 if v["total"] else 0)} for k,v in devices.items()]
    category_scores = [{"category": k, "score": (v["pass"]/v["total"]*100 if v["total"] else 0)} for k,v in categories.items()]
    return {"fleet_score": fleet_score, "devices": device_scores, "categories": category_scores}

@app.get("/report/csv")
def report_csv(claims=Depends(require_role(["admin","auditor"]))):
    items = list_findings(limit=10000)
    sio = io.StringIO()
    writer = csv.writer(sio)
    writer.writerow(["ts","device_id","rule_id","category","compliant","severity","details"])
    for r in items:
        writer.writerow([r["ts"], r["device_id"], r["rule_id"], r["category"], r["compliant"], r["severity"], r["details"]])
    return StreamingResponse(iter([sio.getvalue()]), media_type="text/csv")

@app.get("/report/pdf")
def report_pdf(claims=Depends(require_role(["admin","auditor"]))):
    items = list_findings(limit=10000)
    pdf_bytes = generate_pdf([dict(r) for r in items])
    return StreamingResponse(iter([pdf_bytes]), media_type="application/pdf")

def _ntro_event(r):
    return {"ts": r["ts"], "type": r["event_type"], "actor": r["actor"], "details": r["details"], "key": r["key"]}

@app.get("/audit/export")
def audit_export(limit: int = 1000, claims=Depends(require_role(["admin","auditor"]))):
    rows = list_audit_events(limit=limit)
    return {"events": [_ntro_event(r) for r in rows]}

async def _schedule_reports():
    interval = int(os.getenv("REPORT_INTERVAL_MIN", "1440"))
    reports_dir = Path.home() / ".remotecli" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    while True:
        try:
            items = list_findings(limit=10000)
            pdf_bytes = generate_pdf([dict(r) for r in items])
            ts = int(time.time())
            (reports_dir / f"report_{ts}.pdf").write_bytes(pdf_bytes)
        except Exception:
            pass
        await asyncio.sleep(interval * 60)

def _seed_controls():
    # Windows controls mapped to rule IDs
    win_map = {
        "WIN.ACC.MINLEN": ["WIN-ACC-001"],
        "WIN.ACC.HISTORY": ["WIN-ACC-002"],
        "WIN.ACC.MAXAGE": ["WIN-ACC-003"],
        "WIN.ACC.COMPLEXITY": ["WIN-ACC-004"],
        "WIN.ACC.REVENC": ["WIN-ACC-005"],
        "WIN.ACC.MINAGE": ["WIN-ACC-006"],
        "WIN.LOCK.THRESH": ["WIN-LOCK-001"],
        "WIN.LOCK.DURATION": ["WIN-LOCK-002"],
        "WIN.SEC.GUEST": ["WIN-SEC-001"],
        "WIN.SEC.LEGALNOTICE": ["WIN-SEC-002"],
        "WIN.SEC.BLOCK_MS_ACCOUNTS": ["WIN-SEC-003"],
        "WIN.SEC.CTRL_ALT_DEL": ["WIN-SEC-004"],
        "WIN.SEC.LIMIT_BLANK_PASSWORD": ["WIN-SEC-005"],
        "WIN.SEC.RENAME_ADMIN": ["WIN-SEC-006"],
        "WIN.SEC.RENAME_GUEST": ["WIN-SEC-007"],
        "WIN.SEC.INACTIVITY": ["WIN-SEC-008"],
        "WIN.UAC.ADMINAPPROVAL": ["WIN-UAC-001"],
        "WIN.UAC.SECUREDESKTOP": ["WIN-UAC-002"],
        "WIN.FW.ON": ["WIN-FW-001"],
        "WIN.FW.LOG": ["WIN-FW-LOG-001"],
        "WIN.FW.DEFAULTS": ["WIN-FW-DEF-001"],
        "WIN.AUD.ACCOUNTLOGON": ["WIN-AUDIT-001"],
        "WIN.AUD.PROCESSCREATION": ["WIN-AUDIT-002"],
        "WIN.AUD.PRIVILEGEUSE": ["WIN-AUDIT-003"],
        "WIN.AUD.POLICYCHANGE": ["WIN-AUDIT-004"],
        "WIN.AUD.CREDVALID": ["WIN-AUDIT-005"],
        "WIN.AUD.SECGROUPMGMT": ["WIN-AUDIT-006"],
        "WIN.AUD.REMOVABLE": ["WIN-AUDIT-007"],
        "WIN.AUD.FILESHARE": ["WIN-AUDIT-008"],
        "WIN.AUD.SYSINTEGRITY": ["WIN-AUDIT-009"],
        "WIN.NET.SMBV1": ["WIN-NET-001"],
        "WIN.SVC.REMOTEREGISTRY": ["WIN-SVC-001"],
        "WIN.SVC.XBOX": ["WIN-SVC-002"],
        "WIN.SVC.BLUETOOTH": ["WIN-SVC-004"],
        "WIN.SVC.RDP": ["WIN-SVC-005"],
        "WIN.SVC.WINRM": ["WIN-SVC-006"],
        "WIN.SVC.W3SVC": ["WIN-SVC-007"],
        "WIN.SVC.UPNP": ["WIN-SVC-008"],
        "WIN.SVC.SNMP_TELNET": ["WIN-SVC-003"],
        "WIN.SVC.SNMP_TRAP": ["WIN-SVC-013"],
        "WIN.SVC.REMOTE_ACCESS": ["WIN-SVC-014"],
        "WIN.SVC.RASMAN": ["WIN-SVC-015"],
        "WIN.SVC.REMOTE_ASSISTANCE": ["WIN-SVC-016"],
        "WIN.SVC.ICS": ["WIN-SVC-009"],
        "WIN.SVC.FUNCTION_DISCOVERY_PH": ["WIN-SVC-010"],
        "WIN.SVC.FUNCTION_DISCOVERY_RP": ["WIN-SVC-011"],
        "WIN.SVC.WMP_NETWORK": ["WIN-SVC-012"],
        "WIN.DEF.APPGUARD_ENABLED": ["WIN-DEF-001"],
        "WIN.RIGHTS.LOCALLOGON": ["WIN-RIGHTS-001"],
        "WIN.RIGHTS.NETWORKLOGON": ["WIN-RIGHTS-002"],
        "WIN.RIGHTS.CREDS_MANAGER": ["WIN-RIGHTS-003"],
        "WIN.RIGHTS.CHANGE_TIME": ["WIN-RIGHTS-004"],
        "WIN.RIGHTS.DENY_LOCAL": ["WIN-RIGHTS-005"],
        "WIN.RIGHTS.DENY_NETWORK": ["WIN-RIGHTS-006"],
        "WIN.RIGHTS.RDP_LOGON": ["WIN-RIGHTS-007"],
    }
    for cid, rules in win_map.items():
        add_control("windows", cid, cid)
        for rid in rules:
            map_control_rule(cid, rid)
    # Linux controls mapped to rule IDs
    lin_map = {
        "LIN.FS.BLACKLIST": ["LIN-FS-001"],
        "LIN.FS.PARTITIONS": ["LIN-FS-002"],
        "LIN.FS.TMPFLAGS": ["LIN-FS-003"],
        "LIN.FS.DEVSHM_FLAGS": ["LIN-FS-004"],
        "LIN.FS.VARTMP_FLAGS": ["LIN-FS-005"],
        "LIN.BOOT.GRUBPWD": ["LIN-BOOT-001"],
        "LIN.KERN.ASLR": ["LIN-SYSCTL-001"],
        "LIN.KERN.PTRACE": ["LIN-SYSCTL-002"],
        "LIN.KERN.COREDUMP": ["LIN-DUMP-001"],
        "LIN.LOGIN.BANNER": ["LIN-LOGIN-001"],
        "LIN.SVC.DISABLEINSECURE": ["LIN-SVC-001"],
        "LIN.SVC.AUTOFS": ["LIN-SVC-002"],
        "LIN.SVC.AVAHI": ["LIN-SVC-003"],
        "LIN.SVC.DHCPD": ["LIN-SVC-004"],
        "LIN.SVC.DNS": ["LIN-SVC-005"],
        "LIN.SVC.LDAPD": ["LIN-SVC-006"],
        "LIN.SVC.NFS": ["LIN-SVC-007"],
        "LIN.SVC.RPCBIND": ["LIN-SVC-008"],
        "LIN.SVC.SAMBA": ["LIN-SVC-009"],
        "LIN.SVC.SNMPD": ["LIN-SVC-010"],
        "LIN.SVC.TFTP": ["LIN-SVC-011"],
        "LIN.SVC.APACHE": ["LIN-SVC-012"],
        "LIN.SVC.NGINX": ["LIN-SVC-013"],
        "LIN.SVC.XINETD": ["LIN-SVC-014"],
        "LIN.SVC.X11": ["LIN-SVC-015"],
        "LIN.TIME.SYNC": ["LIN-TIME-001"],
        "LIN.CRON.ACTIVE": ["LIN-CRON-001"],
        "LIN.CRON.PERMISSIONS": ["LIN-CRON-002"],
        "LIN.NET.IPV6": ["LIN-NET-001"],
        "LIN.FW.DEFAULTDENY": ["LIN-FW-001"],
        "LIN.FW.LOG": ["LIN-FW-LOG-001"],
        "LIN.FW.LOOPBACK": ["LIN-FW-LOOP-001"],
        "LIN.FW.IPTABLES_PERSISTENT": ["LIN-IPTABLES-PERSIST-001"],
        "LIN.SSH.ROOTLOGIN": ["LIN-SSH-001"],
        "LIN.SSH.PASSAUTH": ["LIN-SSH-002"],
        "LIN.SSH.BANNER": ["LIN-SSH-003"],
        "LIN.SSH.CIPHERS": ["LIN-SSH-004"],
        "LIN.SSH.KEX": ["LIN-SSH-005"],
        "LIN.SSH.MACS": ["LIN-SSH-006"],
        "LIN.SSH.MAXAUTHTRIES": ["LIN-SSH-007"],
        "LIN.SSH.MAXSESSIONS": ["LIN-SSH-008"],
        "LIN.SSH.GRACETIME": ["LIN-SSH-009"],
        "LIN.SSH.FORWARDING": ["LIN-SSH-010"],
        "LIN.SUDO.LOG": ["LIN-SUDO-001"],
        "LIN.PAM.MINLEN": ["LIN-PAM-001"],
        "LIN.AUD.AUDITD_ACTIVE": ["LIN-AUDITD-001"],
        "LIN.AUD.IMMUTABLE": ["LIN-AUDITD-002"],
        "LIN.AUD.PARTITION": ["LIN-AUD-PART-001"],
        "LIN.INTEGRITY.AIDE_BASELINE": ["LIN-AIDE-002"],
        "LIN.LOG.JOURNALD_ROT": ["LIN-LOG-001"],
        "LIN.LOG.JOURNALD_ACCESS": ["LIN-LOG-002"],
        "LIN.LOG.RSYSLOG_FORWARD": ["LIN-RSYSLOG-001"],
        "LIN.LOG.RSYSLOG_ACCESS": ["LIN-RSYSLOG-002"],
        "LIN.MAINT.WORLDWRITABLE": ["LIN-FILE-001"],
    }
    for cid, rules in lin_map.items():
        add_control("linux", cid, cid)
        for rid in rules:
            map_control_rule(cid, rid)

def _import_controls_from_xlsx(path: Path):
    if not path.exists():
        return
    items = load_prd_xlsx(str(path))
    for it in items:
        osv = it.get("os")
        if osv not in ("windows", "linux"):
            continue
        add_control(osv, it["control_id"], it.get("description", ""))
        for rid in it.get("rule_ids", []):
            map_control_rule(it["control_id"], rid)

def _import_controls_from_policies():
    for os_name in ("windows", "linux"):
        row = get_latest_policy(os_name)
        if not row:
            continue
        policy = load_policy(row["content"])
        rules = policy.get("rules", [])
        for r in rules:
            cid = r.get("control_id")
            rid = r.get("id")
            if cid and rid:
                add_control(os_name, cid, r.get("description", ""))
                map_control_rule(cid, rid)
@app.get("/admin/exec/allow")
def admin_exec_allow_list(claims=Depends(require_role(["admin"]))):
    rows = list_exec_allowlist()
    return {"items": [dict(r) for r in rows]}

class ExecAllowBody(BaseModel):
    host: str
    channel: str
    min_role: str

@app.post("/admin/exec/allow")
def admin_exec_allow_add(body: ExecAllowBody, claims=Depends(require_role(["admin"]))):
    if len(body.host) > int(os.getenv("MAX_HOST_LEN", "256")):
        raise HTTPException(status_code=413, detail="Host too long")
    add_exec_allow(body.host, body.channel, body.min_role)
    add_audit_event("exec_allow_add", claims.get("sub"), f"{body.host} {body.channel} {body.min_role}")
    return {"status": "ok"}

@app.delete("/admin/exec/allow")
def admin_exec_allow_delete(host: str, channel: str, claims=Depends(require_role(["admin"]))):
    ok = delete_exec_allow(host, channel)
    add_audit_event("exec_allow_del", claims.get("sub"), f"{host} {channel}")
    return {"deleted": ok}

class PolicyAddBody(BaseModel):
    os: str
    version: str
    content: str
    sign: Optional[bool] = True

@app.post("/admin/policy")
def admin_policy_add(body: PolicyAddBody, claims=Depends(require_role(["admin"]))):
    if body.os not in ("windows","linux"):
        raise HTTPException(status_code=400, detail="Unsupported OS")
    max_size = int(os.getenv("MAX_POLICY_SIZE", "200000"))
    if len(body.content) > max_size:
        raise HTTPException(status_code=413, detail="Policy too large")
    key_id, sig = (None, None)
    signed = False
    if body.sign:
        key_id, sig = sign_policy_with_active_key(body.content)
        signed = bool(sig)
    add_policy(version=body.version, os=body.os, content=body.content, signed=signed, signature=sig, key_id=key_id)
    add_audit_event("policy_add", claims.get("sub"), f"{body.os} {body.version} signed={signed}")
    return {"status": "ok", "signed": signed}

@app.get("/admin/policy/keys")
def admin_policy_keys(claims=Depends(require_role(["admin"]))):
    rows = list_policy_keys()
    return {"keys": [dict(r) for r in rows]}

class PolicyKeyAddBody(BaseModel):
    key_id: str
    secret: str
    active: Optional[bool] = True

@app.post("/admin/policy/key/add")
def admin_policy_key_add(body: PolicyKeyAddBody, claims=Depends(require_role(["admin"]))):
    import base64, binascii
    try:
        secret_bytes = binascii.unhexlify(body.secret)
    except Exception:
        secret_bytes = base64.b64decode(body.secret)
    add_policy_key(body.key_id, secret_bytes, active=body.active or False)
    if body.active:
        set_active_policy_key(body.key_id)
    add_audit_event("policy_key_add", claims.get("sub"), f"{body.key_id} active={body.active}")
    return {"status": "ok"}

@app.post("/admin/policy/key/rotate")
def admin_policy_key_rotate(key_id: str, claims=Depends(require_role(["admin"]))):
    set_active_policy_key(key_id)
    add_audit_event("policy_key_rotate", claims.get("sub"), key_id)
    return {"status": "ok"}

class CredentialAddBody(BaseModel):
    name: str
    type: str
    username: str
    password: Optional[str] = None
    key_file: Optional[str] = None

@app.post("/admin/credential")
def admin_credential_add(body: CredentialAddBody, claims=Depends(require_role(["admin"]))):
    if body.type not in ("ssh","winrm"):
        raise HTTPException(status_code=400, detail="Unsupported type")
    if len(body.name) > int(os.getenv("MAX_CRED_NAME_LEN", "128")):
        raise HTTPException(status_code=413, detail="Name too long")
    add_credential(body.name, body.type, {"username": body.username, "password": body.password, "key_file": body.key_file})
    add_audit_event("cred_add", claims.get("sub"), body.name)
    return {"status": "ok"}

@app.get("/admin/credentials")
def admin_credentials_list(claims=Depends(require_role(["admin"]))):
    rows = list_credentials()
    return {"items": [dict(r) for r in rows]}

@app.delete("/admin/credential")
def admin_credential_delete(name: str, claims=Depends(require_role(["admin"]))):
    ok = delete_credential(name)
    add_audit_event("cred_del", claims.get("sub"), name)
    return {"deleted": ok}

class ControlAddBody(BaseModel):
    os: str
    control_id: str
    description: str

@app.post("/admin/control")
def admin_control_add(body: ControlAddBody, claims=Depends(require_role(["admin"]))):
    if body.os not in ("windows","linux"):
        raise HTTPException(status_code=400, detail="Unsupported OS")
    add_control(body.os, body.control_id, body.description)
    add_audit_event("control_add", claims.get("sub"), f"{body.os} {body.control_id}")
    return {"status": "ok"}

class ControlMapBody(BaseModel):
    control_id: str
    rule_id: str

@app.post("/admin/control/map")
def admin_control_map(body: ControlMapBody, claims=Depends(require_role(["admin"]))):
    map_control_rule(body.control_id, body.rule_id)
    add_audit_event("control_map", claims.get("sub"), f"{body.control_id} -> {body.rule_id}")
    return {"status": "ok"}

@app.delete("/admin/control/map")
def admin_control_unmap(control_id: str, rule_id: str, claims=Depends(require_role(["admin"]))):
    ok = unmap_control_rule(control_id, rule_id)
    add_audit_event("control_unmap", claims.get("sub"), f"{control_id} -/-> {rule_id}")
    return {"deleted": ok}

@app.get("/coverage")
def coverage(claims=Depends(require_role(["admin","auditor"]))):
    from ..storage import fleet_coverage
    return fleet_coverage()

class AgentRegisterBody(BaseModel):
    device_id: str

@app.post("/auth/agent/register")
def agent_register(body: AgentRegisterBody):
    from ..security import make_jwt_with_extra
    token = make_jwt_with_extra(body.device_id, "readonly", {"device_id": body.device_id})
    return {"token": token}

class RevokeBody(BaseModel):
    jti: str
    exp_ts: int

@app.post("/admin/jwt/revoke")
def jwt_revoke(body: RevokeBody, claims=Depends(require_role(["admin"]))):
    from ..storage import revoke_jwt
    revoke_jwt(body.jti, body.exp_ts)
    add_audit_event("jwt_revoke", claims.get("sub"), body.jti)
    return {"status": "ok"}

@app.get("/admin/jwt/revocations")
def jwt_revocations(claims=Depends(require_role(["admin"]))):
    from ..storage import list_revocations
    rows = list_revocations(limit=200)
    return {"items": [dict(r) for r in rows]}

class PRDImportBody(BaseModel):
    file_path: str

@app.post("/admin/controls/import-xlsx")
def admin_controls_import(body: PRDImportBody, claims=Depends(require_role(["admin"]))):
    fp = Path(body.file_path)
    if not fp.exists():
        raise HTTPException(status_code=400, detail="file not found")
    max_size = int(os.getenv("MAX_IMPORT_SIZE", "5000000"))
    if fp.stat().st_size > max_size:
        raise HTTPException(status_code=413, detail="file too large")
    items = load_prd_xlsx(str(fp))
    added = 0
    mapped = 0
    for it in items:
        osv = it.get("os")
        if osv not in ("windows", "linux"):
            continue
        add_control(osv, it["control_id"], it.get("description", ""))
        added += 1
        for rid in it.get("rule_ids", []):
            map_control_rule(it["control_id"], rid)
            mapped += 1
    add_audit_event("controls_import", claims.get("sub"), f"added={added} mapped={mapped}")
    return {"added": added, "mapped": mapped}