from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional, List
import asyncio
import io
import csv

from ..storage import (
    init_db, get_user, add_command, list_commands, list_users, get_credential,
    get_latest_policy, add_finding, list_findings, upsert_device
)
from ..security import verify_password, make_jwt, verify_jwt
from ..ssh_client import ssh_run_command
from ..winrm_client import winrm_run_command
from ..discovery import discover_cidr
from ..alerts import emit_alert
from ..reports import generate_pdf

templates = Jinja2Templates(directory="remotecli/server/templates")

app = FastAPI(title="SEHCS Server", version="0.2.0")
auth_scheme = HTTPBearer()

@app.on_event("startup")
def startup():
    init_db()

def require_auth(creds: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    try:
        claims = verify_jwt(creds.credentials)
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

class AgentReport(BaseModel):
    device_id: str
    hostname: str
    os: str
    policy_version: str
    findings: List[dict]

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/auth/login")
def login(body: LoginRequest):
    u = get_user(body.username)
    if not u:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(body.password, u["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = make_jwt(body.username, u["role"])
    return {"token": token, "role": u["role"]}

@app.post("/exec")
def exec_command(body: ExecRequest, claims=Depends(require_role(["admin"]))):
    actor = claims["sub"]
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
    return {"exit_code": code, "stdout": out, "stderr": err}

@app.post("/discover")
async def discover(body: DiscoverRequest, claims=Depends(require_role(["admin","auditor"]))):
    result = await discover_cidr(body.cidr)
    return {"hosts": result}

@app.get("/history")
def history(limit: int = 50, claims=Depends(require_role(["admin","auditor"]))):
    rows = list_commands(limit=limit, actor=None)
    return {"items": [dict(r) for r in rows]}

@app.get("/users")
def users(claims=Depends(require_role(["admin"]))):
    return {"users": [{"username": r["username"], "role": r["role"]} for r in list_users()]}

@app.get("/policy", response_model=PolicyResponse)
def get_policy(os: str, claims=Depends(require_role(["admin","auditor","readonly"]))):
    row = get_latest_policy(os)
    if not row:
        raise HTTPException(status_code=404, detail="policy not found")
    return {"version": row["version"], "os": row["os"], "policy": row["content"], "signature": row["signature"], "key_id": row["key_id"]}

@app.post("/agent/report")
def agent_report(body: AgentReport, claims=Depends(require_role(["admin","auditor","readonly"]))):
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