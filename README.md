# RemoteCLI

Remote command execution across Linux (SSH) and Windows (WinRM) with:
- Encrypted credentials (AES/Fernet)
- Role-based access (admin/user)
- Command history + logging (SQLite + rotating logs)
- Network auto-discovery (CIDR probe)
- Windows/Linux compatible server (FastAPI)
- Packaged CLI entry points

# SEHCS (Secure Endpoint Hardening & Compliance System)

Implements NTRO Annexure A/B alignment via:
- Policies (YAML, versioned, signed placeholder)
- Agent (Windows/Linux) for compliance evaluation + optional auto-remediation
- Server (FastAPI) with RBAC (Admin/Auditor/ReadOnly), TLS-ready
- Dashboard (compliance score), discovery, command history
- Encrypted credentials, SQLite-backed storage, JWT auth

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Seed Users and Policies

```bash
remotecli user add --username admin --password "ChangeMe!" --role admin
remotecli user add --username auditor --password "ChangeMe!" --role auditor

remotecli policy add --file remotecli/policies/linux_policy.yaml --os linux --version 2024.11
remotecli policy add --file remotecli/policies/windows_policy.yaml --os windows --version 2024.11
```

## Start Server (TLS optional)

```bash
SSL_CERTFILE=/path/cert.pem SSL_KEYFILE=/path/key.pem remotecli-server
```

Open `https://localhost:8000/dashboard` (Admin/Auditor).

## Login

- Discover network:
```bash
remotecli discover --cidr 192.168.1.0/24
```

- SSH run:
```bash
remotecli ssh --host 192.168.1.10 --user alice --key-file ~/.ssh/id_rsa --cmd "uname -a"
```

- WinRM run:
```bash
remotecli winrm --host WINHOST --user Administrator --password "P@ssw0rd" --cmd "Get-ComputerInfo"
```

- History:
```bash
remotecli history show --limit 20
remotecli history clear
```

## Server (Windows/Linux)

- Start:
```bash
remotecli server --host 0.0.0.0 --port 8000
```

- Auth:

## Policies (Full Coverage)
Use full policy files to expand coverage mapped to Annexure A/B:

```bash
remotecli policy add --file remotecli/policies/linux_policy_full.yaml --os linux --version 2024.11-full --sign
```

```bash
remotecli policy add --file remotecli/policies/windows_policy_full.yaml --os windows --version 2024.11-full --sign
```

## Agent as a Service (Linux)
- Requires `sehcs-agent` entry point available in your venv or installed globally.

```bash
sudo bash scripts/install_agent_linux.sh http://SERVER:8000 <JWT>
```

- Update `SEHCS_SERVER_URL` or `SEHCS_TOKEN` in `/etc/default/sehcs-agent`.
- View status: `systemctl status sehcs-agent.timer` and `journalctl -u sehcs-agent.service`.

## Agent as a Service (Windows)
- Run PowerShell as Administrator:

```powershell
.\remotecli\agent\windows\install_service.ps1 -ServerUrl http://SERVER:8000 -Token "<JWT>" -CreateScheduledTask
```

- Start service: `Start-Service SEHCSAgent`
- Check scheduled task: Task Scheduler → Library → SEHCSAgentHourly