import sys
import click

from .ssh_client import ssh_run_command, ssh_open_shell
from .winrm_client import winrm_run_command
from .config import ensure_app_dirs
from .storage import (
    init_db, add_command, add_credential, list_credentials,
    get_credential, delete_credential, list_commands, clear_commands,
    add_user, list_users, add_policy, get_latest_policy, add_policy_key,
    list_policy_keys, set_active_policy_key
)
from .security import encrypt_dict, sign_policy_with_active_key
from .discovery import discover_cidr
from .logging_utils import setup_logging
import asyncio
import pathlib


@click.group()
def cli():
    """Remote CLI and SEHCS utilities."""
    ensure_app_dirs()
    init_db()
    setup_logging()
    pass


@cli.command("ssh")
@click.option("--host", required=True, help="Target host or IP.")
@click.option("--port", default=22, show_default=True, help="SSH port.")
@click.option("--user", required=True, help="SSH username.")
@click.option("--password", default=None, help="SSH password (omit to use key).")
@click.option("--key-file", default=None, help="Path to private key file for SSH.")
@click.option("--cmd", default=None, help="Run a single remote command.")
@click.option("--shell/--no-shell", default=False, show_default=True, help="Open an interactive shell.")
@click.option("--timeout", default=30, show_default=True, help="Connection timeout (seconds).")
def ssh(host, port, user, password, key_file, cmd, shell, timeout):
    """
    Connect to a Linux/macOS host via SSH.
    - Use --cmd to run a single command.
    - Use --shell to open an interactive session.
    """
    if shell and cmd:
        click.echo("Please use either --cmd or --shell, not both.", err=True)
        sys.exit(2)

    if shell:
        ssh_open_shell(
            host=host,
            port=port,
            username=user,
            password=password,
            key_file=key_file,
            timeout=timeout,
        )
        return

    if not cmd:
        click.echo("No --cmd provided. Use --shell for interactive session.", err=True)
        sys.exit(2)

    code, out, err = ssh_run_command(
        host=host,
        port=port,
        username=user,
        password=password,
        key_file=key_file,
        command=cmd,
        timeout=timeout,
    )
    add_command(actor=user, target=host, channel="ssh", command=cmd, exit_code=code, stdout=out, stderr=err)

    if out:
        click.echo(out, nl=False)
    if err:
        click.echo(err, nl=False, err=True)
    sys.exit(code)


@cli.command("winrm")
@click.option("--host", required=True, help="Target Windows host or IP.")
@click.option("--user", required=True, help="Windows username.")
@click.option("--password", required=True, help="Windows password.")
@click.option("--cmd", required=True, help="Run a command (cmd.exe or PowerShell).")
@click.option("--powershell/--cmd", default=True, show_default=True, help="Use PowerShell (default) or cmd.exe.")
@click.option("--https/--http", "use_https", default=False, show_default=True, help="Use HTTPS (5986) or HTTP (5985).")
@click.option("--port", default=None, help="Override default WinRM port (5985/5986).")
@click.option(
    "--transport",
    type=click.Choice(["ntlm", "credssp", "kerberos"], case_sensitive=False),
    default="ntlm",
    show_default=True,
    help="WinRM transport.",
)
@click.option(
    "--insecure/--strict",
    "insecure",
    default=True,
    show_default=True,
    help="Ignore server cert validation (HTTPS).",
)
def winrm(host, user, password, cmd, powershell, use_https, port, transport, insecure):
    """
    Connect to a Windows host via WinRM and run a command.
    - PowerShell by default; use --cmd to run via cmd.exe.
    - HTTPS requires WinRM over TLS to be configured on the server.
    """
    code, out, err = winrm_run_command(
        host=host,
        username=user,
        password=password,
        command=cmd,
        powershell=powershell,
        use_https=use_https,
        port=port,
        transport=transport,
        insecure=insecure,
    )
    add_command(actor=user, target=host, channel="winrm", command=cmd, exit_code=code, stdout=out, stderr=err)

    if out:
        click.echo(out, nl=False)
    if err:
        click.echo(err, nl=False, err=True)
    sys.exit(code)


@cli.command("discover")
@click.option("--cidr", required=True, help="CIDR to scan, e.g., 192.168.1.0/24")
def discover(cidr):
    """Auto-discover machines by probing common ports in CIDR."""
    results = asyncio.run(discover_cidr(cidr))
    for r in results:
        click.echo(f"{r['host']}: {r['type']} open={r['open_ports']}")

@cli.group("cred")
def cred():
    """Manage encrypted credentials."""
    pass

@cred.command("add")
@click.option("--name", required=True)
@click.option("--type", "ctype", type=click.Choice(["ssh","winrm"]), required=True)
@click.option("--user", required=True)
@click.option("--password", default=None)
@click.option("--key-file", default=None)
def cred_add(name, ctype, user, password, key_file):
    data = {"username": user, "password": password, "key_file": key_file}
    add_credential(name, ctype, data)
    click.echo(f"Credential '{name}' added.")

@cred.command("list")
def cred_list():
    rows = list_credentials()
    for r in rows:
        click.echo(f"{r['name']} ({r['type']})")

@cred.command("delete")
@click.option("--name", required=True)
def cred_delete(name):
    ok = delete_credential(name)
    click.echo("Deleted." if ok else "Not found.")

@cli.group("history")
def history():
    """Command history and logging."""
    pass

@history.command("show")
@click.option("--limit", default=50, show_default=True)
@click.option("--actor", default=None, help="Filter by actor (username)")
def history_show(limit, actor):
    items = list_commands(limit=limit, actor=actor)
    for r in items:
        click.echo(f"{r['ts']} {r['actor']} {r['channel']} {r['target']} :: {r['command']} => {r['exit_code']}")

@history.command("clear")
@click.option("--actor", default=None, help="Only clear for actor (username)")
def history_clear(actor):
    deleted = clear_commands(actor=actor)
    click.echo(f"Deleted {deleted} entries.")

@cli.group("policy")
def policy():
    """Manage compliance policies (YAML)."""
    pass

@policy.command("add")
@click.option("--file", "file_path", type=click.Path(exists=True), required=True)
@click.option("--os", type=click.Choice(["windows","linux"]), required=True)
@click.option("--version", required=True)
@click.option("--sign/--no-sign", default=True, show_default=True)
def policy_add(file_path, os, version, sign):
    text = pathlib.Path(file_path).read_text()
    key_id, sig = (None, None)
    signed = False
    if sign:
        key_id, sig = sign_policy_with_active_key(text)
        signed = bool(sig)
    add_policy(version=version, os=os, content=text, signed=signed, signature=sig, key_id=key_id)
    click.echo(f"Policy {version} for {os} added. Signed={signed}")

@policy.command("show")
@click.option("--os", type=click.Choice(["windows","linux"]), required=True)
def policy_show(os):
    row = get_latest_policy(os)
    if not row:
        click.echo("No policy found.", err=True)
        sys.exit(1)
    click.echo(f"Version: {row['version']}\nSigned: {bool(row['signed'])}\nKey: {row['key_id']}\nSignature: {row['signature']}\n----\n{row['content']}")

@policy.group("key")
def policy_key():
    """Manage policy signing keys."""
    pass

@policy_key.command("add")
@click.option("--key-id", required=True, help="Identifier for the key (e.g., v1)")
@click.option("--secret", required=True, help="Hex or base64 secret; if hex, will be decoded")
@click.option("--active/--inactive", default=True, show_default=True)
def policy_key_add(key_id, secret, active):
    import base64, binascii
    try:
        # Try hex
        secret_bytes = binascii.unhexlify(secret)
    except Exception:
        secret_bytes = base64.b64decode(secret)
    add_policy_key(key_id, secret_bytes, active=active)
    if active:
        set_active_policy_key(key_id)
    click.echo(f"Added key {key_id}. Active={active}")

@policy_key.command("list")
def policy_key_list():
    rows = list_policy_keys()
    for r in rows:
        click.echo(f"{r['key_id']} active={bool(r['active'])} created_ts={r['created_ts']}")

@policy_key.command("rotate")
@click.option("--key-id", required=True)
def policy_key_rotate(key_id):
    set_active_policy_key(key_id)
    click.echo(f"Active key set to {key_id}")

@cli.command("agent")
@click.option("--server-url", required=True)
@click.option("--token", required=True)
@click.option("--auto-remediate/--no-auto-remediate", default=False, show_default=True)
def agent_run(server_url, token, auto_remediate):
    """Run SEHCS agent locally once."""
    from .agent.agent import run_once
    res = run_once(server_url, token, auto_remediate)
    click.echo(res)

@cli.group("user")
def user():
    """User management (RBAC)."""
    pass

@user.command("add")
@click.option("--username", required=True)
@click.option("--password", required=True)
@click.option("--role", type=click.Choice(["admin","auditor","readonly"]), default="readonly", show_default=True)
def user_add(username, password, role):
    add_user(username, password, role)
    click.echo(f"User '{username}' added as {role}.")

@user.command("list")
def user_list():
    rows = list_users()
    for r in rows:
        click.echo(f"{r['username']} ({r['role']})")

@cli.command("server")
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8000, show_default=True, type=int)
def server(host, port):
    """Start the server API (FastAPI)."""
    import uvicorn
    uvicorn.run("remotecli.server.app:app", host=host, port=port, reload=False)