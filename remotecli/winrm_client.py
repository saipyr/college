import winrm


def winrm_run_command(
    host,
    username,
    password,
    command,
    powershell=True,
    use_https=False,
    port=None,
    transport="ntlm",
    insecure=True,
):
    """
    Run a command on a Windows host via WinRM.
    Returns (exit_code, stdout, stderr).
    """
    if port is None:
        port = 5986 if use_https else 5985

    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/wsman"

    server_cert_validation = "ignore" if insecure else "validate"

    session = winrm.Session(
        url,
        auth=(username, password),
        transport=transport,
        server_cert_validation=server_cert_validation,
    )

    if powershell:
        result = session.run_ps(command)
    else:
        result = session.run_cmd(command)

    # winrm Response has status_code, std_out, std_err (bytes)
    out = result.std_out.decode("utf-8", errors="replace")
    err = result.std_err.decode("utf-8", errors="replace")
    return result.status_code, out, err