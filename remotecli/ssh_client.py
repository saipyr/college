import sys
import socket
import select
import paramiko
import termios
import tty


def _connect_ssh(host, port, username, password=None, key_file=None, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            key_filename=key_file,
            timeout=timeout,
            allow_agent=True,
            look_for_keys=True,
        )
        return client
    except (paramiko.SSHException, socket.error) as exc:
        raise RuntimeError(f"SSH connection failed: {exc}") from exc


def ssh_run_command(host, port, username, password, key_file, command, timeout=30):
    client = _connect_ssh(host, port, username, password, key_file, timeout)
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_status = stdout.channel.recv_exit_status()
        return exit_status, out, err
    finally:
        client.close()


def ssh_open_shell(host, port, username, password=None, key_file=None, timeout=30):
    """
    Open an interactive shell bridged to the local terminal.
    """
    client = _connect_ssh(host, port, username, password, key_file, timeout)
    chan = None
    old_tty = None
    try:
        chan = client.invoke_shell(term="xterm")
        chan.settimeout(0.0)

        # Set local terminal to raw mode
        if sys.stdin.isatty():
            old_tty = termios.tcgetattr(sys.stdin)
            tty.setraw(sys.stdin)

        # Main IO loop
        while True:
            rlist, _, _ = select.select([chan, sys.stdin], [], [])
            if chan in rlist:
                try:
                    data = chan.recv(1024)
                    if not data:
                        break
                    sys.stdout.write(data.decode("utf-8", errors="replace"))
                    sys.stdout.flush()
                except socket.timeout:
                    pass

            if sys.stdin in rlist:
                data = sys.stdin.read(1)
                if not data:
                    break
                chan.send(data)
            if chan.exit_status_ready():
                break
    finally:
        if old_tty:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
        if chan:
            chan.close()
        client.close()