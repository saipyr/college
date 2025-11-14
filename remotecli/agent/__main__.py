import click
import os
from .agent import run_once

@click.command()
@click.option("--server-url", default=lambda: os.getenv("SEHCS_SERVER_URL"), help="SEHCS server URL (env SEHCS_SERVER_URL)", show_default=True)
@click.option("--token", default=lambda: os.getenv("SEHCS_TOKEN"), help="JWT token (env SEHCS_TOKEN)", show_default=True)
@click.option("--auto-remediate/--no-auto-remediate", default=False, show_default=True)
def main(server_url, token, auto_remediate):
    """Run SEHCS agent once to evaluate and optionally remediate."""
    if not server_url or not token:
        raise click.UsageError("Provide --server-url and --token or set SEHCS_SERVER_URL/SEHCS_TOKEN env.")
    res = run_once(server_url, token, auto_remediate)
    click.echo(f"Reported: {res.get('status','ok')}")