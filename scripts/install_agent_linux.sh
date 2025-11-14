#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

SERVER_URL="${1:-}"
TOKEN="${2:-}"

if [[ -z "$SERVER_URL" || -z "$TOKEN" ]]; then
  echo "Usage: install_agent_linux.sh <server_url> <token>" >&2
  exit 2
fi

install -D -m 0644 remotecli/agent/systemd/sehcs-agent.service /etc/systemd/system/sehcs-agent.service
install -D -m 0644 remotecli/agent/systemd/sehcs-agent.timer /etc/systemd/system/sehcs-agent.timer

mkdir -p /etc/default
cat >/etc/default/sehcs-agent <<EOF
SEHCS_SERVER_URL=${SERVER_URL}
SEHCS_TOKEN=${TOKEN}
EOF

systemctl daemon-reload
systemctl enable --now sehcs-agent.timer

echo "Installed. Edit /etc/default/sehcs-agent to change settings."