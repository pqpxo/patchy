#!/bin/sh
# Remove the Patchy agent. Afterwards, revoke its credential on the host page in Patchy.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
systemctl disable --now patchy-agent.timer patchy-agent-poll.timer 2>/dev/null || true
systemctl stop patchy-agent.service patchy-agent-poll.service 2>/dev/null || true
rm -f /etc/systemd/system/patchy-agent.service /etc/systemd/system/patchy-agent.timer \
      /etc/systemd/system/patchy-agent-poll.service /etc/systemd/system/patchy-agent-poll.timer
rm -rf /etc/systemd/system/patchy-agent.service.d
systemctl daemon-reload
rm -rf /usr/local/lib/patchy-agent /etc/patchy-agent
id patchy-agent >/dev/null 2>&1 && userdel patchy-agent || true
echo "Patchy agent removed. Now revoke its credential in Patchy (Hosts > host > Revoke)."
