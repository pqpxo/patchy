#!/bin/sh
# Install or upgrade the Patchy agent. Run as root from the directory containing patchy_agent.py:
#   sudo sh install.sh https://patchy.example.lan
# The token is read from a prompt (or stdin) so it never appears in shell history or `ps`.
# Re-running upgrades the script and keeps the existing config and token.
set -eu

SERVER_URL="${1:-}"
LIB=/usr/local/lib/patchy-agent
ETC=/etc/patchy-agent
USER_NAME=patchy-agent
HERE="$(cd "$(dirname "$0")" && pwd)"
# Syft lists the packages inside container images. Pinned release and its published SHA-256 sums.
SYFT_VERSION=1.56.0
SYFT_SHA_amd64=1c2493cfcf52d3367d6cb25780d9190c111c2219c34c820574c43e8bae15c528
SYFT_SHA_arm64=ace61b9397ae28189c674ae332d67a8074dafd71e87724dfb8b22412d8253bb5

install_syft() {
  case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64; SUM=$SYFT_SHA_amd64;;
    aarch64|arm64) ARCH=arm64; SUM=$SYFT_SHA_arm64;;
    *) echo "No Syft build for $(uname -m); container images won't be scanned." >&2; return 0;;
  esac
  for c in curl sha256sum tar; do command -v "$c" >/dev/null || { echo "Syft needs $c; skipped." >&2; return 0; }; done
  TMP="$(mktemp -d)"
  F="syft_${SYFT_VERSION}_linux_${ARCH}.tar.gz"
  if curl -fsSL -o "$TMP/$F" "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/$F" \
      && (cd "$TMP" && echo "$SUM  $F" | sha256sum -c - >/dev/null 2>&1) \
      && tar -xzf "$TMP/$F" -C "$TMP" syft; then
    install -m 0755 "$TMP/syft" "$LIB/syft"
    echo "$SYFT_VERSION" > "$LIB/syft.version"
    echo "Installed Syft $SYFT_VERSION (checksum verified)."
  else
    echo "Syft download or checksum check failed; container images won't be scanned." >&2
  fi
  rm -rf "$TMP"
}

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required." >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required for the timer (you can run the script from cron instead)." >&2; exit 1; }
[ -f "$HERE/patchy_agent.py" ] || { echo "patchy_agent.py not found next to install.sh" >&2; exit 1; }

id "$USER_NAME" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"

install -d -m 0755 "$LIB"
install -m 0755 "$HERE/patchy_agent.py" "$LIB/patchy_agent.py"
install -d -m 0750 -o root -g "$USER_NAME" "$ETC"

if [ ! -f "$ETC/config.json" ]; then
  [ -n "$SERVER_URL" ] || { echo "Usage: sudo sh install.sh https://your-patchy-url" >&2; exit 1; }
  sed "s#https://patchy.example.lan#$SERVER_URL#" "$HERE/config.example.json" > "$ETC/config.json"
  chown root:"$USER_NAME" "$ETC/config.json"; chmod 0640 "$ETC/config.json"
  echo "Wrote $ETC/config.json (edit it to change what is collected)."
  case "$SERVER_URL" in http://*)
    printf "%s is plain HTTP, so the token is sent unencrypted. Allow it on this trusted LAN? [y/N] " "$SERVER_URL"
    read -r ANSWER || ANSWER=""
    case "$ANSWER" in [yY]*) sed -i 's#"allow_insecure_http": false#"allow_insecure_http": true#' "$ETC/config.json";; esac;;
  esac
  if [ -S /var/run/docker.sock ] && getent group docker >/dev/null; then
    printf "List Docker containers too? This adds %s to the docker group, which is root-equivalent. [y/N] " "$USER_NAME"
    read -r ANSWER || ANSWER=""
    case "$ANSWER" in [yY]*)
      usermod -aG docker "$USER_NAME"
      sed -i 's#"docker_images": false#"docker_images": true#' "$ETC/config.json";;
    esac
  fi
fi

if [ ! -s "$ETC/token" ]; then
  printf "Paste the agent token from the Patchy host page (input hidden): "
  stty -echo 2>/dev/null || true; read -r TOKEN; stty echo 2>/dev/null || true; echo
  case "$TOKEN" in pa_*) ;; *) echo "That does not look like a Patchy token (pa_...)." >&2; exit 1;; esac
  umask 027; printf '%s\n' "$TOKEN" > "$ETC/token"; unset TOKEN
  chown root:"$USER_NAME" "$ETC/token"; chmod 0640 "$ETC/token"
fi

# Containers on: offer Syft once, and keep an accepted copy on the pinned version.
if grep -q '"docker_images": true' "$ETC/config.json" 2>/dev/null; then
  if [ -x "$LIB/syft" ]; then
    [ "$(cat "$LIB/syft.version" 2>/dev/null)" = "$SYFT_VERSION" ] || install_syft
  elif [ ! -f "$LIB/syft.declined" ]; then
    printf "Scan container images for vulnerable packages? Downloads Syft %s (Apache-2.0, about 25 MB) from GitHub and checks its SHA-256. [y/N] " "$SYFT_VERSION"
    read -r ANSWER || ANSWER=""
    case "$ANSWER" in [yY]*) install_syft;; *) touch "$LIB/syft.declined";; esac
  fi
fi

HARDENING="StateDirectory=patchy-agent
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
TimeoutStartSec=1800"

cat > /etc/systemd/system/patchy-agent.service <<EOF
[Unit]
Description=Patchy inventory agent (read-only, outbound report)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=$USER_NAME
Group=$USER_NAME
ExecStart=/usr/bin/env python3 $LIB/patchy_agent.py --config $ETC/config.json
$HARDENING
EOF

# Asks Patchy every 5 minutes whether Rescan was pressed; sends a normal report only if it was.
cat > /etc/systemd/system/patchy-agent-poll.service <<EOF
[Unit]
Description=Patchy agent rescan check (read-only, outbound)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=$USER_NAME
Group=$USER_NAME
ExecStart=/usr/bin/env python3 $LIB/patchy_agent.py --config $ETC/config.json --poll
$HARDENING
EOF

cat > /etc/systemd/system/patchy-agent-poll.timer <<EOF
[Unit]
Description=Check every 5 minutes whether Patchy wants a fresh report

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
RandomizedDelaySec=30s

[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/patchy-agent.timer <<EOF
[Unit]
Description=Run the Patchy agent every 6 hours

[Timer]
OnBootSec=5min
OnUnitActiveSec=6h
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now patchy-agent.timer patchy-agent-poll.timer
echo "Checking credential..."
runuser -u "$USER_NAME" -- python3 "$LIB/patchy_agent.py" --config "$ETC/config.json" --check || {
  echo "Credential check failed. Fix $ETC/config.json or $ETC/token, then: sudo systemctl start patchy-agent" >&2; exit 1; }
systemctl start patchy-agent.service && echo "First report sent. Logs: journalctl -u patchy-agent"
