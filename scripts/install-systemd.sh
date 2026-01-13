#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="hashtree"
MODE="user"
ADDR=""
RELAYS=""
DATA_DIR=""
START_NOW="true"

usage() {
  cat <<'EOF'
Usage: install-systemd.sh [options]

Options:
  --user                 Install as user service (default)
  --system               Install as system service (requires root)
  --name NAME            Service name (default: hashtree)
  --addr ADDR            Bind address (default: from config)
  --relays URLS          Comma-separated relay list override
  --data-dir PATH        Data directory (sets HTREE_DATA_DIR)
  --no-start             Enable service but do not start now
  -h, --help             Show this help

Examples:
  ./scripts/install-systemd.sh --user
  ./scripts/install-systemd.sh --system --addr 0.0.0.0:8080 --data-dir /var/lib/hashtree
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --user) MODE="user"; shift ;;
    --system) MODE="system"; shift ;;
    --name) SERVICE_NAME="$2"; shift 2 ;;
    --addr) ADDR="$2"; shift 2 ;;
    --relays) RELAYS="$2"; shift 2 ;;
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    --no-start) START_NOW="false"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

HTREE_BIN="${HTREE_BIN:-$(command -v htree || true)}"
if [ -z "$HTREE_BIN" ]; then
  echo "htree not found in PATH (set HTREE_BIN=/path/to/htree)" >&2
  exit 1
fi

if [ "$MODE" = "system" ]; then
  if [ "$(id -u)" -ne 0 ]; then
    echo "System install requires root (use sudo or --user)" >&2
    exit 1
  fi
  UNIT_DIR="/etc/systemd/system"
  SYSTEMCTL=(systemctl)
  WANTED_BY="multi-user.target"
else
  UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
  SYSTEMCTL=(systemctl --user)
  WANTED_BY="default.target"
fi

mkdir -p "$UNIT_DIR"

EXEC_START="$HTREE_BIN start"
if [ -n "$ADDR" ]; then
  EXEC_START="$EXEC_START --addr $ADDR"
fi
if [ -n "$RELAYS" ]; then
  EXEC_START="$EXEC_START --relays $RELAYS"
fi

UNIT_PATH="$UNIT_DIR/${SERVICE_NAME}.service"
{
  echo "[Unit]"
  echo "Description=hashtree daemon"
  echo "After=network-online.target"
  echo "Wants=network-online.target"
  echo ""
  echo "[Service]"
  echo "ExecStart=$EXEC_START"
  if [ -n "$DATA_DIR" ]; then
    echo "Environment=HTREE_DATA_DIR=$DATA_DIR"
  fi
  if [ -n "${RUST_LOG:-}" ]; then
    echo "Environment=RUST_LOG=$RUST_LOG"
  fi
  echo "Restart=on-failure"
  echo "RestartSec=2"
  echo ""
  echo "[Install]"
  echo "WantedBy=$WANTED_BY"
} > "$UNIT_PATH"

"${SYSTEMCTL[@]}" daemon-reload
if [ "$START_NOW" = "true" ]; then
  "${SYSTEMCTL[@]}" enable --now "${SERVICE_NAME}.service"
else
  "${SYSTEMCTL[@]}" enable "${SERVICE_NAME}.service"
fi

echo "Installed ${UNIT_PATH}"
