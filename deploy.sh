#!/bin/bash
set -e

# Usage: ./deploy.sh [user] [host]
# Example: ./deploy.sh homeassistant homeassistant.local
# With no arguments, falls back to HA_SSH_USER/HA_SSH_HOST(/HA_SSH_PORT)
# from .env - see .env.example.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$SCRIPT_DIR/.env"
  set +a
fi

USER="${1:-$HA_SSH_USER}"
HOST_ARG="${2:-$HA_SSH_HOST}"

if [ -z "$USER" ] || [ -z "$HOST_ARG" ]; then
  echo "Usage: $0 <user> <host>  (or set HA_SSH_USER/HA_SSH_HOST in .env)"
  exit 1
fi

SSH_PORT_ARGS=()
if [ -n "$HA_SSH_PORT" ]; then
  SSH_PORT_ARGS=(-p "$HA_SSH_PORT")
fi

HOST="$USER@$HOST_ARG"
REMOTE_DIR="/config/custom_components/lksystems"

echo "==> Creating remote directory..."
ssh "${SSH_PORT_ARGS[@]}" "$HOST" "sudo mkdir -p $REMOTE_DIR && sudo chmod 777 $REMOTE_DIR"

echo "==> Syncing files..."
rsync -avO -e "ssh ${SSH_PORT_ARGS[*]}" --exclude='__pycache__' --exclude='.DS_Store' \
  custom_components/lksystems/ \
  "$HOST:$REMOTE_DIR/"

echo "==> Done! Reload the integration in HA: Settings → Devices & Services → LK Systems → (3 dots) → Reload."
echo "    Or restart HA if this is a first install."
