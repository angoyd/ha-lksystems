#!/bin/bash
set -e

# Usage: ./deploy.sh <user> <host>
# Example: ./deploy.sh homeassistant homeassistant.local
if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <user> <host>"
  exit 1
fi

USER="$1"
HOST_ARG="$2"
HOST="$USER@$HOST_ARG"
REMOTE_DIR="/config/custom_components/lksystems"

echo "==> Creating remote directory..."
ssh "$HOST" "sudo mkdir -p $REMOTE_DIR && sudo chmod 777 $REMOTE_DIR"

echo "==> Syncing files..."
rsync -avO --exclude='__pycache__' --exclude='.DS_Store' \
  custom_components/lksystems/ \
  "$HOST:$REMOTE_DIR/"

echo "==> Done! Reload the integration in HA: Settings → Devices & Services → LK Systems → (3 dots) → Reload."
echo "    Or restart HA if this is a first install."
