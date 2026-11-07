#!/usr/bin/env bash
# Deploy HostBridge to the OMV home server with Docker Compose.
# Usage: ./deploy.sh              (run from this folder, on a machine on your LAN)
# Env:   OMV_HOST (default root@192.168.100.30), REMOTE_DIR (default /opt/hostbridge),
#        SSHPASS (optional - uses sshpass for password auth, otherwise your SSH key)
set -euo pipefail
cd "$(dirname "$0")"

OMV_HOST="${OMV_HOST:-root@192.168.100.30}"
REMOTE_DIR="${REMOTE_DIR:-/opt/hostbridge}"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)
if [ -n "${SSHPASS:-}" ]; then RUN=(sshpass -e); else RUN=(); fi
remote() { "${RUN[@]}" ssh "${SSH_OPTS[@]}" "$OMV_HOST" "$@"; }

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example - edit it (NPM/AdGuard URLs, passwords) and run ./deploy.sh again."
  exit 1
fi
grep -q '^SECRET_KEY=.\+' .env || echo "SECRET_KEY=$(openssl rand -hex 32)" >> .env

echo "==> Checking Docker on $OMV_HOST"
remote 'docker compose version >/dev/null 2>&1 || { echo "Docker Compose not found on server (install the compose plugin, e.g. via OMV > System > omv-extras)"; exit 1; }'

PORT=$(grep -E '^HOST_PORT=' .env | cut -d= -f2); PORT=${PORT:-8080}
if remote "ss -ltn | grep -q ':$PORT ' && ! docker ps --format '{{.Names}}' | grep -qx hostbridge"; then
  echo "Port $PORT is already used on the server. Set HOST_PORT=<free port> in .env and re-run."; exit 1
fi

echo "==> Uploading to $REMOTE_DIR"
remote "mkdir -p '$REMOTE_DIR'"
tar czf - --exclude=.venv --exclude=__pycache__ --exclude=.git --exclude=deploy.sh . \
  | remote "tar xzf - -C '$REMOTE_DIR' && chmod 600 '$REMOTE_DIR/.env'"

echo "==> Building and starting"
remote "cd '$REMOTE_DIR' && docker compose up -d --build && sleep 5 && docker compose ps"
remote "curl -fsS http://127.0.0.1:$PORT/api/health >/dev/null" \
  && echo "==> HostBridge is up: http://${OMV_HOST#*@}:$PORT" \
  || echo "==> Container started but health check failed - see: ssh $OMV_HOST 'cd $REMOTE_DIR && docker compose logs'"
