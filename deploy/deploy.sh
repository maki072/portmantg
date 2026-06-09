#!/bin/bash
# Deploy portmantg to your server.
# Run from the repo root: ./deploy/deploy.sh
# Requires: gh CLI authenticated, ssh access to your server as root.
#
# Configure SERVER below, or set the PORTMANTG_SERVER env variable:
#   PORTMANTG_SERVER=root@your.server.com ./deploy/deploy.sh

set -e

REPO="maki072/portmantg"
SERVER="${PORTMANTG_SERVER:-root@YOUR_SERVER}"
SSH_OPTS="-o StrictHostKeyChecking=no -p 22"
REMOTE_DIR="/opt/portmantg"

echo "==> Fetching latest build artifact from GitHub Actions..."
TMPDIR=$(mktemp -d)
gh run download --repo "$REPO" --name portmantg-linux-amd64 --dir "$TMPDIR" 2>/dev/null || {
  echo "No artifact found. Triggering build first..."
  gh workflow run "Build & Deploy" --repo "$REPO" --ref master
  echo "Waiting for build to complete..."
  sleep 10
  RUN_ID=$(gh run list --repo "$REPO" --workflow "Build & Deploy" --limit 1 --json databaseId -q '.[0].databaseId')
  gh run watch "$RUN_ID" --repo "$REPO"
  gh run download "$RUN_ID" --repo "$REPO" --name portmantg-linux-amd64 --dir "$TMPDIR"
}

chmod +x "$TMPDIR/portmantg"
ls -lh "$TMPDIR/portmantg"

echo "==> Copying binary to $SERVER..."
scp $SSH_OPTS "$TMPDIR/portmantg" "$SERVER:$REMOTE_DIR/portmantg.new"

echo "==> Copying web files..."
scp $SSH_OPTS -r web/ "$SERVER:$REMOTE_DIR/web/"

echo "==> Restarting service..."
ssh $SSH_OPTS "$SERVER" "
  mv $REMOTE_DIR/portmantg.new $REMOTE_DIR/portmantg
  chmod +x $REMOTE_DIR/portmantg
  mkdir -p /var/lib/portmantg
  systemctl daemon-reload
  systemctl restart portmantg 2>/dev/null || systemctl start portmantg
  sleep 1
  systemctl is-active portmantg
"

echo "==> Done! portmantg deployed."
rm -rf "$TMPDIR"
