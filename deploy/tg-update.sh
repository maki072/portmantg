#!/bin/bash
# Telegram client auto-updater
# Downloads latest Windows x64 installer and Android APK
# Runs as a systemd timer (daily at 04:00 UTC)

set -uo pipefail

FILES_DIR="/var/www/tgpage/files"
LOG_TAG="tg-update"
GITHUB_API="https://api.github.com/repos/telegramdesktop/tdesktop/releases/latest"
APK_URL="https://telegram.org/dl/android/apk"

log() { logger -t "$LOG_TAG" "$*"; echo "[$(date -u '+%F %T')] $*"; }
die() { log "ERROR: $*"; exit 1; }

mkdir -p "$FILES_DIR"

# --- Windows x64 installer (version from GitHub API) ---
log "Checking latest tdesktop release..."
RELEASE=$(curl -fsSL "$GITHUB_API" -H "Accept: application/vnd.github+json") \
    || die "Failed to fetch GitHub API"

NEW_VER=$(echo "$RELEASE" | python3 -c \
    "import sys,json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))")
WIN_URL=$(echo "$RELEASE" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for a in d['assets']:
    n=a['name']
    if n.startswith('tsetup-x64') and n.endswith('.exe'):
        print(a['browser_download_url']); break
")

[ -z "$NEW_VER" ] && die "Could not parse version"
[ -z "$WIN_URL" ] && die "Could not find Windows installer URL"

CUR_VER=$(cat "$FILES_DIR/.tg_version" 2>/dev/null || echo "0")
log "Windows: current=$CUR_VER, latest=$NEW_VER"

if [ "$NEW_VER" != "$CUR_VER" ] || [ ! -f "$FILES_DIR/tsetup-x64.exe" ]; then
    log "Downloading Windows installer $NEW_VER ..."
    curl -fsSL "$WIN_URL" -o "$FILES_DIR/tsetup-x64.exe.tmp" \
        || die "Failed to download Windows installer"
    mv "$FILES_DIR/tsetup-x64.exe.tmp" "$FILES_DIR/tsetup-x64.exe"
    echo "$NEW_VER" > "$FILES_DIR/.tg_version"
    log "Windows installer updated ($NEW_VER)"
else
    log "Windows installer up to date ($CUR_VER)"
fi

# --- Android APK (download + compare size, CDN blocks HEAD/range) ---
log "Downloading Android APK to check for updates..."
curl -fsSL "$APK_URL" --max-redirs 10 -o "$FILES_DIR/Telegram.apk.tmp" \
    || die "Failed to download APK"

NEW_SIZE=$(stat -c%s "$FILES_DIR/Telegram.apk.tmp")
OLD_SIZE=$(stat -c%s "$FILES_DIR/Telegram.apk" 2>/dev/null || echo "0")

if [ "$NEW_SIZE" -lt 10000000 ]; then
    rm -f "$FILES_DIR/Telegram.apk.tmp"
    die "Downloaded APK too small (${NEW_SIZE}B)"
fi

if [ "$NEW_SIZE" != "$OLD_SIZE" ]; then
    mv "$FILES_DIR/Telegram.apk.tmp" "$FILES_DIR/Telegram.apk"
    log "Android APK updated: ${OLD_SIZE}B -> ${NEW_SIZE}B"
else
    rm -f "$FILES_DIR/Telegram.apk.tmp"
    log "Android APK up to date (${OLD_SIZE}B)"
fi

log "Done. TDesktop: $NEW_VER"
