#!/usr/bin/env bash
# portmantg installer
# Downloads the latest release from GitHub and sets up the service.
# Usage: curl -fsSL https://raw.githubusercontent.com/maki072/portmantg/master/install.sh | bash
#   or:  bash install.sh

set -euo pipefail

REPO="maki072/portmantg"
INSTALL_DIR="/opt/portmantg"
DATA_DIR="/var/lib/portmantg"
SERVICE_FILE="/etc/systemd/system/portmantg.service"
BINARY="$INSTALL_DIR/portmantg"
WEB_DIR="$INSTALL_DIR/web"

BLUE='\033[0;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()    { echo -e "${BLUE}==>${NC} $*"; }
success() { echo -e "${GREEN}✓${NC} $*"; }
warn()    { echo -e "${YELLOW}!${NC} $*"; }
error()   { echo -e "${RED}✗${NC} $*" >&2; exit 1; }

prompt() {
  local var="$1" msg="$2" default="${3:-}"
  if [ -n "$default" ]; then
    read -rp "$(echo -e "${BLUE}?${NC} $msg [${default}]: ")" val
    eval "$var=\"${val:-$default}\""
  else
    read -rp "$(echo -e "${BLUE}?${NC} $msg: ")" val
    eval "$var=\"$val\""
  fi
}

prompt_secret() {
  local var="$1" msg="$2"
  read -rsp "$(echo -e "${BLUE}?${NC} $msg: ")" val
  echo
  eval "$var=\"$val\""
}

# ── Preflight ────────────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || error "Run as root: sudo bash install.sh"
command -v systemctl >/dev/null 2>&1 || error "systemd required"
command -v iptables  >/dev/null 2>&1 || error "iptables required"
for cmd in curl tar; do
  command -v "$cmd" >/dev/null 2>&1 || error "Required tool not found: $cmd"
done

echo
echo "  portmantg installer"
echo "  ───────────────────────────────────────"
echo "  Telegram MTProxy distribution service"
echo "  GitHub: https://github.com/$REPO"
echo

# ── Download latest release ──────────────────────────────────────────────────
info "Fetching latest release info from GitHub..."

RELEASE_JSON=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest") \
  || error "Failed to fetch release info. Check network connectivity."

TAG=$(echo "$RELEASE_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
[ -n "$TAG" ] || error "No releases found. Please build from source."
info "Latest release: $TAG"

# Find the linux-amd64 asset URL
ASSET_URL=$(echo "$RELEASE_JSON" | grep '"browser_download_url"' | grep 'linux-amd64' | head -1 | sed 's/.*"browser_download_url": *"\([^"]*\)".*/\1/')
[ -n "$ASSET_URL" ] || error "No linux-amd64 binary found in release $TAG."

info "Downloading binary..."
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

curl -fSL --progress-bar "$ASSET_URL" -o "$TMPDIR/portmantg"
chmod +x "$TMPDIR/portmantg"

# Also download web assets if present as a tarball
WEB_URL=$(echo "$RELEASE_JSON" | grep '"browser_download_url"' | grep 'web\.tar\.gz' | head -1 | sed 's/.*"browser_download_url": *"\([^"]*\)".*/\1/')

# ── Create directories ───────────────────────────────────────────────────────
info "Creating directories..."
mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$WEB_DIR"

# ── Service configuration ────────────────────────────────────────────────────
echo
echo "  Service configuration"
echo "  ───────────────────────────────────────"

prompt PROXY_HOST  "Public hostname for proxy links (e.g. proxy.example.com)"
prompt TARGET_IP   "MTProxy backend IP"
prompt TARGET_PORT "MTProxy backend port" "8444"
prompt TELEMT_URL  "telemt API URL" "http://127.0.0.1:9091"
prompt SNI_DOMAIN  "SNI domain for TLS camouflage (e.g. www.google.com)" "www.google.com"
prompt PORT_START  "First allocatable user port" "1000"
prompt PORT_END    "Last allocatable user port" "3000"
prompt RATE_LIMIT  "Cooldown between new requests per device" "5m"
prompt LISTEN_ADDR "HTTP listen address" ":8080"

echo
echo "  Admin panel (leave blank to disable)"
echo "  ───────────────────────────────────────"
prompt     ADMIN_USER "Admin username (blank = disabled)" ""
ADMIN_PASS=""
if [ -n "$ADMIN_USER" ]; then
  prompt_secret ADMIN_PASS "Admin password"
fi

ADMIN_FLAGS=""
if [ -n "$ADMIN_USER" ]; then
  ADMIN_FLAGS="  -admin-user=$ADMIN_USER \\\n  -admin-pass=$ADMIN_PASS \\"
fi

# ── Web server setup ─────────────────────────────────────────────────────────
echo
echo "  Web server"
echo "  ───────────────────────────────────────"
echo "  Supported: nginx, angie, caddy, none (configure manually)"
prompt WEB_SERVER "Web server" "nginx"

# ── Install binary ───────────────────────────────────────────────────────────
info "Installing binary to $INSTALL_DIR..."
cp "$TMPDIR/portmantg" "$BINARY"
chmod +x "$BINARY"

# Install web files: from release tarball or from current directory
if [ -n "$WEB_URL" ]; then
  info "Downloading web assets..."
  curl -fsSL "$WEB_URL" | tar -xz -C "$WEB_DIR" --strip-components=1 2>/dev/null || true
fi
# Also copy local web/ if present (for manual installs)
if [ -d "./web" ] && [ "$(ls -A ./web)" ]; then
  info "Copying local web/ assets..."
  cp -r ./web/. "$WEB_DIR/"
fi

# ── systemd unit ─────────────────────────────────────────────────────────────
info "Creating systemd unit $SERVICE_FILE..."

ADMIN_BLOCK=""
if [ -n "$ADMIN_USER" ]; then
  ADMIN_BLOCK="  -admin-user=$(printf '%s' "$ADMIN_USER") \\\n  -admin-pass=$(printf '%s' "$ADMIN_PASS") \\"
fi

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=portmantg - Telegram MTProxy distribution service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR

ExecStart=$BINARY \\
  -addr=$LISTEN_ADDR \\
  -db=$DATA_DIR/portmantg.db \\
  -web=$WEB_DIR \\
  -telemt-url=$TELEMT_URL \\
  -target-ip=$TARGET_IP \\
  -target-port=$TARGET_PORT \\
  -port-start=$PORT_START \\
  -port-end=$PORT_END \\
  -proxy-host=$PROXY_HOST \\
  -sni=$SNI_DOMAIN \\
  -rate-limit=$RATE_LIMIT \\
  -inactive-age=720h \\
  -cleanup-every=6h$([ -n "$ADMIN_USER" ] && printf " \\\\\n  -admin-user=%s \\\\\n  -admin-pass=%s" "$ADMIN_USER" "$ADMIN_PASS")

Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=portmantg

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable portmantg
systemctl restart portmantg || systemctl start portmantg
sleep 1

# ── Web server config ────────────────────────────────────────────────────────
LISTEN_PORT="${LISTEN_ADDR##*:}"
LISTEN_PORT="${LISTEN_PORT:-8080}"

configure_nginx_angie() {
  local bin="$1"  # nginx or angie
  local conf_dir
  if [ "$bin" = "angie" ]; then
    conf_dir="/etc/angie/http.d"
  else
    conf_dir="/etc/nginx/conf.d"
  fi

  if [ ! -d "$conf_dir" ]; then
    warn "Config dir $conf_dir not found — skipping $bin config."
    return
  fi

  local conf_file="$conf_dir/portmantg.conf"
  info "Writing $conf_file..."
  cat > "$conf_file" << EOF
# portmantg — generated by install.sh
# Proxy MTProxy distribution service.
# Adjust server_name and SSL settings for your setup.

upstream portmantg_backend {
    server 127.0.0.1:$LISTEN_PORT;
    keepalive 4;
}

server {
    listen 80;
    server_name $PROXY_HOST;

    # Uncomment to redirect to HTTPS:
    # return 301 https://\$host\$request_uri;

    location /api/ {
        proxy_pass         http://portmantg_backend;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 30s;
    }

    location /proxy {
        return 301 /proxy/;
    }

    location /proxy/ {
        proxy_pass         http://portmantg_backend/;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location / {
        proxy_pass         http://portmantg_backend;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}

# Uncomment for HTTPS:
# server {
#     listen 443 ssl;
#     server_name $PROXY_HOST;
#     ssl_certificate     /etc/letsencrypt/live/$PROXY_HOST/fullchain.pem;
#     ssl_certificate_key /etc/letsencrypt/live/$PROXY_HOST/privkey.pem;
#     ... (same location blocks as above)
# }
EOF

  if $bin -t 2>/dev/null; then
    systemctl reload "$bin" && success "$bin reloaded."
  else
    warn "$bin config test failed — please check $conf_file manually."
  fi
}

configure_caddy() {
  if ! command -v caddy >/dev/null 2>&1; then
    warn "caddy binary not found — skipping config."
    return
  fi

  local caddyfile="/etc/caddy/Caddyfile"
  [ -f "$caddyfile" ] || caddyfile="/usr/local/etc/caddy/Caddyfile"

  info "Appending portmantg block to $caddyfile..."
  cat >> "$caddyfile" << EOF

# portmantg — generated by install.sh
$PROXY_HOST {
    handle /api/* {
        reverse_proxy 127.0.0.1:$LISTEN_PORT
    }
    handle /proxy/* {
        reverse_proxy 127.0.0.1:$LISTEN_PORT {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
        }
    }
    handle {
        reverse_proxy 127.0.0.1:$LISTEN_PORT
    }
}
EOF
  systemctl reload caddy 2>/dev/null || caddy reload 2>/dev/null || warn "Caddy reload failed — check Caddyfile manually."
}

case "$WEB_SERVER" in
  nginx)  configure_nginx_angie nginx ;;
  angie)  configure_nginx_angie angie ;;
  caddy)  configure_caddy ;;
  none|"") warn "Skipping web server config. Configure it manually using deploy/angie-portmantg.conf as a reference." ;;
  *)      warn "Unknown web server '$WEB_SERVER' — skipping. Use nginx, angie, caddy, or none." ;;
esac

# ── TG client auto-updater ───────────────────────────────────────────────────
echo
echo "  Telegram client auto-updater"
echo "  ───────────────────────────────────────"
prompt INSTALL_TG_UPDATE "Install tg-update timer (daily download of TG clients for /files/)? [y/N]" "y"

if [[ "${INSTALL_TG_UPDATE,,}" =~ ^y ]]; then
  TG_UPDATE_SCRIPT_URL="https://raw.githubusercontent.com/$REPO/master/deploy/tg-update.sh"
  info "Downloading tg-update.sh..."
  curl -fsSL "$TG_UPDATE_SCRIPT_URL" -o /usr/local/bin/tg-update.sh \
    || warn "Failed to download tg-update.sh — skipping"
  chmod +x /usr/local/bin/tg-update.sh

  cat > /etc/systemd/system/tg-update.service << 'UNIT'
[Unit]
Description=Telegram client auto-updater
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/tg-update.sh
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tg-update
UNIT

  cat > /etc/systemd/system/tg-update.timer << 'UNIT'
[Unit]
Description=Run Telegram client updater daily
Requires=tg-update.service

[Timer]
OnCalendar=*-*-* 04:00:00 UTC
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
UNIT

  mkdir -p /var/www/tgpage/files
  systemctl daemon-reload
  systemctl enable --now tg-update.timer
  success "tg-update timer installed (daily at 04:00 UTC)"
  info "Run now: systemctl start tg-update.service"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo
echo "  ───────────────────────────────────────"
if systemctl is-active --quiet portmantg; then
  success "portmantg is running!"
else
  warn "portmantg may not have started. Check: journalctl -u portmantg -n 50"
fi

echo
echo "  Installation summary"
echo "  ───────────────────────────────────────"
echo "  Binary:    $BINARY"
echo "  Web files: $WEB_DIR"
echo "  Database:  $DATA_DIR/portmantg.db"
echo "  Service:   systemctl status portmantg"
echo "  Logs:      journalctl -u portmantg -f"
if [ -n "$ADMIN_USER" ]; then
  echo "  Admin:     http://$PROXY_HOST/admin.html  (basic auth)"
fi
echo
