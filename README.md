# portmantg

> Automatic Telegram MTProxy distribution service — one click, one port, forever yours.

**portmantg** is a lightweight Go web service that hands out personal Telegram MTProxy connections on demand. A visitor opens the site, clicks "Get proxy", and instantly receives a unique port with a ready-to-use "Add to Telegram" link.

## How it works

```
Browser → your-domain.com (nginx/angie) → portmantg :8080
                                  │
                         SQLite + iptables DNAT
                                  │
                         Telegram client → your-domain.com:<port>
                                  │  (DNAT)
                         MTProxy backend :8444
```

1. A new device visits the site → receives a `device_id` cookie (httpOnly, 1 year).
2. `/api/proxy` is called → portmantg allocates the next free port, generates a random secret, registers the user in the MTProxy backend API, adds an iptables DNAT rule, saves to SQLite.
3. The response contains a `tg://proxy?...` link — the user clicks "Add to Telegram".
4. Each subsequent visit for the same device returns the same proxy (no new port allocated).
5. A background goroutine runs every 6 hours and frees ports inactive for 30 days.

## Features

- **One proxy per device** — cookie fingerprint, no bulk generation
- **5-minute cooldown** between new proxy requests per device
- **Auto-cleanup** — ports freed after 30 days of inactivity
- **Instant setup** — no registration, no accounts
- **TLS secret** with SNI camouflage (`ee` prefix + hex-encoded domain)
- **Pure Go** — no CGO, single static binary

## Requirements

- Linux server with `iptables`
- [telemt](https://github.com/refraction-networking/utls) or compatible MTProxy backend with HTTP management API
- Go 1.21+ (for building)

## Building

```bash
# No CGO needed — pure Go SQLite
CGO_ENABLED=0 go build -o portmantg ./cmd/portmantg
```

## Configuration

All options are command-line flags — no config file, no secrets in code.

| Flag | Default | Description |
|---|---|---|
| `-addr` | `:8080` | HTTP listen address |
| `-db` | `/var/lib/portmantg/portmantg.db` | SQLite database path |
| `-web` | `/opt/portmantg/web` | Static web files directory |
| `-telemt-url` | `http://127.0.0.1:9091` | MTProxy backend API base URL |
| `-target-ip` | _(required)_ | DNAT target IP (MTProxy backend) |
| `-target-port` | `8444` | DNAT target port |
| `-port-start` | `1000` | First allocatable user port |
| `-port-end` | `3000` | Last allocatable user port |
| `-proxy-host` | _(required)_ | Public hostname in proxy links |
| `-sni` | _(required)_ | SNI domain embedded in TLS secret |
| `-rate-limit` | `5m` | Cooldown between new requests per device |
| `-inactive-age` | `720h` | Inactivity threshold (30 days) |
| `-cleanup-every` | `6h` | Cleanup interval |

Set all values via the systemd unit — never hardcode them in source.

## Deployment

See [`deploy/`](deploy/) for the systemd unit template and nginx/angie config snippet.

```bash
# 1. Create directories
mkdir -p /var/lib/portmantg /opt/portmantg/web

# 2. Copy binary and web files
cp portmantg /opt/portmantg/
cp -r web/ /opt/portmantg/web/

# 3. Edit deploy/portmantg.service with your values, then install
cp deploy/portmantg.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now portmantg
```

## API

### `GET /api/status`
Returns current proxy for this device (no side effects).

```json
{"has_proxy": true, "port": 1005, "secret": "abc...", "link": "tg://proxy?..."}
{"has_proxy": false}
```

### `GET /api/proxy`
Returns existing proxy or creates a new one.

- `200` — returning existing proxy
- `201` — new proxy created
- `429` — rate limited (`retry_after` in seconds)
- `503` — no ports available

```json
{"port": 1005, "secret": "abc...", "link": "tg://proxy?...", "created": true}
```

## License

MIT
