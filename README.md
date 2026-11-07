# HostBridge

A small self-hosted web UI that manages **Nginx Proxy Manager** proxy hosts and
**AdGuard Home** DNS rewrites together. You add `jellyfin.home.lan → 192.168.1.20:8096`
once, and HostBridge:

1. creates the proxy host in Nginx Proxy Manager (SSL, websockets, access list…)
2. adds a DNS rewrite `jellyfin.home.lan → <NPM IP>` on **every** AdGuard Home instance

Editing a host keeps DNS in step: renamed or removed domains have their rewrites
removed, and new ones are added. Deleting a host removes its rewrites too (you can opt out).

## Features
- One table showing every proxy host and its DNS status on each AdGuard instance
- Detects DNS rewrites that are **missing** (one-click *Fix DNS*), DNS rewrites with **no proxy host**
  (one-click *Create proxy*), wildcard coverage (`*.home.lan`) and NPM nginx errors
- Several AdGuard Home instances kept in sync (primary/secondary setups)
- Domain shortcut: with `DEFAULT_DOMAIN_SUFFIX=home.lan`, typing `immich` creates `immich.home.lan`
- Use existing certificates or request a new Let's Encrypt one
- Safe create: AdGuard reachability is checked before NPM is touched, and if writing the
  rewrite fails the new proxy host is rolled back
- Password-protected UI, light and dark themes, works on phones
- REST API with OpenAPI docs at `/api/docs`

## Quick start (Docker)
```bash
cp .env.example .env      # then edit it
docker compose up -d --build
```
Open `http://<server>:8080`.

### Configuration (`.env`)
| Variable | Description |
|---|---|
| `APP_PASSWORD` | Password for the UI. Leave empty to disable login (not recommended). |
| `SECRET_KEY` | Signs session cookies. If unset, a random key is used and sessions reset on restart. |
| `SECURE_COOKIE` | `true` when HostBridge is served over HTTPS. |
| `NPM_URL` | NPM admin URL, e.g. `http://192.168.1.10:81` |
| `NPM_EMAIL` / `NPM_PASSWORD` | NPM login (a dedicated NPM user with proxy host permissions works too). |
| `ADGUARD_URL` | AdGuard Home URL(s), comma-separated. |
| `ADGUARD_USERNAME` / `ADGUARD_PASSWORD` | One value for all instances, or one per instance (comma-separated). |
| `ADGUARD_NAMES` | Optional display names for the instances. |
| `DEFAULT_DNS_ANSWER` | IP that new rewrites point to (the NPM host). Can be overridden per host. |
| `DEFAULT_DOMAIN_SUFFIX` | Optional suffix appended to bare names. |
| `LETSENCRYPT_EMAIL` | Default email for new Let's Encrypt certificates. |
| `VERIFY_TLS` | `false` if NPM/AdGuard use self-signed certificates. |

If NPM and AdGuard run as containers on the same Docker host, uncomment the
`networks` section in `docker-compose.yml` and use container names in the URLs.

## Running without Docker
```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
set -a; . ./.env; set +a
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## How DNS rewrites are handled
- A rewrite for a domain is "ensured": if one with the same answer type (IPv4, IPv6 or
  CNAME) already exists with a different value, it is replaced. Rewrites of other types are left alone.
- Rewrites that don't belong to a proxy host (e.g. `nas.home.lan`) are listed separately
  and are only changed when you act on them.
- Proxy host *locations* and other settings HostBridge doesn't expose are preserved on edit.

## API
All endpoints are under `/api` (see `/api/docs`):
`GET /hosts`, `POST /hosts`, `PUT /hosts/{id}`, `DELETE /hosts/{id}?dns=true`,
`POST /hosts/{id}/enabled?enabled=true`, `POST /dns`, `POST /dns/delete`,
`GET /certificates`, `GET /access-lists`, `GET /status`.

## Project layout
```
app/
  main.py      API routes, merge/sync logic, auth
  npm.py       Nginx Proxy Manager client
  adguard.py   AdGuard Home client
  config.py    environment configuration
  static/      single-page UI (no build step)
```
