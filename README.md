# Kometa Log Scanner

A Flask website that stores and scans Kometa log files, presents
recommendations, creates opaque shareable result URLs, and maintains a unified
People Poster processing queue. Each scan result has a separate deletion token.

## Requirements

- Python 3.13
- Large archive members are extracted to disk and scanned with bounded memory; allow enough disk space for the 1 GiB extracted limit
- Supported archives: .zip, .7z, .tar, .tar.gz, .tgz, .gz, .tar.bz2, .tbz2, .bz2, .tar.xz, .txz, .xz, .tar.zst, and .zst
- Windows, Linux, or macOS

## Windows installation

Open PowerShell in the cloned `Logscan` directory:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python -m logscan_web.app
```

This starts Flask's development server. Open <http://127.0.0.1:5000>.
Stop it with `Ctrl+C`.

To test with the same Windows WSGI server used for production-like deployments:

```powershell
waitress-serve --listen=127.0.0.1:5010 --threads=1 logscan_web.app:app
```

Then open <http://127.0.0.1:5010>. Using port `5010` avoids conflicts when
another local service already owns port `5000`.

If PowerShell blocks virtual-environment activation, run this once in the
current PowerShell window:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

## Linux or macOS installation

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cp .env.example .env
python -m logscan_web.app
```

Open <http://127.0.0.1:5000> and stop the development server with `Ctrl+C`.

## Environment configuration

The application loads `.env` from the current working directory for local
development. Real process environment variables take precedence.

- `LOGSCAN_API_KEY` authenticates automated log uploads. Generate a long random value.
- `DISCORD_CLIENT_ID` and `DISCORD_CLIENT_SECRET` identify a Discord application used for account sign-in.
- `DISCORD_BOT_TOKEN` enables live support-role revalidation on privileged requests. The bot must belong to the configured guild and its token must remain secret.
- `DISCORD_REDIRECT_URI` must exactly match the application's OAuth redirect; production uses `https://logscan.kometa.team/support/callback`.
- `DISCORD_GUILD_ID` is the Kometa Discord server ID.
- `DISCORD_SUPPORT_ROLE_IDS` is a comma-separated allowlist of support or administrator role IDs. Holding any listed role grants access.
- `LOGSCAN_SECRET_KEY` signs browser sessions. Generate a separate long random value and keep it stable across restarts.
- `LOGSCAN_SECURE_COOKIES=true` restricts support sessions to HTTPS in production.
- `TMDB_API_KEY` enables TMDb identity resolution, profile images, and trending people.
- `DISCORD_PEOPLE_WEBHOOK_URL` optionally announces newly discovered missing people.
- `SCAN_STORE` selects persistent storage. For local testing, `./data/scans` keeps data inside the checkout; containers use `/data/scans`.

The unified People page is available at <http://127.0.0.1:5000/people> when
using Flask, or the equivalent path on the selected Waitress port.


The protected support inventory is available at `/support/logs`. In the Discord
Developer Portal, register the configured callback under OAuth2 Redirects.
Enable Discord Developer Mode to copy the server and role IDs. Sign-in requests
only `identify` and `guilds.members.read` and store no Discord OAuth access token.
Account sessions persist for 30 days. When `DISCORD_BOT_TOKEN` is configured,
support membership is revalidated against Discord on each request (including users
who gained a support role after signing in), and access is denied if validation
fails; repeated checks within one request share a single lookup. Without a bot
token, the role assertion expires after eight hours and requires a fresh OAuth
sign-in.

## Production

Do not use Flask's development server for a public deployment.

Linux production command:

```bash
gunicorn --workers 1 --threads 4 --timeout 900 --bind 0.0.0.0:8000 logscan_web.app:app
```

Windows production command:

```powershell
waitress-serve --listen=0.0.0.0:8000 --threads=4 logscan_web.app:app
```

One process is intentional because scan job status is held in memory.
Four threads keep status polling responsive while the single background scan
worker serializes memory-intensive scans. Put a reverse proxy and rate limiting
in front of a public instance.

## Docker

```bash
docker build -t kometa-logscan-web .
docker run --rm -p 8000:8000 \
  -e LOGSCAN_API_KEY=replace-me \
  -e TMDB_API_KEY=your-tmdb-api-key \
  -v logscan-data:/data \
  kometa-logscan-web
```

Open <http://127.0.0.1:8000>.

## Updating a Docker deployment

From the directory containing the repository and Compose file, pull the
latest application version and recreate the container with a newly built
image:

```bash
cd /opt/logscan
git pull
docker compose up -d --build --remove-orphans
docker compose logs -f
```

The persistent `/opt/logscan/data` directory is not recreated or removed by
this process. Press `Ctrl+C` to stop following logs; it does not stop the
container.

## Saltbox deployment

The included `compose.saltbox.yml` follows Saltbox's Traefik template and
publishes the app at `https://logscan.kometa.team`.

```bash
sudo mkdir -p /opt/logscan/data
sudo chown -R 10001:10001 /opt/logscan/data
cd /opt/logscan
cp .env.example .env
openssl rand -hex 32
# Put that value in .env, then:
docker compose -f compose.saltbox.yml up -d --build
```

Create an A/AAAA record for `logscan.kometa.team` pointing to the Saltbox
server (or use Saltbox DDNS/wildcard DNS). The compose file expects the
external `saltbox` Docker network and Saltbox's standard Traefik middlewares.
If the domain is not managed through the Cloudflare account configured in
Saltbox, change `cfdns` to the certificate resolver used by your installation.

Logs and result JSON are stored below `/opt/logscan/data`, so all persistent
application data remains inside `/opt/logscan` on the host. Scans are
automatically deleted 48 hours after upload. The service checks immediately at
startup and hourly thereafter.

## People queue

The `/people` page combines missing People Posters found in uploaded logs with
IMDb StarMeter and TMDb trending people. Each person carries `missing`, `trending`,
or both source tags and is de-duplicated by TMDb person ID. People already present
in the primary Kometa People Images repository automatically leave the actionable
queue. Filters and exports use the same union so automation processes both sources.
Set `TMDB_API_KEY` so the service can resolve people and load profile images.

For website uploads, set `DISCORD_PEOPLE_WEBHOOK_URL` to a webhook created in
the destination Discord channel. A non-embedding notice is posted only when a
person is first added to the queue, preventing repeat notifications for the
same person. The notification links back to the filtered People queue and the
source scan when available.

The Missing and Trending filters use OR behavior and are both enabled by
default. Export downloads the currently selected source union as
`tmdbid|name`. Marking a person complete clears both sources; candidates also
leave the queue automatically after their image appears in the primary Kometa
People Images repository.

## Reverse proxy notes

The application accepts uploads and extracted archive contents up to 1 GiB. Large archive members are streamed to temporary disk storage while scanning. Browser and authenticated Discord uploads return `202 Accepted` after intake and continue as background jobs, so long scans and queue waits are not tied to the proxy read timeout. Your reverse proxy must accept the compressed upload plus multipart overhead.

For Nginx, include this in the applicable `server` or `location` block:

```nginx
client_max_body_size 1025M;
proxy_read_timeout 900s;
proxy_send_timeout 900s;
proxy_pass http://127.0.0.1:8000;
```

If Cloudflare proxies the hostname, its plan-specific request-body limit still applies to the compressed upload. Use a higher-limit plan or DNS-only routing when uploads must exceed that limit.

## Tests

Run the regression suite from the repository root:

```powershell
py -3.13 -m unittest discover -s tests -v
```

On Linux or macOS, use `python -m unittest discover -s tests -v` from the
activated Python 3.13 virtual environment.

## Included files

- `logscan_web/app.py` — Flask routes and upload handling
- `logscan_web/storage.py` — filesystem persistence and deletion tokens
- `logscan_web/scanner.py` — input validation and result normalization
- `logscan_web/models.py` and `logscan_web/rules/` — structured scan data and modular recommendation rules
- `logscan_web/templates/` — HTML interface
- `logscan_web/static/` — styles and browser behavior
- `tests/` — scanner and API regression tests
- `requirements.txt` — complete Python dependencies
- `Dockerfile` — container deployment
- `compose.saltbox.yml` — Saltbox/Traefik deployment
