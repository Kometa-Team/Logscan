# Kometa Log Scanner

A website that stores and scans Kometa log files, presents recommendations,
and creates opaque shareable result URLs. Each result has a separate deletion
token. The included Red cog detects log attachments, asks the author for
confirmation, uploads the file, and returns its result/deletion URL.

## Requirements

- Python 3.13
- Approximately 1 GB RAM is recommended for 100 MB logs
- Windows, Linux, or macOS

## Windows installation

Open PowerShell in the extracted `kometa-logscan-web` directory:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m logscan_web.app
```

Open <http://127.0.0.1:5000>.

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
python -m logscan_web.app
```

Open <http://127.0.0.1:5000>.

## Production

Do not use Flask's development server for a public deployment.

Linux production command:

```bash
gunicorn --workers 1 --threads 1 --timeout 300 --bind 0.0.0.0:8000 logscan_web.app:app
```

Windows production command:

```powershell
waitress-serve --listen=0.0.0.0:8000 --threads=1 logscan_web.app:app
```

One worker/thread is intentional because the inherited recommendation engine
has process-global divider state. It also avoids allowing simultaneous 100 MB
scans to exhaust memory. Put a reverse proxy and rate limiting in front of a
public instance.

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

## Red bot cog

Add this repository to Red's Downloader and install `logscan`:

```text
[p]repo add logscan <repository-clone-url>
[p]cog install logscan logscan
[p]load logscan
[p]logscanset url https://logscan.kometa.team
[p]logscanset apikey <the same value from /opt/logscan/.env>
[p]logscanset channels production <channel-id>
```

The settings commands are bot-owner only. The API-key command attempts to
delete the invoking Discord message. Prefer running it in a private channel.
The cog requires permission to read messages, send messages, attach buttons,
and read attachment content.

### Cog channel and role configuration

Log scanning is restricted to the active environment's configured channels.
The cog starts in `production`, with its existing scan channel configured as
the default. Configure the production channels explicitly after installation;
supplying multiple IDs permits scanning in all of them:

```text
[p]logscanset channels production <channel-id> [additional-channel-ids]
```

For a separate testing setup, configure its channels and switch the cog to the
`test` environment:

```text
[p]logscanset channels test <channel-id> [additional-channel-ids]
[p]logscanset environment test
```

Switch back with `[p]logscanset environment production`. The configured lists
are independent: changing the active environment changes which list controls
automatic attachment detection and the `[p]logscan <message-link>` command.
Threads are always allowed, so a user can scan a log in a thread even when the
thread's parent channel is not listed. A log posted in a non-thread channel
outside the active list receives a short-lived message explaining where scans
are permitted.

The uploader is always allowed to press the scan button. To let support staff
act on a user's prompt, configure role IDs:

```text
[p]logscanset roles <role-id> [additional-role-ids]
```

Those roles can approve or cancel another user's pending scan; they do not
bypass the allowed-channel rules. Run `[p]logscanset roles` with no IDs to
clear the privileged-role list.

The returned link contains the deletion token after `#delete=`. URL fragments
are not included in HTTP requests, but anyone who receives the complete link
can view and permanently delete that log. A result URL without the fragment is
view-only. All links expire when their scan is automatically deleted after 48
hours.

## Missing People backlog

When a scan encounters a missing People Poster, the website records the person
in the persistent `/people` backlog. Set `TMDB_API_KEY` in the web service
environment so the service can resolve a TMDb person ID and load their profile
images. A person remains in the backlog until someone marks them complete.

The cog sends one non-embedding notification per detected person to channel
`1539665929330499664`, including the scan, original Discord message (where
available), TMDb-image status, and the person page.

For website uploads, set `DISCORD_PEOPLE_WEBHOOK_URL` to a webhook created in
the destination Discord channel. A non-embedding notice is posted only when a
person is first added to the backlog, preventing repeat notifications for the
same person.

## Reverse proxy notes

The application accepts uploads up to 100 MiB. Your reverse proxy must accept a
slightly larger HTTP request because multipart uploads add overhead.

For Nginx, include this in the applicable `server` or `location` block:

```nginx
client_max_body_size 110M;
proxy_read_timeout 300s;
proxy_send_timeout 300s;
proxy_pass http://127.0.0.1:8000;
```

If Cloudflare proxies the hostname, its plan-specific request-body limit also
applies. A nominal 100 MB Cloudflare limit may reject a 100 MiB file plus form
overhead. Use a smaller application limit, a higher-limit plan, or DNS-only
routing if full-size uploads must work.

## Tests

```bash
python -m unittest discover -s tests -v
```

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