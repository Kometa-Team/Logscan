# Kometa Log Scanner

A Flask website that stores and scans Kometa and ImageMaid log files, presents
recommendations, creates opaque shareable result URLs, and maintains a unified
People Poster processing queue. Each scan result has a separate deletion token.

Log type is detected from content, including mixed Kometa/ImageMaid archives.
ImageMaid results include versions, modes, runtime, errors, and reported cleanup
counts and recovered space. Analytics groups default to closed accordions, and
the main page shows cumulative ImageMaid cleanup totals.

Identical extracted log contents reuse an existing, unexpired scan across web
and Discord uploads. Each uploader receives a new private management token and
can see their own signed-in upload. Removing an upload retains a shared scan
for its other uploaders; support can remove the entire scan. Expired or fully
deleted logs may be uploaded again. Reused scans do not increase aggregate
processed-log or cleanup totals. Anonymous aggregate totals survive retention
cleanup; log content and identities do not.

Quickstart checks `/api/capabilities` before uploading ImageMaid logs. Update the
web service before enabling the updated Quickstart and Discord integration.

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
or both source tags and is de-duplicated by TMDb person ID, with a normalized-name
fallback for unresolved identities. A confirmed missing image in any supported
style keeps the person actionable, even when their primary image exists. The
missing obligation completes only when every applicable style is verified present;
independent trending sources remain available. Filters and exports use the same union.
Set `TMDB_API_KEY` so the service can resolve people and load profile images.

For website uploads, set `DISCORD_PEOPLE_WEBHOOK_URL` to a webhook created in
the destination Discord channel. A non-embedding notice is posted only when a
actionable person is first added to the queue, preventing repeat notifications for the
same person. The notification links back to the filtered People queue and the
source scan when available.

Source and requester tags filter the unified queue. Export keeps one
`tmdbid|name` row per person. Manual completion and exclusions retain their
existing effect, including the temporary check on trending people.

The authoritative registry is `logscan_web/people_images.py`. It includes
`People-Images` (primary), `People-Images-bw`, `People-Images-diiivoy`,
`People-Images-diiivoycolor`, `People-Images-rainier`, `People-Images-signature`,
and `People-Images-transparent`. Their public repository listings were checked
for the `master` branch and letter/`Images` filename paths; the transparent
style uses PNG assets and the other styles use JPG assets. Legacy root image
URLs remain recognized. No person-specific applicability exclusions are
currently declared. Compact card details show each style's availability.

The service loads complete GitHub file trees in batches of four. If the API
fails, it uses each repository's generated image index after checking the
declared image count and every image URL. Successful checks are cached for one
hour and store the Git revision or index hash and verification time. Failed,
truncated, malformed, or expired inventories remain unknown; they never clear
outstanding candidates. Failed styles retry on the next refresh after five
minutes without refetching fresh styles. No per-person image requests are needed.
An optional `GITHUB_TOKEN` increases API limits; the raw index fallback does not
require it. Unknown statuses explain the failed checks.

People advice retains both earlier outcomes: posters already available (check
the failed update) and missing posters needing creation (review the People
queue). Inconclusive repository checks produce separate pending-verification
advice. Legacy `tmdb_person` poster updates and `No Poster Found` warnings remain
supported alongside `url_poster` failures. Advice links open the People queue
with its Missing Kometa and requester filters preserved, including relative
links stored by historical reanalysis; this display fix needs no new reanalysis.

People recommendations link to each person's physical log lines. Trusted TMDb
image URLs reported in the same collection are retained for previews, with a
source label when the current profile lookup is unavailable. A failed TMDb
request is not classified as a missing image. Ambiguous searches remain
unresolved unless the log's profile image uniquely matches one exact-name
candidate. Reanalysis upgrades an existing name record without duplicating the
person, notification, or upload provenance.

API-key findings identify the affected service and configuration field, link to
that service's documentation, and show its icon. The bundled service icons are
copied from Quickstart's `static/images/service-icons` directory; Logscan serves
its own copies. Different services have separate findings and occurrence counts.
Unidentified services retain generic advice without guessing a service or icon.

Analysis version **13** automatically reprocesses logs still retained on the
server at startup, including newly recognized `url_poster` failures. Deploy the
updated application and restart it (or rebuild the Docker container using the
steps above), preserving the existing data volume. Watch for the retained-scan
reprocessing message. Existing `people.json` records gain optional style,
verification, and upload provenance fields as they are updated; no reset or
separate migration command is needed. Reprocessing preserves scan IDs, receipt
tokens, upload attribution, and historical analytics, and sends no backfill
notifications. Logs that have already expired cannot be recovered. Explicit
manual completions are retained so reanalysis cannot recreate those obligations.

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

## Scan results

Plex version security assessments and their shared source workflow are described
in [Plex security advisory assessments](docs/plex-security.md).

Scan results retain the findings count and separately show **Log occurrences**:
the number of critical, error, warning, info, debug, and trace log entries.
Repeated entries count separately, while one entry may produce more than one
finding. These counts are calculated from the full log, including large logs,
rather than from the
displayed evidence lines.
Critical, error, and warning counts share their colors with findings and log
viewer highlights; info, debug, and trace have distinct colors.
The support console displays the same six levels in a separate **Log counts**
column beside **Findings**, sortable by total tagged entries. Counts unavailable
before backfill are shown as unavailable rather than zero.

Entry-backed findings additionally report `occurrence_count`: the number of
distinct log lines satisfying that detector's complete predicate. Multiple
keywords on the same line count once. Word boundaries, case-insensitive matches,
and same-line requirements are applied before counting. `all_of` remains a
log-wide prerequisite; qualifying lines are counted only after it is satisfied.
Detectors can overlap, so their occurrences are never summed into total errors
or findings counts. Contextual advice without a matching-entry count reports
`occurrence_count: null`.

Normal and streaming scans count the entire log. Evidence retains the first
10,000 matching lines while counting continues; `evidence_truncated` is true
when further evidence was omitted. Results show the count beside each applicable
finding and explain truncation, such as "10,005 occurrences; showing the first
10,000 matching entries." Older records without these fields remain viewable.

Large-file text rules match arbitrary mixed case, just like the normal scanner,
without lowercasing or decoding the entire log into memory.

Validation-only Kometa runs are complete when `validator.py` logs a terminal
`Result:`. The result (including `PASSED`, `FAILED`, or `SKIPPED`) and validation
level are displayed separately. A completed validation command can have a
failed outcome; a report without a terminal result remains incomplete. No
normal runtime footer is required, and no runtime is fabricated.

Analysis version 6 reprocesses retained scans through the existing startup
backfill, preserving scan IDs, source logs, deletion tokens and upload attribution.
It adds per-detector counts and truncation flags to stored results, preserves
existing schema metadata, and leaves raw log-level counts and findings totals
separate. Quickstart's scanner and analytics are unchanged.

## Development Checks

Install the application dependencies and development tools from the repository
root (Python 3.13):

```powershell
py -3.13 -m pip install -r requirements.txt -r requirements-dev.txt
npm ci
py -3.13 -m pre_commit install
```

Run the same checks used by CI:

```powershell
py -3.13 -m pre_commit run --all-files
py -3.13 -m pytest
npm test
```

On Linux or macOS, replace `py -3.13` with `python` from an activated Python 3.13
virtual environment. The JavaScript tools require Node.js 22.18 or newer.

Pre-commit checks YAML and JSON syntax, merge conflicts, filename case conflicts,
whitespace, and requirements ordering, then runs Ruff and Black. Ruff uses the
initial Quickstart rule set (`E4`, `E7`, `E9`, `F`); Black and Ruff share a
180-character line length. ESLint checks browser scripts and Node tests, and
CSpell checks Markdown prose, excluding code blocks and inline code. Project
names are listed in `cspell.json`; add legitimate technical terms there instead
of ignoring misspelled prose. Hooks can fix files; review their changes before
committing. Run either Python check separately with:

```powershell
py -3.13 -m ruff check .
py -3.13 -m black --check .
npm run lint:js
npm run spellcheck
```

CI runs these file checks and both regression suites on pull requests and pushes
to `main`. Dependabot checks Python dependencies, JavaScript development tools,
and GitHub Actions daily.

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
