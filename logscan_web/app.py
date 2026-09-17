import hmac
import hashlib
import json
import os
import re
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from flask import Flask, abort, jsonify, render_template, request, send_file, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from .models import Finding
from .recommendations import validate_redacted_config
from .scanner import ALLOWED_SUFFIXES, ARCHIVE_SUFFIXES, MAX_FILE_BYTES, ScanError, extract_missing_people, find_scannable_archive_logs, prepare_scan_input, scan_archive_logs, scan_log
from .storage import PeopleStore, PopularPeopleCacheStore, PopularPeopleCheckStore, PopularPeopleExclusionStore, PopularPeopleFlagStore, ScanStore, TMDbFindCacheStore

RETENTION_SECONDS = 48 * 60 * 60
CLEANUP_INTERVAL_SECONDS = 60 * 60
POPULAR_PEOPLE_PAGE_SIZE = 25
TMDB_POPULAR_PAGE_SIZE = 20
KOMETA_IMAGE_SOURCES = (
    ("Kometa Repo Image", "https://raw.githubusercontent.com/Kometa-Team/People-Images/refs/heads/master/README.md"),
    ("DIIIVOY", "https://raw.githubusercontent.com/Kometa-Team/People-Images-diiivoy/master/README.md"),
    ("DIIIVOY Color", "https://raw.githubusercontent.com/Kometa-Team/People-Images-diiivoycolor/master/README.md"),
    ("Rainier", "https://raw.githubusercontent.com/Kometa-Team/People-Images-rainier/master/README.md"),
    ("Signature", "https://raw.githubusercontent.com/Kometa-Team/People-Images-signature/master/README.md"),
)
KOMETA_IMAGE_CACHE_SECONDS = 60 * 60
POPULAR_PEOPLE_CACHE_SECONDS = 24 * 60 * 60
POPULAR_PEOPLE_LIMIT = 250
POPULAR_PEOPLE_CHECK_SECONDS = 30 * 24 * 60 * 60
TMDB_FIND_CACHE_SECONDS = 7 * 24 * 60 * 60
TMDB_FIND_MAX_WORKERS = 8


def add_missing_people_recommendations(result, candidates: list[dict], repository_people: dict[str, str]) -> None:
    """Add advice for missing people images, split by repository availability."""
    found = []
    pending = []
    for candidate in candidates:
        name = candidate["name"]
        (found if name.casefold() in repository_people else pending).append(name)

    def add_advice(identifier: str, title: str, description: str, solution: str) -> None:
        result.recommendations.append(Finding(identifier, "advice", title, description, solution).as_dict())

    if found:
        people = ", ".join(found)
        add_advice(
            "missing_people_images_available",
            "Missing people images are available in Kometa's repository",
            "Missing person images were identified in this log, but are already available in the Kometa People Images repository. "
            f"\n\nPeople: {people}.",
            "Delete the collection related to each listed person so Kometa can recreate it with the available image.",
        )
    if pending:
        people = ", ".join(pending)
        add_advice(
            "missing_people_images_pending",
            "Missing people images need to be created",
            "Missing person images were identified in this log. The Kometa team have been made aware and will action these as soon as possible. "
            f"\nPeople: {people}.",
            "Wait for the People Images repository to be updated, then rerun Kometa to create the affected collection image.",
        )
    if found or pending:
        result.recommendations.sort(key=lambda item: {"critical": 0, "error": 1, "warning": 2, "schema": 3, "advice": 4}[item["severity"]])
        result.metadata["counts"]["advice"] = sum(item["severity"] == "advice" for item in result.recommendations)
        result.overview["recommendation_count"] = len(result.recommendations)


def _people_needing_repository_images(candidates: list[dict], repository_people: dict[str, str] | None) -> list[dict]:
    """Return log candidates absent from the primary People Images repository."""
    if repository_people is None:
        # Keep the existing reporting path when GitHub is temporarily unavailable.
        return candidates
    return [candidate for candidate in candidates if candidate["name"].casefold() not in repository_people]


def _has_current_tmdb_image(person: dict) -> bool:
    """Return whether TMDb currently provides a profile image for a person."""
    return bool(person.get("profile_path"))


def load_local_env() -> None:
    """Load a local development .env without overriding real process settings."""
    env_file = os.path.join(os.getcwd(), ".env")
    try:
        with open(env_file, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                if key and key.replace("_", "").isalnum():
                    os.environ.setdefault(key, value.strip().strip("'\""))
    except FileNotFoundError:
        pass


def create_app() -> Flask:
    load_local_env()
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_BYTES + (1024 * 1024)
    app.config["SCAN_STORE"] = os.environ.get("SCAN_STORE", "/data/scans")
    app.config["LOGSCAN_API_KEY"] = os.environ.get("LOGSCAN_API_KEY", "")
    app.config["TMDB_API_KEY"] = os.environ.get("TMDB_API_KEY", "")
    app.config["DISCORD_PEOPLE_WEBHOOK_URL"] = os.environ.get("DISCORD_PEOPLE_WEBHOOK_URL", "")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    store = ScanStore(app.config["SCAN_STORE"])
    people_store = PeopleStore(app.config["SCAN_STORE"])
    popular_people_exclusions = PopularPeopleExclusionStore(app.config["SCAN_STORE"])
    popular_people_checks = PopularPeopleCheckStore(app.config["SCAN_STORE"])
    popular_people_flags = PopularPeopleFlagStore(app.config["SCAN_STORE"])
    popular_people_store = PopularPeopleCacheStore(app.config["SCAN_STORE"])
    tmdb_find_cache = TMDbFindCacheStore(app.config["SCAN_STORE"])
    kometa_images_cache = {"expires_at": 0.0, "images": {}}
    kometa_images_lock = threading.Lock()
    popular_people_cache = {"expires_at": 0.0, "snapshot_id": "", "people": []}
    popular_people_lock = threading.Lock()
    popular_people_refreshing = False
    popular_people_payload_cache: dict[tuple, list[dict]] = {}
    popular_people_payload_lock = threading.Lock()

    def tmdb_get(path: str, params: dict | None = None) -> dict | None:
        api_key = app.config["TMDB_API_KEY"]
        if not api_key:
            return None
        query = urlencode({"api_key": api_key, **(params or {})})
        request_url = f"https://api.themoviedb.org/3{path}?{query}"
        try:
            with urlopen(Request(request_url, headers={"Accept": "application/json"}), timeout=10) as response:
                import json
                return json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, ValueError):
            app.logger.warning("TMDb lookup failed for %s", path)
            return None

    def kometa_image_urls() -> dict[str, dict[str, str]]:
        """Map each image source to its case-insensitive person-name URLs."""
        with kometa_images_lock:
            if kometa_images_cache["expires_at"] > time.monotonic():
                return kometa_images_cache["images"]
            images = {}
            for label, readme_url in KOMETA_IMAGE_SOURCES:
                try:
                    with urlopen(Request(readme_url, headers={"Accept": "text/plain"}), timeout=15) as response:
                        readme = response.read().decode("utf-8")
                except (HTTPError, URLError, TimeoutError, UnicodeDecodeError):
                    app.logger.warning("Unable to fetch the %s people-image README.", label)
                    continue
                images[label] = {
                    name.casefold(): url
                    for name, url in re.findall(r"^\* \[([^]]+)]\((https://[^)]+)\)$", readme, re.MULTILINE)
                }
            kometa_images_cache.update(expires_at=time.monotonic() + KOMETA_IMAGE_CACHE_SECONDS, images=images)
            return images

    def imdb_starmeter_people() -> list[dict]:
        """Resolve IMDb's current StarMeter chart entries to TMDb people."""
        query = """
            {
              chartNames(first: 100, chart: { chartType: MOST_POPULAR_NAMES }) {
                edges { node { id } }
              }
            }
        """
        try:
            with urlopen(Request(
                "https://caching.graphql.imdb.com/",
                data=json.dumps({"query": query}).encode("utf-8"),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Origin": "https://www.imdb.com",
                    "User-Agent": "Mozilla/5.0 (compatible; Kometa-Logscan/1.0)",
                    "x-imdb-client-name": "imdb-web-next-localized",
                },
            ), timeout=15) as response:
                chart = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, ValueError):
            app.logger.warning("Unable to fetch IMDb StarMeter from GraphQL.")
            return []

        imdb_ids = []
        seen_ids = set()
        edges = chart.get("data", {}).get("chartNames", {}).get("edges", [])
        for edge in edges:
            imdb_id = edge.get("node", {}).get("id")
            if not isinstance(imdb_id, str) or not re.fullmatch(r"nm\d{5,}", imdb_id):
                continue
            if imdb_id in seen_ids:
                continue
            seen_ids.add(imdb_id)
            imdb_ids.append(imdb_id)

        def resolve(imdb_id: str) -> tuple[str, dict | None]:
            cached = tmdb_find_cache.get(imdb_id, TMDB_FIND_CACHE_SECONDS)
            if cached is not None:
                return imdb_id, cached
            data = tmdb_get(f"/find/{imdb_id}", {"external_source": "imdb_id"})
            match = next((person for person in (data or {}).get("person_results", []) if person.get("id")), None)
            tmdb_find_cache.save(imdb_id, match)
            return imdb_id, match

        with ThreadPoolExecutor(max_workers=TMDB_FIND_MAX_WORKERS, thread_name_prefix="tmdb-find") as executor:
            resolved = dict(executor.map(resolve, imdb_ids))
        people = []
        for imdb_id in imdb_ids:
            match = resolved.get(imdb_id)
            if match and not match.get("adult") and _has_current_tmdb_image(match):
                people.append({**match, "imdb_id": imdb_id})
        return people

    def order_popular_people(people: list[dict], flags: dict[int, dict[str, str]]) -> list[dict]:
        """Keep StarMeter order ahead of the TMDb fill-in, then surface flags."""
        return sorted(
            people,
            key=lambda person: (
                person.get("starmeter_rank", POPULAR_PEOPLE_LIMIT),
                person["id"] not in flags,
            ),
        )

    def _filtered_popular_people(people: list[dict]) -> list[dict]:
        excluded_ids = popular_people_exclusions.list()
        checked_ids = popular_people_checks.active_ids(POPULAR_PEOPLE_CHECK_SECONDS)
        flags = popular_people_flags.list()
        people = [person for person in people if person.get("id") not in excluded_ids | checked_ids]
        return order_popular_people(people, flags)

    def _install_popular_people_snapshot(snapshot: dict) -> None:
        try:
            updated_at = datetime.fromisoformat(snapshot["updated_at"]).timestamp()
        except (KeyError, TypeError, ValueError):
            return
        with popular_people_lock:
            popular_people_cache.update(
                expires_at=time.monotonic() + max(0, POPULAR_PEOPLE_CACHE_SECONDS - (datetime.now(UTC).timestamp() - updated_at)),
                snapshot_id=snapshot["updated_at"],
                people=snapshot["people"],
            )

    def _build_popular_people() -> list[dict]:
        """Build a complete, de-duplicated image-bearing IMDb-first snapshot."""
        popular = []
        seen_ids = set()
        for starmeter_rank, person in enumerate(imdb_starmeter_people(), start=1):
            person_id = person.get("id")
            if person_id and person_id not in seen_ids:
                seen_ids.add(person_id)
                popular.append({**person, "starmeter_rank": starmeter_rank})
                if len(popular) >= POPULAR_PEOPLE_LIMIT:
                    return popular
        tmdb_page = 1
        while len(popular) < POPULAR_PEOPLE_LIMIT:
            data = tmdb_get("/person/popular", {"page": tmdb_page})
            results = (data or {}).get("results", [])
            if not results:
                break
            for person in results:
                person_id = person.get("id")
                if not person_id or person_id in seen_ids or person.get("adult") or not _has_current_tmdb_image(person):
                    continue
                seen_ids.add(person_id)
                popular.append(person)
                if len(popular) >= POPULAR_PEOPLE_LIMIT:
                    break
            tmdb_page += 1
            if tmdb_page > (data or {}).get("total_pages", 0):
                break
        return popular

    def _refresh_popular_people() -> None:
        nonlocal popular_people_refreshing
        try:
            people = _build_popular_people()
            if people:
                snapshot = popular_people_store.save(people)
                _install_popular_people_snapshot(snapshot)
                with popular_people_payload_lock:
                    popular_people_payload_cache.clear()
        except Exception:
            app.logger.exception("Unable to refresh the Trending People snapshot.")
        finally:
            with popular_people_lock:
                popular_people_refreshing = False

    def _refresh_popular_people_in_background() -> None:
        nonlocal popular_people_refreshing
        with popular_people_lock:
            if popular_people_refreshing:
                return
            popular_people_refreshing = True
        threading.Thread(target=_refresh_popular_people, name="popular-people-refresh", daemon=True).start()

    def popular_people() -> list[dict]:
        """Return a fast cached snapshot and refresh stale data without blocking visitors."""
        nonlocal popular_people_refreshing
        with popular_people_lock:
            cached_people = list(popular_people_cache["people"])
            fresh = popular_people_cache["expires_at"] > time.monotonic()
        if not cached_people:
            snapshot = popular_people_store.load()
            if snapshot:
                _install_popular_people_snapshot(snapshot)
                with popular_people_lock:
                    cached_people = list(popular_people_cache["people"])
                    fresh = popular_people_cache["expires_at"] > time.monotonic()
        if cached_people:
            if not fresh:
                _refresh_popular_people_in_background()
            return _filtered_popular_people(cached_people)

        with popular_people_lock:
            if popular_people_refreshing:
                return []
            popular_people_refreshing = True
        _refresh_popular_people()
        with popular_people_lock:
            refreshed_people = list(popular_people_cache["people"])
        return _filtered_popular_people(refreshed_people)

    def clear_popular_people_payload_cache() -> None:
        with popular_people_payload_lock:
            popular_people_payload_cache.clear()

    def popular_people_payload(people: list[dict], flags: dict[int, dict[str, str]]) -> list[dict]:
        """Build display data only for the currently requested page of people."""
        kometa_images = kometa_image_urls()
        payload = []
        for person in people:
            profile_path = person.get("profile_path")
            name = person.get("name", "Unknown person")
            known_for = []
            for credit in person.get("known_for", [])[:3]:
                media_type = credit.get("media_type")
                credit_id = credit.get("id")
                title = credit.get("title") or credit.get("name")
                if media_type in {"movie", "tv"} and credit_id and title:
                    known_for.append({"title": title, "url": f"https://www.themoviedb.org/{media_type}/{credit_id}"})
            repo_image = kometa_images.get("Kometa Repo Image", {}).get(name.casefold())
            variant_images = [
                {"label": label, "url": urls[name.casefold()]}
                for label, urls in kometa_images.items()
                if label != "Kometa Repo Image" and name.casefold() in urls
            ] if repo_image else []
            payload.append({
                "tmdb_id": person["id"], "name": name,
                "tmdb_person_url": f"https://www.themoviedb.org/person/{person['id']}",
                "imdb_person_url": f"https://www.imdb.com/name/{person['imdb_id']}/" if person.get("imdb_id") else None,
                "tmdb_image_url": f"https://image.tmdb.org/t/p/original{profile_path}" if profile_path else None,
                "known_for_department": person.get("known_for_department"), "known_for": known_for,
                "tmdb_image": {
                    "preview_url": f"https://image.tmdb.org/t/p/w342{profile_path}",
                    "download_url": url_for("download_tmdb_image", image_path=profile_path, name=name),
                } if profile_path else None,
                "kometa_image": repo_image,
                "kometa_variant_images": variant_images,
                "flag_reason": flags.get(person["id"], {}).get("reason"),
            })
        return payload

    def save_missing_people(candidates: list[dict], *, filename: str, log_url: str, source_url: str | None) -> list[dict]:
        saved = []
        for candidate in candidates:
            name = candidate["name"]
            match_data = tmdb_get("/search/person", {"query": name})
            matches = (match_data or {}).get("results", [])
            exact = next((item for item in matches if item.get("name", "").casefold() == name.casefold()), None)
            match = exact or (matches[0] if matches else None)
            tmdb_id = match.get("id") if match else None
            image_data = tmdb_get(f"/person/{tmdb_id}/images") if tmdb_id else None
            tmdb_image_found = bool((image_data or {}).get("profiles", []))
            key_seed = str(tmdb_id) if tmdb_id else name.casefold()
            key = f"tmdb-{tmdb_id}" if tmdb_id else f"name-{hashlib.sha256(key_seed.encode()).hexdigest()[:16]}"
            person, is_new = people_store.upsert_with_status({
                "key": key,
                "name": match.get("name", name) if match else name,
                "tmdb_id": tmdb_id,
                "tmdb_image_found": tmdb_image_found,
                "log_tmdb_image_found": bool(candidate["tmdb_image_found"]),
                "log_name": filename,
                "log_url": log_url,
                "source_url": source_url,
            })
            person["people_url"] = url_for("person_page", person_key=person["key"], _external=True)
            person["is_new"] = is_new
            saved.append(person)
        return saved

    def notify_people_webhook(people: list[dict]) -> None:
        """Notify Discord when the website creates a new people-backlog entry."""
        webhook_url = app.config["DISCORD_PEOPLE_WEBHOOK_URL"]
        if not webhook_url:
            app.logger.info("Missing-person webhook is not configured; no website notification sent.")
            return
        new_people = [person for person in people if person.get("is_new")]
        for person in people:
            if not person.get("is_new"):
                app.logger.info("Missing-person webhook skipped for existing person: %s", person["name"])
        if not new_people:
            return
        first = new_people[0]
        if len(new_people) > 2:
            names = "\n".join(f"- {person['name']}" for person in new_people)
            people_summary = (
                f"**People:**\n{names}\n"
                f"[Review all missing people images]({url_for('people_page', _external=True)})"
            )
        else:
            names = "\n".join(
                f"- [{person['name']}]({person['people_url']}) — **TMDb Image Found:** "
                f"{'Yes' if person.get('tmdb_image_found') else 'No'}"
                for person in new_people
            )
            people_summary = f"**People:**\n{names}"
        source_line = (
            f"**Log Source:** [Click Here]({first['source_url']})\n"
            if first.get("source_url") else "**Log Source:** Not available\n"
        )
        message = (
            f"**Log Name:** `{first['log_name']}`\n"
            f"**Log URL:** [Click Here]({first['log_url']})\n"
            f"{source_line}"
            f"{people_summary}"
        )
        try:
            payload = json.dumps({"content": message[:2000], "flags": 4}).encode("utf-8")
            webhook_request = Request(
                webhook_url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Kometa-Logscan/1.0",
                },
                method="POST",
            )
            with urlopen(webhook_request, timeout=10):
                pass
            app.logger.info("Missing-person webhook sent for %d new people.", len(new_people))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            app.logger.warning(
                "Unable to send missing-person Discord webhook: HTTP %s %s",
                exc.code,
                detail,
            )
        except (URLError, TimeoutError) as exc:
            app.logger.warning("Unable to send missing-person Discord webhook: %s", exc)

    def cleanup_loop():
        while True:
            try:
                removed = store.delete_expired(RETENTION_SECONDS)
                if removed:
                    app.logger.info("Deleted %d expired scan(s).", removed)
            except Exception:
                app.logger.exception("Unable to clean up expired scans.")
            time.sleep(CLEANUP_INTERVAL_SECONDS)

    # Gunicorn is intentionally configured with one worker, so one daemon is
    # sufficient. The immediate sweep also removes expired data after downtime.
    store.delete_expired(RETENTION_SECONDS)
    if not app.config.get("TESTING"):
        threading.Thread(target=cleanup_loop, name="logscan-cleanup", daemon=True).start()

    @app.get("/")
    def index():
        return render_template("index.html", initial_scan=None, initial_batch=None)

    @app.get("/people")
    def people_page():
        return render_template("people.html")

    @app.get("/people/popular")
    def popular_people_page():
        return render_template("people_popular.html")

    @app.get("/people/<person_key>")
    def person_page(person_key):
        if people_store.get(person_key) is None:
            abort(404)
        return render_template("person.html", person_key=person_key)

    @app.get("/scan/<scan_id>")
    def result_page(scan_id):
        record = store.get(scan_id)
        if record is None:
            abort(404)
        public = {key: value for key, value in record.items() if key != "delete_token_hash"}
        public["expires_at"] = int(datetime.fromisoformat(record["created_at"]).timestamp() + RETENTION_SECONDS)
        return render_template("index.html", initial_scan=public, initial_batch=None)

    @app.get("/batch/<batch_id>")
    def batch_page(batch_id):
        batch = store.get_batch(batch_id)
        if batch is None:
            abort(404)
        public_url = url_for("batch_page", batch_id=batch_id, _external=True)
        public_scans = [{key: scan[key] for key in ("id", "filename", "result_url", "expires_at")} | {"batch_public_url": public_url, "unscanned_files": batch.get("unscanned_files", [])} for scan in batch["scans"]]
        return render_template("index.html", initial_scan=None, initial_batch=public_scans)

    @app.get("/batch/<batch_id>/admin/<token>")
    def batch_admin_page(batch_id, token):
        batch = store.get_batch(batch_id, token)
        if batch is None:
            abort(404)
        public_url = url_for("batch_page", batch_id=batch_id, _external=True)
        private_url = url_for("batch_admin_page", batch_id=batch_id, token=token, _external=True)
        admin_scans = [
            {
                "id": scan["id"],
                "filename": scan["filename"],
                "result_url": f"{scan['result_url']}#delete={scan['delete_token']}",
                "expires_at": scan["expires_at"],
                "batch_public_url": public_url,
                "batch_private_url": private_url,
                "unscanned_files": batch.get("unscanned_files", []),
            }
            for scan in batch["scans"]
        ]
        return render_template("index.html", initial_scan=None, initial_batch=admin_scans)

    def bot_request_is_authorized() -> bool:
        configured_key = app.config["LOGSCAN_API_KEY"]
        supplied = request.headers.get("Authorization", "").removeprefix("Bearer ")
        return bool(configured_key) and hmac.compare_digest(supplied, configured_key)

    @app.post("/api/bot/validate")
    def validate_bot_upload():
        """Check an attachment without persisting a scan or notifying anyone."""
        if not bot_request_is_authorized():
            return jsonify(error="Invalid API key."), 401
        upload = request.files.get("log")
        if upload is None or not upload.filename:
            return jsonify(error="Choose a log file to scan."), 400
        try:
            files = find_scannable_archive_logs(upload.filename, upload.read())
        except ScanError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(files=[{"filename": filename, "content_size": size} for filename, size in files])

    @app.post("/api/scan")
    @app.post("/api/bot/scan")
    def scan():
        is_bot = bot_request_is_authorized()
        if request.path == "/api/bot/scan" and not is_bot:
            return jsonify(error="Invalid API key."), 401
        uploads = [upload for upload in request.files.getlist("log") if upload.filename]
        if not uploads:
            return jsonify(error="Choose a log file to scan."), 400
        upload = uploads[0]
        upload_filename = upload.filename
        try:
            if len(uploads) == 1:
                content = upload.read()
            else:
                bundled_uploads = BytesIO()
                with zipfile.ZipFile(bundled_uploads, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    for item in uploads:
                        archive.writestr(item.filename, item.read())
                content = bundled_uploads.getvalue()
                upload_filename = "website-log-batch.zip"
            scans = scan_archive_logs(upload_filename, content)
            if not scans:
                filename, content = prepare_scan_input(upload_filename, content)
                scans = [(filename, content, scan_log(filename, content))]
        except ScanError as exc:
            return jsonify(error=str(exc)), 400
        source_url = request.form.get("source_url") if is_bot else None
        uploaded_by = request.form.get("uploaded_by") if is_bot else None
        uploaded_by_id = request.form.get("uploaded_by_id") if is_bot else None
        expires_at = int((datetime.now(UTC) + timedelta(seconds=RETENTION_SECONDS)).timestamp())
        payloads = []
        unscanned_files = []
        if Path(upload_filename).suffix.lower() == ".zip":
            with zipfile.ZipFile(BytesIO(content)) as archive:
                scanned_names = {filename for filename, _content, _result in scans}
                for entry in archive.infolist():
                    if entry.is_dir() or entry.filename in scanned_names:
                        continue
                    suffix = Path(entry.filename).suffix.lower()
                    if suffix not in ALLOWED_SUFFIXES | ARCHIVE_SUFFIXES and not suffix.lstrip(".").isdigit():
                        reason = "Bad file extension"
                    else:
                        with archive.open(entry) as member:
                            entry_content = member.read()
                        try:
                            contained_scans = scan_archive_logs(entry.filename, entry_content)
                        except ScanError:
                            contained_scans = []
                        if contained_scans:
                            continue
                        reason = "ZIP contains no valid Kometa logs" if suffix == ".zip" else "Not a valid Kometa log file"
                    unscanned_files.append({"filename": entry.filename, "reason": reason})
        for filename, content, result in scans:
            if uploaded_by:
                result.overview["uploaded_by"] = uploaded_by
                result.overview["uploaded_by_id"] = uploaded_by_id
                result.overview["message_url"] = source_url
            missing_candidates = extract_missing_people(content.decode("utf-8", errors="replace"))
            repository_people = None
            if missing_candidates:
                repository_people = kometa_image_urls().get("Kometa Repo Image")
                if repository_people is not None:
                    add_missing_people_recommendations(result, missing_candidates, repository_people)
            scan_id, delete_token = store.create(filename, content, result)
            result_url = url_for("result_page", scan_id=scan_id, _external=True)
            missing_people = save_missing_people(
                _people_needing_repository_images(missing_candidates, repository_people),
                filename=result.filename,
                log_url=result_url,
                source_url=source_url,
            )
            payloads.append({"id": scan_id, "filename": result.filename, "recommendations": result.recommendations, "metadata": result.metadata, "overview": result.overview, "categories": result.categories, "result_url": result_url, "delete_token": delete_token, "expires_at": expires_at, "uploaded_by_bot": is_bot, "missing_people": missing_people})
        notify_people_webhook([person for payload in payloads for person in payload["missing_people"]])
        if len(payloads) > 1:
            batch_id, admin_token = store.create_batch(payloads, unscanned_files)
            response = {
                "scans": payloads,
                "batch_result_url": url_for("batch_page", batch_id=batch_id, _external=True),
                "batch_admin_url": url_for("batch_admin_page", batch_id=batch_id, token=admin_token, _external=True),
                "unscanned_files": unscanned_files,
            }
            return jsonify(response)
        if request.path == "/api/bot/scan":
            response = {"scans": payloads}
            return jsonify(response)
        return jsonify({"scans": payloads}) if len(payloads) > 1 else jsonify(payloads[0])

    @app.get("/api/people")
    def people():
        people = people_store.list()
        for person in people:
            person["people_url"] = url_for("person_page", person_key=person["key"], _external=True)
        return jsonify(people=people)

    @app.get("/api/people/popular")
    def popular_people_api():
        if not app.config["TMDB_API_KEY"]:
            return jsonify(error="TMDb API key is not configured."), 503
        page = request.args.get("page", default=1, type=int)
        missing_image = request.args.get("missing_image") == "1"
        people = popular_people()
        people = [person for person in people if _has_current_tmdb_image(person)]
        if missing_image:
            primary_images = kometa_image_urls().get("Kometa Repo Image", {})
            people = [person for person in people if person.get("name", "").casefold() not in primary_images]
        total_pages = max(1, (len(people) + POPULAR_PEOPLE_PAGE_SIZE - 1) // POPULAR_PEOPLE_PAGE_SIZE)
        if page is None or not 1 <= page <= total_pages:
            return jsonify(error=f"Page must be between 1 and {total_pages}."), 400
        first_index = (page - 1) * POPULAR_PEOPLE_PAGE_SIZE
        page_people = people[first_index:first_index + POPULAR_PEOPLE_PAGE_SIZE]
        flags = popular_people_flags.list()
        with popular_people_lock:
            snapshot_id = popular_people_cache["snapshot_id"]
        cache_key = (
            snapshot_id, page, missing_image, tuple(person["id"] for person in page_people),
            tuple(sorted((person_id, flag.get("reason", "")) for person_id, flag in flags.items())),
        )
        with popular_people_payload_lock:
            payload = popular_people_payload_cache.get(cache_key)
        if payload is None:
            payload = popular_people_payload(page_people, flags)
            with popular_people_payload_lock:
                popular_people_payload_cache[cache_key] = payload
        response = jsonify(people=payload, page=page, total_pages=total_pages)
        response.set_etag(hashlib.sha256(repr(cache_key).encode("utf-8")).hexdigest())
        response.headers["Cache-Control"] = "private, max-age=60, stale-while-revalidate=300"
        return response.make_conditional(request)

    @app.get("/api/people/popular/export")
    def export_missing_popular_people():
        """Download people absent from the primary Kometa image repository."""
        if not app.config["TMDB_API_KEY"]:
            return jsonify(error="TMDb API key is not configured."), 503
        primary_images = kometa_image_urls().get("Kometa Repo Image", {})
        missing_people = [
            person for person in popular_people()
            if _has_current_tmdb_image(person) and person.get("name", "").casefold() not in primary_images
        ]
        export = "\n".join(
            f"{person['tmdb_id']}|{person['name']}"
            for person in popular_people_payload(missing_people, popular_people_flags.list())
        )
        return send_file(
            BytesIO(export.encode("utf-8")),
            mimetype="text/plain",
            as_attachment=True,
            download_name="missing-trending-people.txt",
        )

    @app.post("/api/people/popular/<int:person_id>/exclude")
    def exclude_popular_person(person_id):
        if popular_people_exclusions.add(person_id):
            clear_popular_people_payload_cache()
            return "", 201
        return "", 204

    @app.post("/api/people/popular/<int:person_id>/check")
    def check_popular_person(person_id):
        if not popular_people_checks.mark(person_id):
            abort(400)
        popular_people_flags.delete(person_id)
        clear_popular_people_payload_cache()
        return "", 204

    @app.post("/api/people/popular/<int:person_id>/flag")
    def flag_popular_person(person_id):
        payload = request.get_json(silent=True) or {}
        reason = payload.get("reason", "")
        if not isinstance(reason, str) or len(reason.strip()) > 500 or not popular_people_flags.upsert(person_id, reason):
            return jsonify(error="Provide a flag reason of up to 500 characters."), 400
        clear_popular_people_payload_cache()
        return "", 204

    @app.get("/api/tmdb/image-download")
    def download_tmdb_image():
        """Proxy an original TMDb profile image with a useful download filename."""
        image_path = request.args.get("image_path", "")
        person_name = request.args.get("name", "person")
        if not re.fullmatch(r"/[A-Za-z0-9_-]+\.jpe?g", image_path, re.IGNORECASE):
            abort(404)
        filename = re.sub(r'[<>:"/\\\\|?*\x00-\x1f]+', "_", person_name).strip(" .") or "person"
        try:
            with urlopen(
                Request(f"https://image.tmdb.org/t/p/original{image_path}", headers={"Accept": "image/jpeg"}),
                timeout=15,
            ) as response:
                image = response.read()
        except (HTTPError, URLError, TimeoutError):
            app.logger.warning("Unable to download TMDb image %s", image_path)
            abort(502)
        return send_file(BytesIO(image), mimetype="image/jpeg", as_attachment=True, download_name=f"{filename}.jpg")

    @app.get("/api/people/<person_key>/images")
    def person_images(person_key):
        person = people_store.get(person_key)
        if person is None:
            abort(404)
        images = []
        if not person.get("tmdb_id"):
            match_data = tmdb_get("/search/person", {"query": person["name"]})
            matches = (match_data or {}).get("results", [])
            exact = next(
                (item for item in matches if item.get("name", "").casefold() == person["name"].casefold()),
                None,
            )
            match = exact or (matches[0] if matches else None)
            if match:
                person = people_store.upsert({
                    **person,
                    "tmdb_id": match["id"],
                    "name": match.get("name", person["name"]),
                })
        if person.get("tmdb_id"):
            data = tmdb_get(f"/person/{person['tmdb_id']}/images", {"include_image_language": "en,null"})
            for image in (data or {}).get("profiles", []):
                path = image.get("file_path")
                if path:
                    images.append({
                        "preview_url": f"https://image.tmdb.org/t/p/w342{path}",
                        "download_url": url_for("download_tmdb_image", image_path=path, name=person["name"]),
                        "width": image.get("width"),
                        "height": image.get("height"),
                    })
            if person.get("tmdb_image_found") != bool(images):
                person = people_store.upsert({**person, "tmdb_image_found": bool(images)})
        limit = request.args.get("limit", type=int)
        if limit is not None:
            images = images[:max(0, min(limit, 100))]
        return jsonify(person=person, images=images)

    @app.delete("/api/people/<person_key>")
    def complete_person(person_key):
        if not people_store.delete(person_key):
            abort(404)
        return "", 204

    @app.get("/api/scans/<scan_id>/log")
    def stored_log(scan_id):
        path = store.log_path(scan_id)
        if path is None:
            abort(404)
        return send_file(path, mimetype="text/plain; charset=utf-8", conditional=True)

    @app.post("/api/scans/<scan_id>/validate-config")
    def validate_stored_config(scan_id):
        path = store.log_path(scan_id)
        if path is None:
            abort(404)
        try:
            failures = validate_redacted_config(path.read_text(encoding="utf-8", errors="replace"))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        except RuntimeError as exc:
            app.logger.warning("Config validation failed: %s", exc)
            return jsonify(error=str(exc)), 502
        return jsonify(failures=failures)

    @app.delete("/api/scans/<scan_id>")
    def delete_scan(scan_id):
        token = request.headers.get("X-Delete-Token", "")
        if not token or not store.delete(scan_id, token):
            return jsonify(error="The scan was not found or the delete token is invalid."), 403
        return "", 204

    @app.delete("/api/batches/<batch_id>/admin/<token>")
    def delete_batch(batch_id, token):
        if not store.delete_batch(batch_id, token):
            return jsonify(error="The batch was not found or the private token is invalid."), 403
        return "", 204

    @app.errorhandler(404)
    def not_found(_error):
        if request.path.startswith("/api/"):
            return jsonify(error="The requested resource was not found."), 404
        return render_template("404.html"), 404

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify(error="The selected file is larger than the 100 MB limit."), 413

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
