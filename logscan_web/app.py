import hmac
import hashlib
import json
import os
import re
import secrets
import threading
import time
import tempfile
import unicodedata
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from flask import Flask, abort, jsonify, render_template, request, send_file, url_for, session
from werkzeug.middleware.proxy_fix import ProxyFix

from .models import Finding
from .recommendations import has_yaml_language_server_directive, schema_branch_for_log, validate_redacted_config
from .scanner import ALLOWED_SUFFIXES, ARCHIVE_SUFFIXES, MAX_FILE_BYTES, ScanError, extract_quickstart_metadata, find_scannable_archive_logs, find_scannable_upload_path, prepare_scan_input, scan_archive_logs, scan_content_size, scan_log
from .storage import AnonymousAnalyticsStore, PeopleStore, PopularPeopleCacheStore, PopularPeopleCheckStore, PopularPeopleExclusionStore, PopularPeopleFlagStore, ScanStore, TMDbFindCacheStore, UsageStatsStore
from .support import create_support_blueprint, discord_session_user, support_session_authorized

LOG_INDEX_STRIDE = 1000
LOG_VIEW_MAX_LINES = 2000
_log_index_cache = {}
_log_index_lock = threading.Lock()


def _format_bytes(value: int) -> str:
    size = float(max(0, value))
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def _is_archive_upload(filename: str) -> bool:
    lowered = filename.casefold()
    compound = (".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar.zst")
    return Path(lowered).suffix in ARCHIVE_SUFFIXES or lowered.endswith(compound)


def _finalize_result_metrics(result, archive_compressed_size: int | None, archive_uncompressed_size: int | None) -> None:
    counts = result.metadata.setdefault("counts", {})
    for severity in ("critical", "error", "warning", "advice"):
        counts[severity] = sum(item.get("severity") == severity for item in result.recommendations)
    counts["schema"] = int(result.metadata.get("schema_validation_count") or counts.get("schema") or 0)
    finding_count = sum(int(counts.get(severity) or 0) for severity in ("critical", "error", "warning", "schema", "advice"))
    size_bytes = int(result.metadata.get("size_bytes") or 0)
    overview = result.overview
    overview["finding_count"] = finding_count
    overview["line_count"] = int(result.metadata.get("line_count") or 0)
    overview["size_display"] = _format_bytes(size_bytes)
    if archive_compressed_size is None or archive_uncompressed_size is None:
        return
    ratio = archive_uncompressed_size / archive_compressed_size if archive_compressed_size else 0
    reduction = (1 - (archive_compressed_size / archive_uncompressed_size)) * 100 if archive_uncompressed_size else 0
    result.metadata.update({
        "archive_compressed_size": archive_compressed_size,
        "archive_uncompressed_size": archive_uncompressed_size,
        "archive_compression_ratio": ratio,
        "archive_reduction_percent": reduction,
    })
    overview.update({
        "archive_compressed_size_display": _format_bytes(archive_compressed_size),
        "archive_uncompressed_size_display": _format_bytes(archive_uncompressed_size),
        "archive_compression_ratio": f"{ratio:.2f}:1",
        "archive_reduction_percent": f"{reduction:.1f}%",
    })

def _stored_log_index(path: Path) -> dict:
    stat = path.stat()
    cache_key = (str(path), stat.st_mtime_ns, stat.st_size)
    with _log_index_lock:
        cached = _log_index_cache.get(cache_key)
        if cached is not None:
            return cached
        offsets = [0]
        sections = []
        recent = []
        config_lines = []
        in_config = False
        with path.open("rb") as source:
            line_number = 0
            while raw_line := source.readline():
                line_number += 1
                line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                if line_number > 1 and (line_number - 1) % LOG_INDEX_STRIDE == 0:
                    offsets.append(source.tell() - len(raw_line))
                recent.append(line)
                if len(recent) > 3:
                    recent.pop(0)
                if len(recent) == 3 and re.search(r"\|={10,}\|\s*$", recent[0]) and re.search(r"\|={10,}\|\s*$", recent[2]):
                    match = re.search(r"\|\s*([^|=][^|]*?)\s*\|\s*$", recent[1])
                    if match:
                        sections.append({"title": match.group(1).strip(), "line": line_number - 1})
                if not in_config:
                    in_config = "Redacted Config" in line
                elif "Config Warning:" in line or "Initializing cache database at" in line:
                    in_config = False
                elif in_config:
                    match = re.search(r"\[config\.py:\d+\]\s+\[([A-Z]+)\]\s*\|(.*)$", line)
                    if not match or match.group(1) in {"CRITICAL", "ERROR", "WARNING"}:
                        in_config = False
                    else:
                        value = match.group(2).rstrip(" |")
                        config_lines.append(value[1:] if value.startswith(" ") else value)
        if len(config_lines) > 1:
            config_lines.pop()
        index = {"offsets": offsets, "total": line_number, "sections": sections, "config": "\n".join(config_lines)}
        if len(_log_index_cache) >= 8:
            _log_index_cache.pop(next(iter(_log_index_cache)))
        _log_index_cache[cache_key] = index
        return index


def _stored_log_lines(path: Path, index: dict, start: int, count: int) -> list[str]:
    block = (start - 1) // LOG_INDEX_STRIDE
    first_line = block * LOG_INDEX_STRIDE + 1
    lines = []
    with path.open("rb") as source:
        source.seek(index["offsets"][block])
        current = first_line
        while current < start and source.readline():
            current += 1
        while len(lines) < count and (raw_line := source.readline()):
            lines.append(raw_line.decode("utf-8", errors="replace").rstrip("\r\n"))
    return lines

RETENTION_SECONDS = 48 * 60 * 60
CLEANUP_INTERVAL_SECONDS = 60 * 60
SCHEMA_VALIDATION_VERSION = 2
POPULAR_PEOPLE_PAGE_SIZE = 25
TMDB_POPULAR_PAGE_SIZE = 20
KOMETA_IMAGE_SOURCES = (
    ("Kometa Repo Image", "https://raw.githubusercontent.com/Kometa-Team/People-Images/refs/heads/master/README.md"),
    ("Black & White", "https://raw.githubusercontent.com/Kometa-Team/People-Images-bw/master/README.md"),
    ("DIIIVOY", "https://raw.githubusercontent.com/Kometa-Team/People-Images-diiivoy/master/README.md"),
    ("DIIIVOY Color", "https://raw.githubusercontent.com/Kometa-Team/People-Images-diiivoycolor/master/README.md"),
    ("Rainier", "https://raw.githubusercontent.com/Kometa-Team/People-Images-rainier/master/README.md"),
    ("Signature", "https://raw.githubusercontent.com/Kometa-Team/People-Images-signature/master/README.md"),
)
KOMETA_IMAGE_CACHE_SECONDS = 60 * 60
POPULAR_PEOPLE_CACHE_SECONDS = 24 * 60 * 60
POPULAR_PEOPLE_LIMIT = 250
POPULAR_PEOPLE_CHECK_SECONDS = 30 * 24 * 60 * 60
KOMETA_VERSION_CACHE_SECONDS = 60 * 60
KOMETA_VERSION_URL = "https://raw.githubusercontent.com/Kometa-Team/Kometa/{branch}/VERSION"
_kometa_version_cache = {"checked_at": None, "expires_at": 0.0, "versions": {}}
_kometa_version_lock = threading.Lock()
TMDB_FIND_CACHE_SECONDS = 7 * 24 * 60 * 60
TMDB_FIND_MAX_WORKERS = 8


def _person_name_key(value: str | None) -> str:
    """Return an accent-insensitive key for matching person image names."""
    decomposed = unicodedata.normalize("NFKD", value or "")
    unaccented = "".join(character for character in decomposed if not unicodedata.combining(character))
    return " ".join(unaccented.casefold().split())


def add_missing_people_recommendations(
    result, candidates: list[dict], repository_people: dict[str, str], people_url: str | None = None,
) -> None:
    """Add advice for missing people images, split by repository availability."""
    found = []
    pending = []
    for candidate in candidates:
        name = candidate["name"]
        (found if _person_name_key(name) in repository_people else pending).append(name)

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
            "Wait for the People Images repository to be updated, then rerun Kometa to create the affected collection image."
            + (f" Review the submitted people here: {people_url}" if people_url else ""),
        )
    if found or pending:
        result.recommendations.sort(key=lambda item: {"critical": 0, "error": 1, "warning": 2, "schema": 3, "advice": 4}[item["severity"]])
        result.metadata["counts"]["advice"] = sum(item["severity"] == "advice" for item in result.recommendations)
        result.overview["finding_count"] = len(result.recommendations)


def _people_needing_repository_images(candidates: list[dict], repository_people: dict[str, str] | None) -> list[dict]:
    """Return log candidates absent from the primary People Images repository."""
    if repository_people is None:
        # Keep the existing reporting path when GitHub is temporarily unavailable.
        return candidates
    return [candidate for candidate in candidates if _person_name_key(candidate["name"]) not in repository_people]


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
    app.config["DISCORD_CLIENT_ID"] = os.environ.get("DISCORD_CLIENT_ID", "")
    app.config["DISCORD_CLIENT_SECRET"] = os.environ.get("DISCORD_CLIENT_SECRET", "")
    app.config["DISCORD_GUILD_ID"] = os.environ.get("DISCORD_GUILD_ID", "")
    app.config["DISCORD_SUPPORT_ROLE_IDS"] = {
        role.strip()
        for role in os.environ.get("DISCORD_SUPPORT_ROLE_IDS", "").split(",")
        if role.strip()
    }
    app.config["DISCORD_REDIRECT_URI"] = os.environ.get(
        "DISCORD_REDIRECT_URI", "http://127.0.0.1:5000/support/callback"
    )
    app.config["LOGSCAN_SECRET_KEY"] = os.environ.get("LOGSCAN_SECRET_KEY", "")
    app.secret_key = app.config["LOGSCAN_SECRET_KEY"] or secrets.token_bytes(32)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("LOGSCAN_SECURE_COOKIES", "false").casefold() in {"1", "true", "yes"}
    app.config["TMDB_API_KEY"] = os.environ.get("TMDB_API_KEY", "")
    app.config["DISCORD_PEOPLE_WEBHOOK_URL"] = os.environ.get("DISCORD_PEOPLE_WEBHOOK_URL", "")
    support_keys = (
        "DISCORD_CLIENT_ID",
        "DISCORD_CLIENT_SECRET",
        "DISCORD_GUILD_ID",
        "DISCORD_SUPPORT_ROLE_IDS",
        "LOGSCAN_SECRET_KEY",
    )
    missing_support_keys = [key for key in support_keys if not app.config.get(key)]
    if missing_support_keys:
        app.logger.warning(
            "Discord OAuth disabled; missing configuration: %s",
            ", ".join(missing_support_keys),
        )
    else:
        app.logger.warning(
            "Discord OAuth enabled: guild_id=%s roles=%d redirect_uri=%s secure_cookie=%s",
            app.config["DISCORD_GUILD_ID"],
            len(app.config["DISCORD_SUPPORT_ROLE_IDS"]),
            app.config["DISCORD_REDIRECT_URI"],
            app.config["SESSION_COOKIE_SECURE"],
        )
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    store = ScanStore(app.config["SCAN_STORE"])
    people_store = PeopleStore(app.config["SCAN_STORE"])
    usage_stats = UsageStatsStore(app.config["SCAN_STORE"])
    analytics = AnonymousAnalyticsStore(app.config["SCAN_STORE"])
    usage_stats.ensure_people_baseline(len(people_store.list()))
    analytics.import_legacy_baseline(usage_stats.snapshot())
    popular_people_exclusions = PopularPeopleExclusionStore(app.config["SCAN_STORE"])
    popular_people_checks = PopularPeopleCheckStore(app.config["SCAN_STORE"])
    popular_people_flags = PopularPeopleFlagStore(app.config["SCAN_STORE"])
    popular_people_store = PopularPeopleCacheStore(app.config["SCAN_STORE"])
    tmdb_find_cache = TMDbFindCacheStore(app.config["SCAN_STORE"])
    app.register_blueprint(create_support_blueprint(store, RETENTION_SECONDS))
    kometa_images_cache = {"expires_at": 0.0, "images": {}}
    kometa_images_lock = threading.Lock()
    popular_people_cache = {"expires_at": 0.0, "snapshot_id": "", "people": []}
    popular_people_lock = threading.Lock()
    popular_people_refreshing = False
    scan_jobs: dict[str, dict] = {}
    scan_jobs_lock = threading.Lock()
    scan_slot = threading.Semaphore(1)
    background_scan_token = secrets.token_urlsafe(32)
    background_scan_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="logscan")
    schema_cache = {}
    schema_cache_dir = Path(app.config["SCAN_STORE"]) / ".schema-cache"
    schema_cache_lock = threading.Lock()

    def validate_config(log_content: str) -> list[dict]:
        """Validate using the process cache without serializing validation work."""
        return validate_redacted_config(
            log_content,
            schema_cache=schema_cache,
            schema_cache_dir=schema_cache_dir,
            schema_cache_lock=schema_cache_lock,
        )

    def update_scan_job(job_id: str | None, phase: str, *, error: str | None = None, redirect_url: str | None = None, result: dict | None = None) -> None:
        if not job_id:
            return
        now = time.time()
        with scan_jobs_lock:
            for expired_id in [
                key for key, value in scan_jobs.items()
                if now - value.get("updated_at", now) > 3600
            ]:
                scan_jobs.pop(expired_id, None)
            job = scan_jobs.setdefault(job_id, {"started_at": now})
            job.update(phase=phase, updated_at=now)
            if error:
                job["error"] = error
            if redirect_url:
                job["redirect_url"] = redirect_url
            if result is not None:
                job["result"] = result
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
                    _person_name_key(name): url
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

        def resolve(imdb_id: str) -> tuple[str, dict | None, bool]:
            cached = tmdb_find_cache.get(imdb_id, TMDB_FIND_CACHE_SECONDS)
            if cached is not None:
                return imdb_id, cached, False
            data = tmdb_get(f"/find/{imdb_id}", {"external_source": "imdb_id"})
            match = next((person for person in (data or {}).get("person_results", []) if person.get("id")), None)
            return imdb_id, match, True

        with ThreadPoolExecutor(max_workers=TMDB_FIND_MAX_WORKERS, thread_name_prefix="tmdb-find") as executor:
            lookup_results = list(executor.map(resolve, imdb_ids))
        resolved = {imdb_id: match for imdb_id, match, _ in lookup_results}
        newly_resolved = {imdb_id: match for imdb_id, match, should_cache in lookup_results if should_cache}
        if newly_resolved:
            tmdb_find_cache.save_many(newly_resolved)
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
            person_id = person.get("id")
            profile_path = person.get("profile_path")
            name = person.get("name", "Unknown person")
            known_for = []
            for credit in person.get("known_for", [])[:3]:
                media_type = credit.get("media_type")
                credit_id = credit.get("id")
                title = credit.get("title") or credit.get("name")
                if media_type in {"movie", "tv"} and credit_id and title:
                    known_for.append({"title": title, "url": f"https://www.themoviedb.org/{media_type}/{credit_id}"})
            name_key = _person_name_key(name)
            repo_image = kometa_images.get("Kometa Repo Image", {}).get(name_key)
            variant_images = [
                {"label": label, "url": urls[name_key]}
                for label, urls in kometa_images.items()
                if label != "Kometa Repo Image" and name_key in urls
            ]
            payload.append({
                "tmdb_id": person_id, "name": name,
                "tmdb_person_url": f"https://www.themoviedb.org/person/{person_id}" if person_id else None,
                "tmdb_images_url": f"https://www.themoviedb.org/person/{person_id}/images/profiles" if person_id else None,
                "imdb_person_url": f"https://www.imdb.com/name/{person['imdb_id']}/" if person.get("imdb_id") else None,
                "tmdb_image_url": f"https://image.tmdb.org/t/p/original{profile_path}" if profile_path else None,
                "known_for_department": person.get("known_for_department"), "known_for": known_for,
                "tmdb_image": {
                    "preview_url": f"https://image.tmdb.org/t/p/w342{profile_path}",
                    "download_url": url_for("download_tmdb_image", image_path=profile_path, name=name),
                } if profile_path else None,
                "kometa_image": repo_image,
                "kometa_variant_images": variant_images,
                "flag_reason": flags.get(person_id, {}).get("reason") if person_id else None,
            })
        return payload

    def normalized_kometa_version(value: str | None) -> str:
        """Keep only a conservative version token; never persist arbitrary log text."""
        if not value:
            return "unknown"
        match = re.search(r"(?i)(?:v)?(\d+\.\d+(?:\.\d+)?(?:-build\d+)?)", value)
        return match.group(1) if match else "unknown"

    def normalized_quickstart_version(value: str | None) -> str:
        if not value:
            return "unknown"
        match = re.fullmatch(r"(?i)v?(\d+\.\d+(?:\.\d+)?(?:-build\d+)?)", value.strip())
        return match.group(1) if match else "unknown"

    def safe_branch(value: str | None, allowed: set[str]) -> str:
        branch = (value or "").casefold()
        return branch if branch in allowed else "unknown"

    def rejection_category(message: str) -> str:
        lowered = message.casefold()
        if "larger than" in lowered:
            return "too_large"
        if "encrypted" in lowered:
            return "encrypted_archive"
        if "archive" in lowered or "zip" in lowered or "gzip" in lowered or "tar" in lowered:
            return "invalid_archive"
        if "empty" in lowered:
            return "empty_file"
        if "complete kometa log" in lowered or "valid kometa logs" in lowered:
            return "not_kometa_log"
        if "choose" in lowered or "extension" in lowered:
            return "unsupported_file"
        return "invalid_upload"

    def selected_people_sources() -> set[str]:
        """The unified page always builds both discovery sources before tag filtering."""
        return {"missing", "trending"}

    def categorized_people_tags(person: dict) -> dict[str, list[str]]:
        requesters = [
            f"Requested by {requester['name']}"
            for requester in person.get("requested_by", [])
            if requester.get("name")
        ]
        discovery = []
        if "trending" in person.get("sources", []):
            discovery.append("Trending")
        discovery.extend(person.get("provenance_tags", []))
        availability = ["Missing Kometa"] if "missing" in person.get("sources", []) else []
        return {
            "availability": availability,
            "discovery": discovery,
            "tmdb": list(person.get("metadata_tags", [])),
            "requester": requesters,
        }

    def searchable_people_tags(person: dict) -> list[str]:
        tags = list(person.get("sources", []))
        if "missing" in tags:
            tags.append("Missing Kometa")
        groups = categorized_people_tags(person)
        for values in groups.values():
            tags.extend(values)
        tags.extend(tag.removeprefix("Requested by ") for tag in groups["requester"])
        return tags

    def available_people_tags(people: list[dict]) -> list[dict]:
        counts: dict[tuple[str, str], int] = {}
        for person in people:
            for category, tags in categorized_people_tags(person).items():
                for tag in set(tags):
                    counts[(category, tag)] = counts.get((category, tag), 0) + 1
        category_order = {"availability": 0, "discovery": 1, "tmdb": 2, "requester": 3}
        return [
            {"category": category, "tag": tag, "count": count}
            for (category, tag), count in sorted(
                counts.items(), key=lambda item: (category_order[item[0][0]], item[0][1].casefold())
            )
        ]

    def filter_people_by_tag(people: list[dict], query: str) -> list[dict]:
        """Filter source and requester tags with case-insensitive * and ? wildcards."""
        query = query.strip().casefold()
        if not query:
            return people
        wildcarded = "*" in query or "?" in query
        expression = re.escape(query).replace(r"\*", ".*").replace(r"\?", ".")
        pattern = re.compile(f"^{expression}$" if wildcarded else f".*{expression}.*")
        return [
            person for person in people
            if any(pattern.fullmatch(tag.casefold()) for tag in searchable_people_tags(person))
        ]

    def filter_people_by_selected_tags(people: list[dict], selected: list[str], available: list[dict]) -> list[dict]:
        if not selected:
            return people
        categories = {item["tag"].casefold(): item["category"] for item in available}
        selected_by_category: dict[str, set[str]] = {}
        for tag in selected:
            category = categories.get(tag.casefold())
            if category is None:
                return []
            selected_by_category.setdefault(category, set()).add(tag.casefold())

        def matches(person: dict) -> bool:
            groups = categorized_people_tags(person)
            return all(
                selected_tags & {tag.casefold() for tag in groups.get(category, [])}
                for category, selected_tags in selected_by_category.items()
            )

        return [person for person in people if matches(person)]

    def people_union(sources: set[str]) -> list[dict]:
        """Return missing-log and trending people, keyed by TMDb ID."""
        primary_images = kometa_image_urls().get("Kometa Repo Image", {})
        combined: dict[str, dict] = {}

        if sources & {"missing", "trending"} and app.config["TMDB_API_KEY"]:
            for person in popular_people():
                name = person.get("name", "Unknown person")
                if not _has_current_tmdb_image(person):
                    continue
                missing_image = _person_name_key(name) not in primary_images
                if "trending" not in sources and not missing_image:
                    continue
                person_sources = {"trending"}
                if missing_image:
                    person_sources.add("missing")
                combined[f"tmdb-{person['id']}"] = {**person, "sources": person_sources}

        if "missing" in sources:
            trending_by_name = {
                person.get("name", "").casefold(): person
                for person in combined.values()
                if person.get("name")
            }
            for record in people_store.list():
                if _person_name_key(record.get("name")) in primary_images:
                    analytics.record_addressed([record])
                    continue
                person_id = record.get("tmdb_id")
                if not person_id:
                    matched = trending_by_name.get(record.get("name", "").casefold())
                    person_id = matched.get("id") if matched else None
                key = f"tmdb-{person_id}" if person_id else record["key"]
                person = combined.get(key)
                if person is None:
                    details = tmdb_get(f"/person/{person_id}") if person_id else None
                    person = {
                        **(details or {}),
                        "id": person_id,
                        "name": (details or {}).get("name", record["name"]),
                        "sources": set(),
                    }
                    combined[key] = person
                person["sources"].add("missing")
                person["missing_record"] = record

        people = list(combined.values())
        flags = popular_people_flags.list()
        people.sort(key=lambda person: (
            0 if "missing" in person["sources"] else 1,
            person.get("starmeter_rank", POPULAR_PEOPLE_LIMIT + 1),
            person.get("name", "").casefold(),
        ))
        payload = popular_people_payload(people, flags)
        for item, person in zip(payload, people):
            record = person.get("missing_record", {})
            sources = sorted(person["sources"])
            metadata_tags = []
            tmdb_ready = bool(item.get("tmdb_image")) or bool(record.get("tmdb_image_found"))
            if "missing" in sources:
                metadata_tags.append("TMDb Ready" if tmdb_ready else "Missing TMDb")
            requesters = record.get("requested_by", [])
            if record and not requesters:
                requesters = [{"name": "Unknown", "id": None}]
            item.update(
                person_key=f"tmdb-{person['id']}" if person.get("id") else record.get("key"),
                sources=sources,
                metadata_tags=metadata_tags,
                provenance_tags=["Log Upload"] if record else [],
                log_url=record.get("log_url"),
                source_url=record.get("source_url"),
                original_name=record.get("original_name", record.get("name", item["name"])),
                requested_by=requesters,
            )
        return payload

    def save_missing_people(
        candidates: list[dict], *, filename: str, log_url: str, source_url: str | None,
        uploaded_by: str | None = None, uploaded_by_id: str | None = None,
    ) -> list[dict]:
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
                "original_name": name,
                "tmdb_id": tmdb_id,
                "tmdb_image_found": tmdb_image_found,
                "log_tmdb_image_found": bool(candidate["tmdb_image_found"]),
                "log_name": filename,
                "log_url": log_url,
                "source_url": source_url,
                "requested_by": [{"name": uploaded_by, "id": uploaded_by_id}] if uploaded_by else [],
            })
            person["people_url"] = url_for("people_page", tags="Missing Kometa", _external=True)
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

    def backfill_schema_validation_counts():
        records = [
            record for record in store.list()
            if (record.get("metadata") or {}).get("schema_validation_version") != SCHEMA_VALIDATION_VERSION
        ]
        if not records:
            return
        app.logger.info("Backfilling schema validation counts for %d retained scan(s).", len(records))
        completed = 0
        for record in records:
            scan_id = record.get("id", "")
            path = store.log_path(scan_id)
            if path is None:
                continue
            try:
                log_content = path.read_text(encoding="utf-8", errors="replace")
                failures = validate_config(log_content)
                count = len(failures)
            except ValueError:
                failures = []
                count = 0
            except RuntimeError as exc:
                app.logger.warning("Schema count backfill unavailable for scan %s: %s", scan_id, exc)
                continue
            store.update_metadata(
                scan_id,
                schema_validation_count=count,
                schema_validation_branch=schema_branch_for_log(log_content),
                schema_validation_failures=failures,
                schema_directive_missing=not has_yaml_language_server_directive(log_content),
                schema_validation_version=SCHEMA_VALIDATION_VERSION,
            )
            completed += 1
            time.sleep(0.5)
        app.logger.info("Backfilled schema validation counts for %d of %d retained scan(s).", completed, len(records))
    def backfill_quickstart_metadata():
        records = [
            record for record in store.list()
            if "quickstart_run" not in (record.get("metadata") or {})
        ]
        if not records:
            return
        app.logger.info("Backfilling Quickstart metadata for %d retained scan(s).", len(records))
        completed = 0
        for record in records:
            scan_id = record.get("id", "")
            path = store.log_path(scan_id)
            if path is None:
                continue
            try:
                launcher_metadata = extract_quickstart_metadata(
                    path.read_text(encoding="utf-8", errors="replace")
                )
            except OSError as exc:
                app.logger.warning("Quickstart metadata backfill failed for scan %s: %s", scan_id, exc)
                continue
            if store.update_metadata(scan_id, **launcher_metadata):
                completed += 1
        app.logger.info("Backfilled Quickstart metadata for %d of %d retained scan(s).", completed, len(records))

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
        threading.Thread(target=backfill_schema_validation_counts, name="schema-count-backfill", daemon=True).start()
        threading.Thread(target=backfill_quickstart_metadata, name="quickstart-metadata-backfill", daemon=True).start()

    @app.context_processor
    def service_usage():
        analytics_snapshot = analytics.snapshot()
        totals = analytics_snapshot["totals"]
        stats = {
            "logs_submitted": totals["successful_logs"],
            "lines_processed": totals["lines_processed"],
            "people_submitted": totals["people_submitted"],
            "people_addressed": totals["people_addressed"],
            "started_at": analytics_snapshot["started_at"],
        }
        try:
            started = datetime.fromisoformat(stats["started_at"])
            stats["tracking_since"] = started.strftime("%B %d, %Y").replace(" 0", " ")
        except (KeyError, TypeError, ValueError):
            stats["tracking_since"] = "tracking began"
        return {
            "usage_stats": stats,
            "discord_user": discord_session_user(),
            "support_access": support_session_authorized(),
        }

    @app.get("/")
    def index():
        return render_template("index.html", initial_scan=None, initial_batch=None)

    @app.get("/favicon.ico")
    def favicon():
        return send_file(Path(app.static_folder) / "favicon.png", mimetype="image/png")

    @app.get("/people")
    def people_page():
        return render_template("people.html")

    @app.get("/analytics")
    def analytics_page():
        return render_template("analytics.html")

    @app.get("/scan/<scan_id>")
    def result_page(scan_id):
        record = store.get(scan_id)
        if record is None:
            abort(404)
        public = {key: value for key, value in record.items() if key != "delete_token_hash"}
        metadata = public.setdefault("metadata", {})
        schema_count = metadata.get("schema_validation_count")
        if isinstance(schema_count, int):
            metadata.setdefault("counts", {})["schema"] = schema_count
        recommendations = public.get("recommendations") or []
        counts = {
            severity: sum(item.get("severity") == severity for item in recommendations)
            for severity in ("critical", "error", "warning", "schema", "advice")
        }
        if isinstance(schema_count, int):
            counts["schema"] = schema_count
        overview = public.setdefault("overview", {})
        overview["finding_count"] = sum(counts.values())
        overview["line_count"] = int(metadata.get("line_count") or 0)
        overview["size_display"] = _format_bytes(int(metadata.get("size_bytes") or 0))
        compressed_size = int(metadata.get("archive_compressed_size") or 0)
        uncompressed_size = int(metadata.get("archive_uncompressed_size") or 0)
        if compressed_size and uncompressed_size:
            ratio = float(metadata.get("archive_compression_ratio") or (uncompressed_size / compressed_size))
            reduction = float(metadata.get("archive_reduction_percent") or ((1 - compressed_size / uncompressed_size) * 100))
            overview.update({
                "archive_compressed_size_display": _format_bytes(compressed_size),
                "archive_uncompressed_size_display": _format_bytes(uncompressed_size),
                "archive_compression_ratio": f"{ratio:.2f}:1",
                "archive_reduction_percent": f"{reduction:.1f}%",
            })
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
        upload_filename = upload.filename
        supplied_job_id = request.headers.get("X-Scan-Job-ID", "")
        job_id = supplied_job_id if re.fullmatch(r"[A-Za-z0-9_-]{20,80}", supplied_job_id) else None
        if job_id:
            temporary = tempfile.NamedTemporaryFile(prefix="logscan-validation-", delete=False)
            temporary_path = Path(temporary.name)
            try:
                with temporary:
                    upload.save(temporary)
            except Exception:
                temporary_path.unlink(missing_ok=True)
                raise
            update_scan_job(job_id, "queued")

            def run_background_validation():
                update_scan_job(job_id, "validating")
                try:
                    files = find_scannable_upload_path(upload_filename, temporary_path)
                except ScanError as exc:
                    update_scan_job(job_id, "failed", error=str(exc))
                    return
                finally:
                    temporary_path.unlink(missing_ok=True)
                result = {"files": [{"filename": filename, "content_size": size} for filename, size in files]}
                update_scan_job(job_id, "complete", result=result)

            background_scan_executor.submit(run_background_validation)
            return jsonify(job_id=job_id, phase="queued"), 202
        content = upload.read()
        try:
            files = find_scannable_archive_logs(upload_filename, content)
        except ScanError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(files=[{"filename": filename, "content_size": size} for filename, size in files])

    @app.get("/api/scan-jobs/<job_id>")
    def scan_job_status(job_id):
        if not re.fullmatch(r"[A-Za-z0-9_-]{20,80}", job_id):
            abort(404)
        with scan_jobs_lock:
            job = scan_jobs.get(job_id)
            if job is None:
                abort(404)
            payload = dict(job)
            if payload["phase"] == "queued":
                waiting = sorted(
                    (candidate_id, candidate)
                    for candidate_id, candidate in scan_jobs.items()
                    if candidate.get("phase") in {"uploading", "queued", "validating", "scanning", "saving"}
                )
                waiting.sort(key=lambda item: item[1].get("started_at", 0))
                position = next(
                    (index for index, (candidate_id, _candidate) in enumerate(waiting, start=1) if candidate_id == job_id),
                    1,
                )
                payload["queue_position"] = position
                payload["ahead_count"] = max(0, position - 1)
        payload["elapsed_seconds"] = max(0, round(time.time() - payload["started_at"]))
        return jsonify(payload)

    @app.post("/api/scan")
    @app.post("/api/bot/scan")
    def scan():
        is_bot = bot_request_is_authorized()
        is_background_scan = hmac.compare_digest(request.headers.get("X-Background-Scan", ""), background_scan_token)
        supplied_job_id = request.headers.get("X-Scan-Job-ID", "")
        accepts_job_id = request.path == "/api/scan" or is_bot or is_background_scan
        job_id = supplied_job_id if accepts_job_id and re.fullmatch(r"[A-Za-z0-9_-]{20,80}", supplied_job_id) else None
        update_scan_job(job_id, "uploading")
        if request.path == "/api/bot/scan" and not is_bot:
            analytics.record_rejection("unauthorized_bot", "discord")
            return jsonify(error="Invalid API key."), 401
        uploads = [upload for upload in request.files.getlist("log") if upload.filename]
        if not uploads:
            analytics.record_rejection("missing_file", "discord" if is_bot else "web")
            return jsonify(error="Choose a log file to scan."), 400
        upload = uploads[0]
        upload_filename = upload.filename
        trusted_attribution = is_bot or is_background_scan
        signed_in_user = discord_session_user() if not trusted_attribution else None
        source_url = request.form.get("source_url") if trusted_attribution else None
        uploaded_by = request.form.get("uploaded_by") if trusted_attribution else (signed_in_user or {}).get("username")
        uploaded_by_id = request.form.get("uploaded_by_id") if trusted_attribution else (signed_in_user or {}).get("id")
        upload_source = "discord" if is_bot else "web"
        try:
            queued_upload_path = None
            if len(uploads) == 1 and job_id and not is_background_scan:
                temporary = tempfile.NamedTemporaryFile(prefix="logscan-scan-", delete=False)
                queued_upload_path = Path(temporary.name)
                try:
                    with temporary:
                        upload.save(temporary)
                except Exception:
                    queued_upload_path.unlink(missing_ok=True)
                    raise
                content = None
            elif len(uploads) == 1:
                content = upload.read()
            else:
                bundled_uploads = BytesIO()
                with zipfile.ZipFile(bundled_uploads, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    for item in uploads:
                        archive.writestr(item.filename, item.read())
                content = bundled_uploads.getvalue()
                upload_filename = "website-log-batch.zip"
            if job_id and not is_background_scan:
                if queued_upload_path is None:
                    temporary = tempfile.NamedTemporaryFile(prefix="logscan-scan-", delete=False)
                    queued_upload_path = Path(temporary.name)
                    with temporary:
                        temporary.write(content)
                    content = None
                origin = request.url_root
                scan_endpoint = request.path
                background_headers = {
                    "X-Scan-Job-ID": job_id,
                    "X-Background-Scan": background_scan_token,
                }
                if is_bot:
                    background_headers["Authorization"] = f"Bearer {app.config['LOGSCAN_API_KEY']}"
                background_values = {}
                if source_url:
                    background_values["source_url"] = source_url
                if uploaded_by:
                    background_values["uploaded_by"] = uploaded_by
                if uploaded_by_id is not None:
                    background_values["uploaded_by_id"] = uploaded_by_id
                update_scan_job(job_id, "queued")

                def run_background_scan():
                    try:
                        with queued_upload_path.open("rb") as queued_upload:
                            background_form = {
                                **background_values,
                                "log": (queued_upload, upload_filename),
                            }
                            response = app.test_client().post(
                                scan_endpoint,
                                data=background_form,
                                content_type="multipart/form-data",
                                headers=background_headers,
                                base_url=origin,
                            )
                        if response.status_code >= 400:
                            payload = response.get_json(silent=True) or {}
                            update_scan_job(job_id, "failed", error=payload.get("error", "The scan could not be completed."))
                    except Exception:
                        app.logger.exception("Background scan %s failed", job_id)
                        update_scan_job(job_id, "failed", error="The scan could not be completed.")
                    finally:
                        queued_upload_path.unlink(missing_ok=True)

                background_scan_executor.submit(run_background_scan)
                return jsonify(job_id=job_id, phase="queued"), 202

            if not scan_slot.acquire(blocking=False):
                update_scan_job(job_id, "queued")
                scan_slot.acquire()
            update_scan_job(job_id, "scanning")
            try:
                scans = scan_archive_logs(upload_filename, content)
            finally:
                scan_slot.release()
            if not scans:
                filename, content = prepare_scan_input(upload_filename, content)
                scans = [(filename, content, scan_log(filename, content))]
        except ScanError as exc:
            analytics.record_rejection(rejection_category(str(exc)), "discord" if is_bot else "web")
            update_scan_job(job_id, "failed", error=str(exc))
            return jsonify(error=str(exc)), 400
        update_scan_job(job_id, "saving")
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
        archive_compressed_size = scan_content_size(content) if _is_archive_upload(upload_filename) else None
        archive_uncompressed_size = (
            sum(scan_content_size(scan_content) for _name, scan_content, _result in scans)
            if archive_compressed_size is not None else None
        )
        for filename, content, result in scans:
            if not app.config.get("TESTING"):
                try:
                    log_content = (
                        content.read_text(encoding="utf-8", errors="replace")
                        if isinstance(content, Path)
                        else content.decode("utf-8", errors="replace")
                    )
                    schema_failures = validate_config(log_content)
                    result.metadata["schema_validation_count"] = len(schema_failures)
                    result.metadata["schema_validation_branch"] = schema_branch_for_log(log_content)
                    result.metadata["schema_validation_failures"] = schema_failures
                    result.metadata["schema_directive_missing"] = not has_yaml_language_server_directive(log_content)
                    result.metadata["schema_validation_version"] = SCHEMA_VALIDATION_VERSION
                    result.metadata["counts"]["schema"] = len(schema_failures)
                except ValueError:
                    result.metadata["schema_validation_count"] = 0
                    result.metadata["schema_validation_branch"] = schema_branch_for_log(log_content)
                    result.metadata["counts"]["schema"] = 0
                except RuntimeError as exc:
                    result.metadata["schema_validation_count"] = 0
                    result.metadata["counts"]["schema"] = 0
                    app.logger.warning("Upload-time config validation unavailable for %s: %s", filename, exc)
            result.overview["upload_source"] = upload_source
            if uploaded_by:
                result.overview["uploaded_by"] = uploaded_by
                result.overview["uploaded_by_id"] = uploaded_by_id
                result.overview["message_url"] = source_url
            missing_candidates = result.missing_people
            repository_people = None
            if missing_candidates:
                repository_people = kometa_image_urls().get("Kometa Repo Image")
                if repository_people is not None:
                    people_tags = ["Missing Kometa"]
                    if uploaded_by:
                        people_tags.append(f"Requested by {uploaded_by}")
                    add_missing_people_recommendations(
                        result,
                        missing_candidates,
                        repository_people,
                        url_for("people_page", tags=people_tags, _external=True),
                    )
            _finalize_result_metrics(result, archive_compressed_size, archive_uncompressed_size)
            scan_id, delete_token = store.create(filename, content, result)
            if isinstance(content, Path) and content.name.startswith("logscan-"):
                content.unlink(missing_ok=True)
            result_url = url_for("result_page", scan_id=scan_id, _external=True)
            missing_people = save_missing_people(
                _people_needing_repository_images(missing_candidates, repository_people),
                filename=result.filename,
                log_url=result_url,
                source_url=source_url,
                uploaded_by=uploaded_by,
                uploaded_by_id=uploaded_by_id,
            )
            payloads.append({"id": scan_id, "filename": result.filename, "recommendations": result.recommendations, "metadata": result.metadata, "overview": result.overview, "categories": result.categories, "result_url": result_url, "delete_token": delete_token, "expires_at": expires_at, "uploaded_by_bot": is_bot, "missing_people": missing_people})
        submitted_people = [person for payload in payloads for person in payload["missing_people"]]
        submitted_count = sum(bool(person.get("is_new")) for person in submitted_people)
        processed_lines = sum(payload["metadata"].get("line_count", 0) for payload in payloads)
        analytics.record_success(
            logs=len(payloads),
            lines=processed_lines,
            bytes_processed=sum(result.metadata["size_bytes"] for _name, _content, result in scans),
            source="discord" if is_bot else "web",
            batch=len(payloads) > 1,
            versions=[normalized_kometa_version(payload["metadata"].get("kometa_version")) for payload in payloads],
            kometa_branches=[safe_branch(payload["metadata"].get("kometa_branch"), {"master", "develop", "nightly"}) for payload in payloads],
            launchers=["quickstart" if payload["metadata"].get("quickstart_run") else "direct" for payload in payloads],
            quickstart_versions=[
                normalized_quickstart_version(payload["metadata"].get("quickstart_version"))
                for payload in payloads if payload["metadata"].get("quickstart_run")
            ],
            quickstart_branches=[
                safe_branch(payload["metadata"].get("quickstart_branch"), {"master", "develop"})
                for payload in payloads if payload["metadata"].get("quickstart_run")
            ],
            kometa_platforms=[payload["metadata"].get("runtime_platform", "Unknown") for payload in payloads],
            installation_methods=[payload["metadata"].get("installation_method", "Unknown") for payload in payloads],
            quickstart_platforms=[
                payload["metadata"].get("runtime_platform", "Unknown")
                for payload in payloads if payload["metadata"].get("quickstart_run")
            ],
            plex={
                key: [
                    value for payload in payloads
                    for value in payload["overview"].get("plex_analytics", {}).get(key, [])
                ]
                for key in ("versions", "platforms", "update_channels", "library_types", "agents", "scanners")
            },
            recommendations=[item for payload in payloads for item in payload["recommendations"]],
            people=submitted_count,
        )
        notify_people_webhook(submitted_people)
        if len(payloads) > 1:
            batch_id, admin_token = store.create_batch(payloads, unscanned_files)
            response = {
                "scans": payloads,
                "batch_result_url": url_for("batch_page", batch_id=batch_id, _external=True),
                "batch_admin_url": url_for("batch_admin_page", batch_id=batch_id, token=admin_token, _external=True),
                "unscanned_files": unscanned_files,
            }
            if uploaded_by_id and not is_bot:
                update_scan_job(job_id, "complete", redirect_url=url_for("support.logs", view="mine"))
            else:
                update_scan_job(job_id, "complete", result=response)
            return jsonify(response)
        if request.path == "/api/bot/scan":
            response = {"scans": payloads}
            update_scan_job(job_id, "complete", result=response)
            return jsonify(response)
        if uploaded_by_id:
            update_scan_job(job_id, "complete", redirect_url=url_for("support.logs", view="mine"))
        else:
            update_scan_job(job_id, "complete", result=payloads[0])
        return jsonify({"scans": payloads}) if len(payloads) > 1 else jsonify(payloads[0])

    @app.get("/api/kometa-versions")
    def current_kometa_versions():
        now = time.time()
        with _kometa_version_lock:
            if _kometa_version_cache["expires_at"] <= now:
                versions = {}
                for branch in ("master", "develop"):
                    try:
                        version_url = KOMETA_VERSION_URL.format(branch=branch)
                        with urlopen(Request(version_url, headers={"User-Agent": "Kometa-Logscan/1.0"}), timeout=10) as response:
                            versions[branch] = response.read().decode("utf-8").strip()
                    except (HTTPError, URLError, TimeoutError, UnicodeDecodeError):
                        versions[branch] = None
                _kometa_version_cache.update({
                    "checked_at": datetime.now(UTC).isoformat(),
                    "expires_at": now + KOMETA_VERSION_CACHE_SECONDS,
                    "versions": versions,
                })
            return jsonify(
                checked_at=_kometa_version_cache["checked_at"],
                **_kometa_version_cache["versions"],
            )
    @app.get("/api/analytics")
    def usage_analytics():
        return jsonify(analytics.snapshot())

    @app.get("/api/people")
    def people():
        sources = selected_people_sources()
        page = request.args.get("page", default=1, type=int)
        per_page = request.args.get("per_page", default=POPULAR_PEOPLE_PAGE_SIZE, type=int)
        if per_page is None or not 1 <= per_page <= POPULAR_PEOPLE_PAGE_SIZE:
            return jsonify(error=f"Per-page count must be between 1 and {POPULAR_PEOPLE_PAGE_SIZE}."), 400
        tag_query = request.args.get("tag", "")
        selected_tags = request.args.getlist("tags")
        base_candidates = people_union(sources)
        available_tags = available_people_tags(base_candidates)
        candidates = filter_people_by_tag(base_candidates, tag_query)
        candidates = filter_people_by_selected_tags(candidates, selected_tags, available_tags)
        total_pages = max(1, (len(candidates) + per_page - 1) // per_page)
        if page is None or not 1 <= page <= total_pages:
            return jsonify(error=f"Page must be between 1 and {total_pages}."), 400
        first_index = (page - 1) * per_page
        return jsonify(
            people=candidates[first_index:first_index + per_page],
            page=page,
            total=len(candidates),
            total_pages=total_pages,
            per_page=per_page,
            sources=sorted(sources),
            actions_enabled=support_session_authorized(),
            tag=tag_query,
            selected_tags=selected_tags,
            available_tags=available_tags,
        )

    @app.get("/api/people/export")
    def export_people():
        base_candidates = people_union(selected_people_sources())
        available_tags = available_people_tags(base_candidates)
        candidates = filter_people_by_tag(base_candidates, request.args.get("tag", ""))
        candidates = filter_people_by_selected_tags(candidates, request.args.getlist("tags"), available_tags)
        export = "\n".join(
            f"{person['tmdb_id']}|{person.get('original_name', person['name'])}"
            for person in candidates
            if person.get("tmdb_id") and "Missing TMDb" not in person.get("metadata_tags", [])
        )
        return send_file(
            BytesIO(export.encode("utf-8")),
            mimetype="text/plain",
            as_attachment=True,
            download_name="people-to-process.txt",
        )

    def people_identity(person_key: str) -> tuple[int | None, dict | None]:
        record = people_store.get(person_key)
        match = re.fullmatch(r"tmdb-(\d+)", person_key)
        person_id = int(match.group(1)) if match else record.get("tmdb_id") if record else None
        if record is None and person_id:
            record = next((item for item in people_store.list() if item.get("tmdb_id") == person_id), None)
        return person_id, record

    def require_people_actions() -> None:
        if not support_session_authorized():
            abort(404)

    @app.post("/api/people/<person_key>/check")
    def check_person(person_key):
        require_people_actions()
        person_id, record = people_identity(person_key)
        if person_id:
            popular_people_checks.mark(person_id)
            popular_people_flags.delete(person_id)
        if record:
            people_store.delete(record["key"])
        clear_popular_people_payload_cache()
        return "", 204

    @app.post("/api/people/<person_key>/exclude")
    def exclude_person(person_key):
        require_people_actions()
        person_id, record = people_identity(person_key)
        if person_id:
            popular_people_exclusions.add(person_id)
        if record:
            people_store.delete(record["key"])
        clear_popular_people_payload_cache()
        return "", 204

    @app.post("/api/people/<person_key>/flag")
    def flag_person(person_key):
        require_people_actions()
        person_id, _record = people_identity(person_key)
        if not person_id:
            return jsonify(error="This person does not have a resolved TMDb ID."), 400
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

    @app.get("/api/scans/<scan_id>/log")
    def stored_log(scan_id):
        path = store.log_path(scan_id)
        if path is None:
            abort(404)
        if "start" in request.args:
            index = _stored_log_index(path)
            try:
                start = max(1, int(request.args.get("start", 1)))
                count = min(LOG_VIEW_MAX_LINES, max(1, int(request.args.get("count", 1000))))
            except ValueError:
                return jsonify(error="Invalid line range."), 400
            start = min(start, max(1, index["total"]))
            return jsonify(
                start=start,
                lines=_stored_log_lines(path, index, start, count),
                total=index["total"],
                sections=index["sections"],
                config=index["config"],
            )
        return send_file(path.resolve(), mimetype="text/plain; charset=utf-8", conditional=True)

    @app.post("/api/scans/<scan_id>/validate-config")
    def validate_stored_config(scan_id):
        record = store.get(scan_id)
        if record is None:
            abort(404)
        metadata = record.get("metadata") or {}
        cached_failures = metadata.get("schema_validation_failures")
        if (
            isinstance(cached_failures, list)
            and metadata.get("schema_validation_version") == SCHEMA_VALIDATION_VERSION
        ):
            return jsonify(
                branch=metadata.get("schema_validation_branch", "master"),
                failures=cached_failures,
                schema_directive_missing=bool(metadata.get("schema_directive_missing")),
            )
        path = store.log_path(scan_id)
        if path is None:
            abort(404)
        try:
            log_content = path.read_text(encoding="utf-8", errors="replace")
            failures = validate_config(log_content)
            branch = schema_branch_for_log(log_content)
            directive_missing = not has_yaml_language_server_directive(log_content)
            store.update_metadata(
                scan_id,
                schema_validation_count=len(failures),
                schema_validation_branch=branch,
                schema_validation_failures=failures,
                schema_directive_missing=directive_missing,
                schema_validation_version=SCHEMA_VALIDATION_VERSION,
            )
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        except RuntimeError as exc:
            app.logger.warning("Config validation failed: %s", exc)
            return jsonify(error=str(exc)), 502
        return jsonify(
            branch=branch,
            failures=failures,
            schema_directive_missing=directive_missing,
        )

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

    @app.errorhandler(400)
    def bad_request(error):
        if request.path.startswith("/api/"):
            return jsonify(error=getattr(error, "description", "The request is invalid.")), 400
        return error

    @app.errorhandler(404)
    def not_found(_error):
        if request.path.startswith("/api/"):
            return jsonify(error="The requested resource was not found."), 404
        return render_template("404.html"), 404

    @app.errorhandler(503)
    def service_unavailable(error):
        if request.path.startswith("/api/"):
            return jsonify(error=getattr(error, "description", "The service is unavailable.")), 503
        return render_template("503.html"), 503

    @app.errorhandler(500)
    def internal_server_error(error):
        update_scan_job(
            request.headers.get("X-Scan-Job-ID"),
            "failed",
            error="The Logscan service encountered an internal error. Check the service logs for details.",
        )
        if request.path.startswith("/api/"):
            return jsonify(error="The Logscan service encountered an internal error. Check the service logs for details."), 500
        return error

    @app.errorhandler(413)
    def too_large(_error):
        if request.path in {"/api/scan", "/api/bot/scan"}:
            analytics.record_rejection("too_large", "discord" if request.path == "/api/bot/scan" else "web")
        return jsonify(error="The selected file is larger than the 1 GB limit."), 413

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
