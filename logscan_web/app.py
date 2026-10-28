import hmac
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import tempfile
import unicodedata
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from functools import wraps
from io import BytesIO
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from flask import Flask, abort, jsonify, render_template, request, send_file, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from .models import Finding
from .people_images import (
    PEOPLE_IMAGE_STYLES,
    PeopleImageInventories,
    assess_people_images,
    parse_people_inventory,
    parse_people_readme,
    person_name_key as _person_name_key,
    tmdb_image_path,
)
from .config_optimizer import optimize_config
from .recommendations import SCHEMA_CACHE_SECONDS, has_yaml_language_server_directive, schema_branch_for_log, validate_redacted_config
from .scanner import (
    ARCHIVE_SUFFIXES,
    MAX_FILE_BYTES,
    ScanError,
    extract_quickstart_metadata,
    find_scannable_archive_logs,
    find_scannable_upload_path,
    is_supported_filename,
    prepare_scan_input,
    scan_archive_logs,
    scan_archive_path,
    scan_content_size,
    scan_log,
)
from .storage import (
    AnonymousAnalyticsStore,
    PeopleStore,
    PopularPeopleCacheStore,
    PopularPeopleCheckStore,
    PopularPeopleExclusionStore,
    PopularPeopleFlagStore,
    ScanStore,
    TMDbFindCacheStore,
    UsageStatsStore,
)
from .support import ACCOUNT_SESSION_SECONDS, create_support_blueprint, discord_session_user, support_role_refresh_required, support_session_authorized, support_session_role_hint

LOG_INDEX_STRIDE = 1000
LOG_VIEW_MAX_LINES = 2000
_log_index_cache = {}
_log_index_lock = threading.Lock()


def _format_bytes(value: int) -> str:
    size = float(max(0, value))
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if size < 1024 or unit == "PB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


def _download_filename_part(value: object, fallback: str, limit: int) -> str:
    normalized = unicodedata.normalize("NFKD", str(value or "")).encode("ascii", "ignore").decode("ascii")
    normalized = re.sub(r"\s+", "-", normalized.strip())
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", normalized)
    normalized = re.sub(r"-+", "-", normalized).strip(" .-_")
    return (normalized or fallback)[:limit].rstrip(" .-_") or fallback


def _download_artifact_names(record: dict) -> dict[str, str]:
    original_name = re.split(r"[\\/]", str(record.get("filename") or "kometa.log"))[-1]
    original_stem = Path(original_name).stem
    stem = _download_filename_part(original_stem, "kometa", 80)
    overview = record.get("overview") or {}
    source = str(overview.get("upload_source") or "web").casefold()
    source = source if source in {"discord", "web"} else "web"
    uploader = _download_filename_part(overview.get("uploaded_by"), "anonymous", 50)
    try:
        created = datetime.fromisoformat(str(record.get("created_at") or "").replace("Z", "+00:00"))
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        timestamp = created.astimezone(UTC).strftime("%Y%m%d-%H%M%SZ")
    except ValueError:
        timestamp = "unknown-time"
    base = f"{stem}--{source}-{uploader}--{timestamp}"
    return {
        "base": base,
        "log": f"{base}.log",
        "config": f"{base}-config.yml",
        "archive": f"{base}-files.zip",
    }


def _schema_directive_advice(metadata: dict) -> dict | None:
    if not metadata.get("schema_directive_missing"):
        return None
    branch = metadata.get("schema_validation_branch")
    if branch not in {"master", "develop"}:
        branch = "master" if metadata.get("kometa_branch") == "master" else "develop"
    schema_url = f"https://raw.githubusercontent.com/Kometa-Team/Kometa/refs/heads/{branch}/json-schema/config-schema.json"
    return {
        "id": "live_schema_directive_advice",
        "severity": "advice",
        "title": "Enable config.yml validation in VS Code",
        "message": (
            "Enable config.yml validation in VS Code\n"
            "Your config.yml does not include a YAML language-server schema directive, so supported editors cannot "
            "provide Kometa-aware validation and available-value suggestions while you edit.\n\n"
            "Proposed solution: Add this as the first line of your original config.yml:\n\n"
            f"`# yaml-language-server: $schema={schema_url}`\n\n"
            "The downloaded config from Logscan includes this line automatically."
        ),
        "evidence_lines": [],
    }


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
    result.metadata.update(
        {
            "archive_compressed_size": archive_compressed_size,
            "archive_uncompressed_size": archive_uncompressed_size,
            "archive_compression_ratio": ratio,
            "archive_reduction_percent": reduction,
        }
    )
    overview.update(
        {
            "archive_compressed_size_display": _format_bytes(archive_compressed_size),
            "archive_uncompressed_size_display": _format_bytes(archive_uncompressed_size),
            "archive_compression_ratio": f"{ratio:.2f}:1",
            "archive_reduction_percent": f"{reduction:.1f}%",
        }
    )


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
ANALYSIS_VERSION = 14
SCHEMA_VALIDATION_VERSION = 7
POPULAR_PEOPLE_PAGE_SIZE = 25
TMDB_POPULAR_PAGE_SIZE = 20
KOMETA_IMAGE_SOURCES = tuple((style.label, style.readme_url) for style in PEOPLE_IMAGE_STYLES)
KOMETA_IMAGE_CACHE_SECONDS = 60 * 60
KOMETA_IMAGE_RETRY_SECONDS = 5 * 60
POPULAR_PEOPLE_CACHE_SECONDS = 24 * 60 * 60
POPULAR_PEOPLE_LIMIT = 250
POPULAR_PEOPLE_CHECK_SECONDS = 30 * 24 * 60 * 60
AUTOMATED_TOP_PEOPLE_REQUESTER = {"name": "Automation", "id": "automation:top-250"}
AUTOMATED_TOP_PEOPLE_TAG = "Automated Top 250"
KOMETA_VERSION_CACHE_SECONDS = 60 * 60
KOMETA_VERSION_URL = "https://raw.githubusercontent.com/Kometa-Team/Kometa/{branch}/VERSION"


def _config_with_schema_directive(config: str, metadata: dict) -> str:
    branch = metadata.get("schema_validation_branch")
    if branch not in {"master", "develop"}:
        branch = "master" if metadata.get("kometa_branch") == "master" else "develop"
    if not re.search(r"^\s*#\s*yaml-language-server:\s*\$schema=", config, re.IGNORECASE | re.MULTILINE):
        schema_url = f"https://raw.githubusercontent.com/Kometa-Team/Kometa/refs/heads/{branch}/json-schema/config-schema.json"
        return f"# yaml-language-server: $schema={schema_url}\n{config}"
    return config


def _schema_validation_is_fresh(metadata: dict) -> bool:
    if metadata.get("schema_validation_version") != SCHEMA_VALIDATION_VERSION:
        return False
    try:
        validated_at = datetime.fromisoformat(metadata["schema_validation_checked_at"])
        if validated_at.tzinfo is None:
            validated_at = validated_at.replace(tzinfo=UTC)
    except (KeyError, TypeError, ValueError):
        return False
    age = datetime.now(UTC) - validated_at.astimezone(UTC)
    return timedelta(0) <= age < timedelta(seconds=SCHEMA_CACHE_SECONDS)


_kometa_version_cache = {"checked_at": None, "expires_at": 0.0, "versions": {}}
_kometa_version_lock = threading.Lock()
TMDB_FIND_CACHE_SECONDS = 7 * 24 * 60 * 60
TMDB_FIND_MAX_WORKERS = 8


def add_missing_people_recommendations(
    result,
    candidates: list[dict],
    repository_people: dict[str, dict[str, str]] | None,
    people_url: str | None = None,
) -> None:
    """Separate verified style gaps, operational failures and pending checks."""
    groups = {"incomplete": [], "complete": [], "pending_verification": []}
    grouped_people = {key: [] for key in groups}
    assessed = []
    for candidate in candidates:
        person = assess_people_images(candidate, repository_people)
        assessed.append(person)
        grouped_people[person["people_image_status"]].append(person)
        details = [person["name"]]
        if person.get("evidence_lines"):
            details.append("Log line number(s): " + ", ".join(str(number) for number in person["evidence_lines"]))
        if person.get("log_tmdb_image_line"):
            details.append(f"TMDb image observed at log line number(s): {person['log_tmdb_image_line']}")
        if person.get("source_styles"):
            source_repositories = [style.repository for style in PEOPLE_IMAGE_STYLES if style.key in person["source_styles"]]
            details.append("Detected failure: " + ", ".join(source_repositories))
        for status, label in (("missing", "Missing styles"), ("present", "Available styles"), ("unknown", "Unverified")):
            labels = [item["label"] for item in person["style_availability"].values() if item["status"] == status]
            if labels:
                details.append(f"{label}: {', '.join(labels)}")
        groups[person["people_image_status"]].append("\n".join(details))
    result.metadata["missing_people_verification"] = assessed

    def add_advice(identifier: str, title: str, description: str, solution: str, status: str) -> None:
        people = grouped_people[status]
        evidence = sorted({number for person in people for number in person.get("evidence_lines", [])})[:10_000]
        count = sum(person.get("occurrence_count", len(person.get("evidence_lines", []))) for person in people)
        result.recommendations.append(
            Finding(identifier, "advice", title, description, solution, tuple(evidence), occurrence_count=count or None, evidence_truncated=count > len(evidence)).as_dict()
        )

    if groups["complete"]:
        add_advice(
            "missing_people_images_available",
            "People posters are available in every supported style",
            "The logged poster failure remains a diagnostic finding; every applicable style is verified present.\n\n" + "\n\n".join(groups["complete"]),
            "Check the requested URL, Plex connectivity and permissions, then retry the poster update.",
            "complete",
        )
    if groups["incomplete"]:
        add_advice(
            "missing_people_images_pending",
            "Missing People Posters",
            "At least one applicable repository style is confirmed missing.\n\n" + "\n\n".join(groups["incomplete"]),
            "Wait for the missing style assets to be added, then rerun Kometa." + (f" Review the submitted people here: {people_url}" if people_url else ""),
            "incomplete",
        )
    if groups["pending_verification"]:
        failures = {}
        for person in grouped_people["pending_verification"]:
            for style in person["style_availability"].values():
                if style["status"] == "unknown":
                    failures.setdefault(style.get("reason", "Verification unavailable."), set()).add(style["label"])
        reasons = "\n".join(f"{reason} Styles: {', '.join(sorted(labels))}." for reason, labels in failures.items())
        add_advice(
            "missing_people_images_unverified",
            "People poster verification is pending",
            "Repository checks could not confirm completeness.\n" + reasons + "\n\n" + "\n\n".join(groups["pending_verification"]),
            "Open the People queue for current verification. Failed checks retry on the next refresh after five minutes." + (f" People queue: {people_url}" if people_url else ""),
            "pending_verification",
        )
    if candidates:
        result.recommendations.sort(key=lambda item: {"critical": 0, "error": 1, "warning": 2, "schema": 3, "advice": 4}[item["severity"]])
        result.metadata["counts"]["advice"] = sum(item["severity"] == "advice" for item in result.recommendations)
        result.overview["finding_count"] = len(result.recommendations)


def _people_needing_repository_images(candidates: list[dict], repository_people: dict[str, dict[str, str]] | None) -> list[dict]:
    """Retain gaps and inconclusive candidates until every style is present."""
    assessed = [assess_people_images(candidate, repository_people) for candidate in candidates]
    return [candidate for candidate in assessed if candidate["people_image_status"] != "complete"]


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
    app.config["DISCORD_BOT_TOKEN"] = os.environ.get("DISCORD_BOT_TOKEN", "")
    app.config["DISCORD_GUILD_ID"] = os.environ.get("DISCORD_GUILD_ID", "")
    app.config["DISCORD_SUPPORT_ROLE_IDS"] = {role.strip() for role in os.environ.get("DISCORD_SUPPORT_ROLE_IDS", "").split(",") if role.strip()}
    app.config["DISCORD_REDIRECT_URI"] = os.environ.get("DISCORD_REDIRECT_URI", "http://127.0.0.1:5000/support/callback")
    app.config["LOGSCAN_SECRET_KEY"] = os.environ.get("LOGSCAN_SECRET_KEY", "")
    app.secret_key = app.config["LOGSCAN_SECRET_KEY"] or secrets.token_bytes(32)
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=ACCOUNT_SESSION_SECONDS)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("LOGSCAN_SECURE_COOKIES", "false").casefold() in {"1", "true", "yes"}
    app.config["TMDB_API_KEY"] = os.environ.get("TMDB_API_KEY", "")
    app.config["GITHUB_TOKEN"] = os.environ.get("GITHUB_TOKEN", "")
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
    kometa_images_cache = {"expires_at": 0.0, "images": {}, "entries": {}}
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

    def validate_config(log_content: str | Path) -> list[dict]:
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
            for expired_id in [key for key, value in scan_jobs.items() if now - value.get("updated_at", now) > 3600]:
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
        except HTTPError as exc:
            if exc.code == 404:
                return {}
            app.logger.warning("TMDb lookup failed for %s", path)
            return None
        except (URLError, TimeoutError, ValueError):
            app.logger.warning("TMDb lookup failed for %s", path)
            return None

    def kometa_image_urls() -> dict[str, dict[str, str]]:
        """Map each image source to its case-insensitive person-name URLs."""
        with kometa_images_lock:
            if kometa_images_cache["expires_at"] > time.monotonic():
                return kometa_images_cache["images"]

            def fetch_partitioned_inventory(style, headers):
                # Large recursive trees can fail with HTTP 500. Read smaller,
                # immutable subtrees from one root snapshot instead.
                tree_url = style.inventory_url.split("?", 1)[0]

                def read_tree(url):
                    with urlopen(Request(url, headers=headers), timeout=10) as response:
                        if int(response.headers.get("Age", "0")) >= KOMETA_IMAGE_CACHE_SECONDS:
                            raise ValueError("Expired file inventory")
                        return json.loads(response.read().decode("utf-8"))

                root = read_tree(tree_url)
                if parse_people_inventory(style, root) is None:
                    return None
                directories = [entry for entry in root["tree"] if entry["type"] == "tree"]
                if any(not re.fullmatch(r"[0-9a-f]{40}", str(entry.get("sha", ""))) for entry in directories):
                    return None
                cached_directories = kometa_images_cache.setdefault("directories", {}).setdefault(style.label, {})
                current_paths = {entry["path"] for entry in directories}
                for path in list(cached_directories):
                    if path not in current_paths:
                        del cached_directories[path]

                def read_directory(entry):
                    subtree = cached_directories.get(entry["path"])
                    # A fresh root listing confirms unchanged immutable contents.
                    if subtree is None or subtree["sha"] != entry["sha"]:
                        try:
                            subtree = read_tree(f"{tree_url.rsplit('/', 1)[0]}/{entry['sha']}?recursive=1")
                        except (OSError, ValueError, HTTPException):
                            return None
                        if parse_people_inventory(style, subtree) is None or subtree["sha"] != entry["sha"]:
                            return None
                        cached_directories[entry["path"]] = subtree
                    return [{**child, "path": f"{entry['path']}/{child['path']}"} for child in subtree["tree"]]

                entries = list(root["tree"])
                complete = True
                with ThreadPoolExecutor(max_workers=4, thread_name_prefix="people-subtree") as executor:
                    for children in executor.map(read_directory, directories):
                        if children is None:
                            complete = False
                        else:
                            entries.extend(children)
                inventory = parse_people_inventory(style, {**root, "tree": entries})
                if inventory is not None:
                    inventory.complete = complete
                return inventory

            def fetch_inventory(style):
                failure = "GitHub returned an incomplete file inventory."
                partitioned = False
                headers = {"Accept": "application/vnd.github+json", "User-Agent": "Kometa-Logscan/1.0"}
                if app.config["GITHUB_TOKEN"]:
                    headers["Authorization"] = f"Bearer {app.config['GITHUB_TOKEN']}"
                try:
                    with urlopen(Request(style.inventory_url, headers=headers), timeout=10) as response:
                        if int(response.headers.get("Age", "0")) >= KOMETA_IMAGE_CACHE_SECONDS:
                            failure = "GitHub returned an expired file inventory."
                        else:
                            inventory = parse_people_inventory(style, json.loads(response.read().decode("utf-8")))
                            if inventory is not None:
                                return style.label, inventory, None
                            partitioned = True
                except HTTPError as exc:
                    partitioned = exc.code >= 500
                    failure = (
                        "GitHub rate limit reached."
                        if exc.code == 429 or (exc.headers or {}).get("X-RateLimit-Remaining") == "0"
                        else f"GitHub file inventory failed (HTTP {exc.code})."
                    )
                except (OSError, ValueError, HTTPException):
                    failure = "GitHub file inventory could not be reached."
                if partitioned:
                    try:
                        inventory = fetch_partitioned_inventory(style, headers)
                        if inventory is not None:
                            return style.label, inventory, None
                    except (OSError, ValueError, HTTPException):
                        pass
                    failure += " The directory file inventories could not be verified."
                # Generated indexes can lag behind syncs that skip README updates.
                # They supply image URLs, but cannot establish that a person is absent.
                try:
                    with urlopen(Request(style.readme_url, headers={"Accept": "text/plain", "User-Agent": "Kometa-Logscan/1.0"}), timeout=10) as response:
                        if int(response.headers.get("Age", "0")) >= KOMETA_IMAGE_CACHE_SECONDS:
                            index_failure = "The repository image index was expired."
                        else:
                            inventory = parse_people_readme(style, response.read().decode("utf-8"))
                            if inventory is not None:
                                return style.label, inventory, None
                            index_failure = "The repository image index was incomplete."
                except HTTPError as exc:
                    index_failure = f"The repository image index failed (HTTP {exc.code})."
                except (OSError, ValueError, HTTPException):
                    index_failure = "The repository image index could not be reached."
                failure += " " + index_failure
                app.logger.warning("Unable to verify %s: %s", style.label, failure)
                return style.label, None, failure

            entries = kometa_images_cache["entries"]
            stale = [style for style in PEOPLE_IMAGE_STYLES if entries.get(style.label, {}).get("expires_at", 0) <= time.monotonic()]
            with ThreadPoolExecutor(max_workers=4, thread_name_prefix="people-inventory") as executor:
                for label, inventory, error in executor.map(fetch_inventory, stale):
                    entries[label] = {
                        "inventory": inventory,
                        "error": error,
                        "expires_at": time.monotonic() + (KOMETA_IMAGE_CACHE_SECONDS if inventory is not None and inventory.complete else KOMETA_IMAGE_RETRY_SECONDS),
                    }
            images = PeopleImageInventories(
                {label: entry["inventory"] for label, entry in entries.items() if entry["inventory"] is not None},
                errors={label: entry["error"] for label, entry in entries.items() if entry["error"]},
            )
            kometa_images_cache.update(expires_at=min(entry["expires_at"] for entry in entries.values()), images=images)
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
            with urlopen(
                Request(
                    "https://caching.graphql.imdb.com/",
                    data=json.dumps({"query": query}).encode("utf-8"),
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Origin": "https://www.imdb.com",
                        "User-Agent": "Mozilla/5.0 (compatible; Kometa-Logscan/1.0)",
                        "x-imdb-client-name": "imdb-web-next-localized",
                    },
                ),
                timeout=15,
            ) as response:
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

    def record_automated_popular_requests(people: list[dict]) -> int:
        images = kometa_image_urls()
        if not images:
            app.logger.warning("Automated Top 250 requests skipped; people-image sources are unavailable.")
            return 0
        created = 0
        for person in _filtered_popular_people(people):
            person_id = person.get("id")
            name = person.get("name", "Unknown person")
            assessment = assess_people_images({"name": name}, images)
            if not person_id or not _has_current_tmdb_image(person) or assessment["people_image_status"] != "incomplete":
                continue
            _record, is_new = people_store.upsert_with_status(
                {
                    "key": f"tmdb-{person_id}",
                    "name": name,
                    "original_name": name,
                    "tmdb_id": person_id,
                    "tmdb_image_found": True,
                    "requested_by": [AUTOMATED_TOP_PEOPLE_REQUESTER],
                    "provenance_tags": [AUTOMATED_TOP_PEOPLE_TAG],
                    "style_availability": assessment["style_availability"],
                    "people_image_status": assessment["people_image_status"],
                }
            )
            created += int(is_new)
        if created:
            analytics.record_people_submitted(created)
        return created

    def _refresh_popular_people() -> None:
        nonlocal popular_people_refreshing
        try:
            people = _build_popular_people()
            if people:
                created = record_automated_popular_requests(people)
                snapshot = popular_people_store.save(people)
                _install_popular_people_snapshot(snapshot)
                with popular_people_payload_lock:
                    popular_people_payload_cache.clear()
                if created:
                    app.logger.info("Recorded %d automated Top 250 people request(s).", created)
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
            record = person.get("missing_record", {})
            current_path = tmdb_image_path("https://image.tmdb.org/t/p/original" + str(person.get("profile_path") or ""))
            saved_path = tmdb_image_path("https://image.tmdb.org/t/p/original" + str(record.get("tmdb_profile_path") or ""))
            log_path = tmdb_image_path("https://image.tmdb.org/t/p/original" + str(record.get("log_tmdb_image_path") or ""))
            profile_path = current_path or saved_path or log_path
            image_source = "current" if current_path else "saved" if saved_path else "log" if log_path else None
            image_status = (
                "available"
                if profile_path
                else "known_available" if record.get("tmdb_image_found") else "missing" if person.get("_tmdb_profile_checked", "profile_path" in person) else "unknown"
            )
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
            variant_images = [{"label": label, "url": urls[name_key]} for label, urls in kometa_images.items() if label != "Kometa Repo Image" and name_key in urls]
            payload.append(
                {
                    "tmdb_id": person_id,
                    "name": name,
                    "tmdb_person_url": f"https://www.themoviedb.org/person/{person_id}" if person_id else None,
                    "tmdb_images_url": f"https://www.themoviedb.org/person/{person_id}/images/profiles" if person_id else None,
                    "imdb_person_url": f"https://www.imdb.com/name/{person['imdb_id']}/" if person.get("imdb_id") else None,
                    "tmdb_image_url": f"https://image.tmdb.org/t/p/original{profile_path}" if profile_path else None,
                    "tmdb_image_source": image_source,
                    "tmdb_image_status": image_status,
                    "known_for_department": person.get("known_for_department"),
                    "known_for": known_for,
                    "tmdb_image": (
                        {
                            "preview_url": f"https://image.tmdb.org/t/p/w342{profile_path}",
                            "download_url": url_for("download_tmdb_image", image_path=profile_path, name=name),
                        }
                        if profile_path
                        else None
                    ),
                    "kometa_image": repo_image,
                    "kometa_variant_images": variant_images,
                    **{key: value for key, value in assess_people_images(person, kometa_images).items() if key in {"style_availability", "people_image_status"}},
                    "flag_reason": flags.get(person_id, {}).get("reason") if person_id else None,
                }
            )
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
        requesters = [f"Requested by {requester['name']}" for requester in person.get("requested_by", []) if requester.get("name")]
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
            for (category, tag), count in sorted(counts.items(), key=lambda item: (category_order[item[0][0]], item[0][1].casefold()))
        ]

    def filter_people_by_tag(people: list[dict], query: str) -> list[dict]:
        """Filter source and requester tags with case-insensitive * and ? wildcards."""
        query = query.strip().casefold()
        if not query:
            return people
        wildcarded = "*" in query or "?" in query
        expression = re.escape(query).replace(r"\*", ".*").replace(r"\?", ".")
        pattern = re.compile(f"^{expression}$" if wildcarded else f".*{expression}.*")
        return [person for person in people if any(pattern.fullmatch(tag.casefold()) for tag in searchable_people_tags(person))]

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
            return all(selected_tags & {tag.casefold() for tag in groups.get(category, [])} for category, selected_tags in selected_by_category.items())

        return [person for person in people if matches(person)]

    def people_union(sources: set[str]) -> list[dict]:
        """Return missing-log and trending people, keyed by TMDb ID."""
        inventories = kometa_image_urls()
        combined: dict[str, dict] = {}
        excluded_ids = popular_people_exclusions.list()
        checked_ids = popular_people_checks.active_ids(POPULAR_PEOPLE_CHECK_SECONDS)
        manually_completed_ids = {record.get("tmdb_id") for record in people_store.list() if record.get("manually_completed")}

        if sources & {"missing", "trending"} and app.config["TMDB_API_KEY"]:
            for person in popular_people():
                if not _has_current_tmdb_image(person):
                    continue
                missing_image = person["id"] not in manually_completed_ids and assess_people_images(person, inventories)["people_image_status"] == "incomplete"
                if "trending" not in sources and not missing_image:
                    continue
                person_sources = {"trending"}
                if missing_image:
                    person_sources.add("missing")
                combined[f"tmdb-{person['id']}"] = {**person, "sources": person_sources}

        if "missing" in sources:
            trending_by_name: dict[str, list[dict]] = {}
            addressed_records = []
            for person in combined.values():
                trending_by_name.setdefault(_person_name_key(person.get("name")), []).append(person)
            # A cold trending refresh can create automated requests above.
            for record in people_store.reconcile_image_availability(inventories):
                if record["people_image_status"] == "complete":
                    addressed_records.append(record)
                    continue
                if record.get("manually_completed") or record.get("tmdb_id") in excluded_ids or record.get("tmdb_id") in checked_ids:
                    continue
                person_id = record.get("tmdb_id")
                if not person_id and not record.get("identity_ambiguous"):
                    matches = trending_by_name.get(_person_name_key(record.get("name")), [])
                    person_id = matches[0].get("id") if len(matches) == 1 else None
                key = f"tmdb-{person_id}" if person_id else record["key"]
                person = combined.get(key)
                if person is None:
                    details = tmdb_get(f"/person/{person_id}") if person_id else None
                    person = {
                        **(details or {}),
                        "id": person_id,
                        "name": (details or {}).get("name", record["name"]),
                        "_tmdb_profile_checked": details is not None,
                        "sources": set(),
                    }
                    combined[key] = person
                person["sources"].add("missing")
                person["missing_record"] = record
            if addressed_records:
                analytics.record_addressed(addressed_records)

        people = list(combined.values())
        flags = popular_people_flags.list()
        people.sort(
            key=lambda person: (
                0 if "missing" in person["sources"] else 1,
                person.get("starmeter_rank", POPULAR_PEOPLE_LIMIT + 1),
                person.get("name", "").casefold(),
            )
        )
        payload = popular_people_payload(people, flags)
        for item, person in zip(payload, people):
            record = person.get("missing_record", {})
            sources = sorted(person["sources"])
            metadata_tags = []
            tmdb_ready = (bool(item.get("tmdb_image")) or bool(record.get("tmdb_image_found"))) and item["people_image_status"] == "incomplete"
            if "missing" in sources:
                metadata_tags.append("TMDb Ready" if tmdb_ready else "Missing TMDb" if item["tmdb_image_status"] == "missing" else "TMDb verification pending")
            requesters = record.get("requested_by", [])
            if record and not requesters:
                requesters = [{"name": "Unknown", "id": None}]
            item.update(
                person_key=f"tmdb-{person['id']}" if person.get("id") else record.get("key"),
                sources=sources,
                metadata_tags=metadata_tags,
                provenance_tags=list(record.get("provenance_tags", ["Log Upload"] if record else []))
                + [f"Manually Added by {entry['name']}" for entry in record.get("manual_requests", []) if entry.get("id") and entry.get("name")],
                log_url=record.get("log_url"),
                source_url=record.get("source_url"),
                original_name=record.get("original_name", record.get("name", item["name"])),
                requested_by=requesters,
                log_evidence_lines=record.get("log_evidence_lines", []),
                source_styles=record.get("source_styles", []),
                detection_reasons=record.get("detection_reasons", []),
                **{key: record[key] for key in ("style_availability", "people_image_status") if key in record},
            )
        return payload

    def save_missing_people(
        candidates: list[dict],
        *,
        filename: str,
        log_url: str,
        source_url: str | None,
        uploaded_by: str | None = None,
        uploaded_by_id: str | None = None,
        historical: bool = False,
    ) -> list[dict]:
        saved = []
        existing_by_name: dict[str, dict | None] = {}
        for record in people_store.list():
            for field in ("name", "original_name"):
                if record.get(field):
                    name_key = _person_name_key(record[field])
                    if name_key not in existing_by_name:
                        existing_by_name[name_key] = record
                    elif (existing_by_name[name_key] or {}).get("key") != record["key"]:
                        existing_by_name[name_key] = None
        excluded_ids = popular_people_exclusions.list()
        checked_ids = popular_people_checks.active_ids(POPULAR_PEOPLE_CHECK_SECONDS)
        for candidate in candidates:
            name = candidate["name"]
            existing = existing_by_name.get(_person_name_key(name))
            log_image_path = candidate.get("log_tmdb_image_path")
            if existing and existing.get("manually_completed"):
                continue
            if existing and existing.get("tmdb_id"):
                match = {"id": existing["tmdb_id"], "name": existing["name"]}
                identity_ambiguous = False
            else:
                match_data = tmdb_get("/search/person", {"query": name})
                matches = (match_data or {}).get("results", [])
                exact = [item for item in matches if _person_name_key(item.get("name")) == _person_name_key(name)]
                match = exact[0] if len(exact) == 1 else None
                if match is None and log_image_path:
                    photo_matches = [item for item in exact if item.get("profile_path") == log_image_path]
                    match = photo_matches[0] if len(photo_matches) == 1 else None
                identity_ambiguous = bool(matches) and match is None
            tmdb_id = match.get("id") if match else None
            if tmdb_id in excluded_ids or tmdb_id in checked_ids:
                continue
            api_image_path = (match or {}).get("profile_path")
            if not api_image_path and tmdb_id and not log_image_path and (not existing or not existing.get("tmdb_id")):
                image_data = tmdb_get(f"/person/{tmdb_id}/images")
                api_image_path = next(
                    (
                        image["file_path"]
                        for image in (image_data or {}).get("profiles", [])
                        if tmdb_image_path("https://image.tmdb.org/t/p/original" + str(image.get("file_path") or ""))
                    ),
                    None,
                )
            tmdb_image_found = bool(api_image_path or log_image_path or candidate.get("tmdb_image_found")) or bool((existing or {}).get("tmdb_image_found"))
            key_seed = str(tmdb_id) if tmdb_id else _person_name_key(name)
            key = f"tmdb-{tmdb_id}" if tmdb_id else f"name-{hashlib.sha256(key_seed.encode()).hexdigest()[:16]}"
            person, is_new = people_store.upsert_with_status(
                {
                    "key": key,
                    "name": match.get("name", name) if match else name,
                    "original_name": name,
                    "tmdb_id": tmdb_id,
                    "identity_ambiguous": identity_ambiguous,
                    "tmdb_image_found": tmdb_image_found,
                    "tmdb_profile_path": api_image_path,
                    "log_tmdb_image_path": log_image_path,
                    "log_tmdb_image_line": candidate.get("log_tmdb_image_line"),
                    "log_evidence_lines": candidate.get("evidence_lines", []),
                    "log_tmdb_image_found": bool(candidate["tmdb_image_found"]),
                    "log_name": filename,
                    "log_url": log_url,
                    "source_url": source_url,
                    "requested_by": [{"name": uploaded_by, "id": uploaded_by_id}] if uploaded_by else [],
                    "provenance_tags": ["Log Upload"],
                    "source_styles": candidate.get("source_styles", []),
                    "detection_reasons": candidate.get("detection_reasons", []),
                    "style_availability": candidate.get("style_availability", {}),
                    "people_image_status": candidate.get("people_image_status", "pending_verification"),
                    "log_provenance": [
                        {
                            "log_url": log_url,
                            "source_url": source_url,
                            "filename": filename,
                            "evidence_lines": candidate.get("evidence_lines", []),
                            "tmdb_image_line": candidate.get("log_tmdb_image_line"),
                        }
                    ],
                }
            )
            existing_by_name[_person_name_key(name)] = person
            person["people_url"] = "/people?tags=Missing+Kometa" if historical else url_for("people_page", tags="Missing Kometa", _external=True)
            person["is_new"] = is_new
            saved.append(person)
        return saved

    def notify_people_webhook(people: list[dict]) -> None:
        """Notify Discord when the website creates a new people-backlog entry."""
        webhook_url = app.config["DISCORD_PEOPLE_WEBHOOK_URL"]
        if not webhook_url:
            app.logger.info("Missing-person webhook is not configured; no website notification sent.")
            return
        new_people = [person for person in people if person.get("is_new") and person.get("people_image_status") == "incomplete"]
        for person in people:
            if not person.get("is_new"):
                app.logger.info("Missing-person webhook skipped for existing person: %s", person["name"])
        if not new_people:
            return
        first = new_people[0]
        if len(new_people) > 2:
            names = "\n".join(f"- {person['name']}" for person in new_people)
            people_summary = f"**People:**\n{names}\n" f"[Review all missing people images]({url_for('people_page', _external=True)})"
        else:
            names = "\n".join(
                f"- [{person['name']}]({person['people_url']}) — **TMDb Image Found:** " f"{'Yes' if person.get('tmdb_image_found') else 'No'}" for person in new_people
            )
            people_summary = f"**People:**\n{names}"
        source_line = f"**Log Source:** [Click Here]({first['source_url']})\n" if first.get("source_url") else "**Log Source:** Not available\n"
        message = f"**Log Name:** `{first['log_name']}`\n" f"**Log URL:** [Click Here]({first['log_url']})\n" f"{source_line}" f"{people_summary}"
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
            record
            for record in store.list()
            if (record.get("metadata") or {}).get("tool_name", "kometa") == "kometa" and not _schema_validation_is_fresh(record.get("metadata") or {})
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
                log_content = path
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
                schema_validation_checked_at=datetime.now(UTC).isoformat(),
            )
            completed += 1
            time.sleep(0.5)
        app.logger.info("Backfilled schema validation counts for %d of %d retained scan(s).", completed, len(records))

    def backfill_scan_analysis():
        records = [record for record in store.list() if (record.get("metadata") or {}).get("analysis_version") != ANALYSIS_VERSION]
        if not records:
            return
        app.logger.info("Reprocessing %d retained scan(s) with analysis version %d.", len(records), ANALYSIS_VERSION)
        completed = 0
        for record in records:
            scan_id = record.get("id", "")
            path = store.log_path(scan_id)
            if path is None:
                continue
            try:
                scans = scan_archive_path(record.get("filename") or "kometa.log", path)
                if len(scans) != 1:
                    raise ScanError("A retained scan must contain exactly one extracted log.")
                _filename, _content, result = scans[0]
            except (OSError, ScanError) as exc:
                app.logger.warning("Retained scan reprocessing failed for %s: %s", scan_id, exc)
                continue

            previous_metadata = record.get("metadata") or {}
            for key in (
                "archive_compressed_size",
                "archive_uncompressed_size",
                "archive_compression_ratio",
                "archive_reduction_percent",
                "schema_validation_count",
                "schema_validation_branch",
                "schema_directive_missing",
                "schema_validation_failures",
                "schema_validation_version",
                "schema_validation_checked_at",
            ):
                if key in previous_metadata:
                    result.metadata[key] = previous_metadata[key]
            result.metadata["analysis_version"] = ANALYSIS_VERSION

            previous_overview = record.get("overview") or {}
            for key in ("upload_source", "uploaded_by", "uploaded_by_id", "message_url"):
                if key in previous_overview:
                    result.overview[key] = previous_overview[key]

            if result.missing_people:
                inventories = kometa_image_urls()
                add_missing_people_recommendations(result, result.missing_people, inventories, "/people?tags=Missing+Kometa")
                save_missing_people(
                    _people_needing_repository_images(result.missing_people, inventories),
                    filename=result.filename,
                    log_url=f"/scan/{scan_id}",
                    source_url=previous_overview.get("message_url"),
                    uploaded_by=previous_overview.get("uploaded_by"),
                    uploaded_by_id=previous_overview.get("uploaded_by_id"),
                    historical=True,
                )
            result.recommendations.sort(key=lambda item: {"critical": 0, "error": 1, "warning": 2, "schema": 3, "advice": 4}[item["severity"]])
            _finalize_result_metrics(
                result,
                previous_metadata.get("archive_compressed_size"),
                previous_metadata.get("archive_uncompressed_size"),
            )
            if store.replace_analysis(scan_id, result):
                completed += 1
        app.logger.info("Reprocessed %d of %d retained scan(s).", completed, len(records))

    app.extensions["backfill_scan_analysis"] = backfill_scan_analysis

    def backfill_quickstart_metadata():
        records = [record for record in store.list() if "quickstart_run" not in (record.get("metadata") or {})]
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
                launcher_metadata = extract_quickstart_metadata(path.read_text(encoding="utf-8", errors="replace"))
            except OSError as exc:
                app.logger.warning("Quickstart metadata backfill failed for scan %s: %s", scan_id, exc)
                continue
            if store.update_metadata(scan_id, **launcher_metadata):
                completed += 1
        app.logger.info("Backfilled Quickstart metadata for %d of %d retained scan(s).", completed, len(records))

    def backfill_retained_scans():
        backfill_scan_analysis()
        backfill_schema_validation_counts()
        backfill_quickstart_metadata()

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
        threading.Thread(target=backfill_retained_scans, name="retained-scan-migration", daemon=True).start()

    @app.context_processor
    def service_usage():
        analytics_snapshot = analytics.snapshot()
        totals = analytics_snapshot["totals"]
        stats = {
            "logs_submitted": totals["successful_logs"],
            "kometa_logs_uploaded": totals["tools"].get("kometa", 0),
            "imagemaid_logs_uploaded": totals["tools"].get("imagemaid", 0),
            "lines_processed": totals["lines_processed"],
            "people_submitted": totals["people_submitted"],
            "people_addressed": totals["people_addressed"],
            "imagemaid_files_removed": totals["imagemaid_files_removed"],
            "imagemaid_space_recovered": _format_bytes(totals["imagemaid_bytes_recovered"]),
            "started_at": analytics_snapshot["started_at"],
        }
        try:
            started = datetime.fromisoformat(stats["started_at"])
            stats["tracking_since"] = started.strftime("%B %d, %Y").replace(" 0", " ")
        except (KeyError, TypeError, ValueError):
            stats["tracking_since"] = "tracking began"
        support_access = support_session_authorized()
        support_menu_access = support_access or support_session_role_hint()
        support_refresh_url = None
        if support_menu_access and support_role_refresh_required():
            support_refresh_url = url_for("support.authorize", next=url_for("support.logs", view="all"))
        return {
            "usage_stats": stats,
            "discord_user": discord_session_user(),
            "support_access": support_access,
            "support_menu_access": support_menu_access,
            "support_refresh_url": support_refresh_url,
        }

    @app.get("/")
    def index():
        return render_template("index.html", initial_scan=None, initial_batch=None)

    @app.get("/favicon.ico")
    def favicon():
        return send_file(Path(app.static_folder) / "logscan.png", mimetype="image/png")

    @app.get("/people")
    def people_page():
        session.setdefault("people_csrf", secrets.token_urlsafe(32))
        return render_template("people.html", people_csrf=session["people_csrf"])

    @app.get("/analytics")
    def analytics_page():
        return render_template("analytics.html")

    @app.get("/api/capabilities")
    def scan_capabilities():
        return jsonify(tools=["kometa", "imagemaid"], deduplication="content-sha256")

    @app.get("/scan/<scan_id>")
    def result_page(scan_id):
        record = store.get(scan_id)
        if record is None:
            abort(404)
        public = {key: value for key, value in record.items() if key not in {"delete_token_hash", "uploads", "content_sha256"}}
        metadata = dict(public.get("metadata") or {})
        public["metadata"] = metadata
        schema_count = metadata.get("schema_validation_count")
        if isinstance(schema_count, int):
            metadata.setdefault("counts", {})["schema"] = schema_count
        # Older retained scans may contain informational integrity advice.
        recommendations = [
            item for item in (public.get("recommendations") or []) if item.get("id") not in {"source_integrity_verified", "source_integrity_disabled", "plex_security_patched"}
        ]
        directive_advice = _schema_directive_advice(metadata)
        if directive_advice and not any(item.get("id") == directive_advice["id"] for item in recommendations):
            recommendations.append(directive_advice)
        public["recommendations"] = recommendations
        counts = {severity: sum(item.get("severity") == severity for item in recommendations) for severity in ("critical", "error", "warning", "schema", "advice")}
        if isinstance(schema_count, int):
            counts["schema"] = schema_count
        metadata["counts"] = counts
        overview = public.setdefault("overview", {})
        overview["finding_count"] = sum(counts.values())
        overview["line_count"] = int(metadata.get("line_count") or 0)
        overview["size_display"] = _format_bytes(int(metadata.get("size_bytes") or 0))
        compressed_size = int(metadata.get("archive_compressed_size") or 0)
        uncompressed_size = int(metadata.get("archive_uncompressed_size") or 0)
        if compressed_size and uncompressed_size:
            ratio = float(metadata.get("archive_compression_ratio") or (uncompressed_size / compressed_size))
            reduction = float(metadata.get("archive_reduction_percent") or ((1 - compressed_size / uncompressed_size) * 100))
            overview.update(
                {
                    "archive_compressed_size_display": _format_bytes(compressed_size),
                    "archive_uncompressed_size_display": _format_bytes(uncompressed_size),
                    "archive_compression_ratio": f"{ratio:.2f}:1",
                    "archive_reduction_percent": f"{reduction:.1f}%",
                }
            )
        public["expires_at"] = int(datetime.fromisoformat(record["created_at"]).timestamp() + RETENTION_SECONDS)
        return render_template("index.html", initial_scan=public, initial_batch=None)

    @app.get("/batch/<batch_id>")
    def batch_page(batch_id):
        batch = store.get_batch(batch_id)
        if batch is None:
            abort(404)
        public_url = url_for("batch_page", batch_id=batch_id, _external=True)
        public_scans = [
            {key: scan[key] for key in ("id", "filename", "result_url", "expires_at")} | {"batch_public_url": public_url, "unscanned_files": batch.get("unscanned_files", [])}
            for scan in batch["scans"]
        ]
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
            elif len(uploads) == 1 and is_background_scan:
                temporary = tempfile.NamedTemporaryFile(prefix="logscan-upload-", delete=False)
                content = Path(temporary.name)
                with temporary:
                    upload.save(temporary)
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
                scans = (
                    scan_archive_path(upload_filename, content)
                    if isinstance(content, Path) and (_is_archive_upload(upload_filename) or content.stat().st_size >= 64 * 1024 * 1024)
                    else scan_archive_logs(upload_filename, content.read_bytes() if isinstance(content, Path) else content)
                )
            finally:
                scan_slot.release()
            if not scans:
                if isinstance(content, Path):
                    raise ScanError("The archive does not contain a complete Kometa log file.")
                filename, content = prepare_scan_input(upload_filename, content)
                scans = [(filename, content, scan_log(filename, content))]
        except ScanError as exc:
            analytics.record_rejection(rejection_category(str(exc)), "discord" if is_bot else "web")
            update_scan_job(job_id, "failed", error=str(exc))
            return jsonify(error=str(exc)), 400
        update_scan_job(job_id, "saving")
        payloads = []
        unscanned_files = []
        if Path(upload_filename).suffix.lower() == ".zip":
            with zipfile.ZipFile(content if isinstance(content, Path) else BytesIO(content)) as archive:
                scanned_names = {filename for filename, _content, _result in scans}
                for entry in archive.infolist():
                    if entry.is_dir() or entry.filename in scanned_names:
                        continue
                    suffix = Path(entry.filename).suffix.lower()
                    if not is_supported_filename(entry.filename):
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
        archive_uncompressed_size = sum(scan_content_size(scan_content) for _name, scan_content, _result in scans) if archive_compressed_size is not None else None
        for filename, content, result in scans:
            result.metadata["analysis_version"] = ANALYSIS_VERSION
            if result.metadata.get("tool_name", "kometa") == "kometa" and not app.config.get("TESTING"):
                try:
                    log_content = content if isinstance(content, Path) else content.decode("utf-8", errors="replace")
                    schema_failures = validate_config(log_content)
                    result.metadata["schema_validation_count"] = len(schema_failures)
                    result.metadata["schema_validation_branch"] = schema_branch_for_log(log_content)
                    result.metadata["schema_validation_failures"] = schema_failures
                    result.metadata["schema_directive_missing"] = not has_yaml_language_server_directive(log_content)
                    result.metadata["schema_validation_version"] = SCHEMA_VALIDATION_VERSION
                    result.metadata["schema_validation_checked_at"] = datetime.now(UTC).isoformat()
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
                repository_people = kometa_image_urls()
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
            scan_id, delete_token, already_uploaded = store.create_or_reuse(filename, content, result, RETENTION_SECONDS)
            retained = store.get(scan_id)
            scan_expires_at = int(datetime.fromisoformat(retained["created_at"]).timestamp() + RETENTION_SECONDS)
            if isinstance(content, Path) and content.name.startswith("logscan-"):
                content.unlink(missing_ok=True)
            result_url = url_for("result_page", scan_id=scan_id, _external=True)
            missing_people = (
                []
                if already_uploaded
                else save_missing_people(
                    _people_needing_repository_images(missing_candidates, repository_people),
                    filename=result.filename,
                    log_url=result_url,
                    source_url=source_url,
                    uploaded_by=uploaded_by,
                    uploaded_by_id=uploaded_by_id,
                )
            )
            payloads.append(
                {
                    "id": scan_id,
                    "filename": result.filename,
                    "recommendations": result.recommendations,
                    "metadata": result.metadata,
                    "overview": result.overview,
                    "categories": result.categories,
                    "result_url": result_url,
                    "delete_token": delete_token,
                    "expires_at": scan_expires_at,
                    "already_uploaded": already_uploaded,
                    "uploaded_by_bot": is_bot,
                    "missing_people": missing_people,
                }
            )
        submitted_people = [person for payload in payloads for person in payload["missing_people"]]
        submitted_count = sum(bool(person.get("is_new")) for person in submitted_people)
        new_payloads = [payload for payload in payloads if not payload["already_uploaded"]]
        processed_lines = sum(payload["metadata"].get("line_count", 0) for payload in new_payloads)
        analytics.record_success(
            logs=len(new_payloads),
            lines=processed_lines,
            bytes_processed=sum(payload["metadata"]["size_bytes"] for payload in new_payloads),
            source="discord" if is_bot else "web",
            batch=len(payloads) > 1,
            versions=[
                normalized_kometa_version(payload["metadata"].get("kometa_version")) for payload in new_payloads if payload["metadata"].get("tool_name", "kometa") == "kometa"
            ],
            kometa_branches=[
                safe_branch(payload["metadata"].get("kometa_branch"), {"master", "develop", "nightly"})
                for payload in new_payloads
                if payload["metadata"].get("tool_name", "kometa") == "kometa"
            ],
            launchers=["quickstart" if payload["metadata"].get("quickstart_run") else "direct" for payload in new_payloads],
            quickstart_versions=[
                normalized_quickstart_version(payload["metadata"].get("quickstart_version")) for payload in new_payloads if payload["metadata"].get("quickstart_run")
            ],
            quickstart_branches=[
                safe_branch(payload["metadata"].get("quickstart_branch"), {"master", "develop"}) for payload in new_payloads if payload["metadata"].get("quickstart_run")
            ],
            kometa_platforms=[payload["metadata"].get("runtime_platform", "Unknown") for payload in new_payloads if payload["metadata"].get("tool_name", "kometa") == "kometa"],
            installation_methods=[
                payload["metadata"].get("installation_method", "Unknown") for payload in new_payloads if payload["metadata"].get("tool_name", "kometa") == "kometa"
            ],
            quickstart_platforms=[payload["metadata"].get("runtime_platform", "Unknown") for payload in new_payloads if payload["metadata"].get("quickstart_run")],
            tools=[payload["metadata"].get("tool_name", "kometa") for payload in new_payloads],
            imagemaid_versions=[
                normalized_kometa_version(payload["metadata"].get("imagemaid_version")) for payload in new_payloads if payload["metadata"].get("tool_name") == "imagemaid"
            ],
            imagemaid_modes=[
                safe_branch(payload["metadata"].get("imagemaid_mode"), {"report", "move", "restore", "remove", "clear"})
                for payload in new_payloads
                if payload["metadata"].get("tool_name") == "imagemaid"
            ],
            duplicates=sum(payload["already_uploaded"] for payload in payloads),
            imagemaid=[payload["metadata"] for payload in new_payloads if payload["metadata"].get("tool_name") == "imagemaid"],
            plex={
                key: [value for payload in new_payloads for value in payload["overview"].get("plex_analytics", {}).get(key, [])]
                for key in ("versions", "platforms", "update_channels", "library_types", "agents", "scanners")
            },
            recommendations=[item for payload in new_payloads for item in payload["recommendations"]],
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
                update_scan_job(job_id, "complete", redirect_url=response["batch_admin_url"])
            else:
                update_scan_job(job_id, "complete", result=response)
            return jsonify(response)
        if request.path == "/api/bot/scan":
            response = {"scans": payloads}
            update_scan_job(job_id, "complete", result=response)
            return jsonify(response)
        if uploaded_by_id:
            result_destination = f'{payloads[0]["result_url"]}#delete={payloads[0]["delete_token"]}'
            update_scan_job(job_id, "complete", redirect_url=result_destination)
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
                _kometa_version_cache.update(
                    {
                        "checked_at": datetime.now(UTC).isoformat(),
                        "expires_at": now + KOMETA_VERSION_CACHE_SECONDS,
                        "versions": versions,
                    }
                )
            return jsonify(
                checked_at=_kometa_version_cache["checked_at"],
                **_kometa_version_cache["versions"],
            )

    @app.get("/api/analytics")
    def usage_analytics():
        return jsonify(analytics.snapshot())

    def people_service_errors(view):
        @wraps(view)
        def guarded(*args, **kwargs):
            try:
                return view(*args, **kwargs)
            except (OSError, ValueError, sqlite3.Error):
                app.logger.warning("People search/request service is unavailable.")
                return jsonify(error="People service is unavailable. Please try again later."), 503

        return guarded

    def public_people_limit(action: str):
        user = discord_session_user()
        actor = f"discord:{user['id']}" if user else f"visitor:{request.remote_addr}"
        limit, window = (30, 60) if action == "search" else (30 if user else 10, 600)
        if not people_store.allow_lookup(actor, action, limit, window):
            return jsonify(error="Too many requests. Please try again shortly."), 429, {"Retry-After": str(window)}
        return None

    def valid_person_id(value) -> bool:
        return type(value) is int and 0 < value <= 2_147_483_647

    def verified_person(person_id: int, *, include_credits: bool = False) -> tuple[dict | None, int]:
        details = tmdb_get(f"/person/{person_id}", {"append_to_response": "combined_credits"} if include_credits else None)
        if details is None:
            return None, 503
        if (
            not isinstance(details, dict)
            or not valid_person_id(details.get("id"))
            or details["id"] != person_id
            or not valid_person_name(details.get("name"))
            or details.get("adult")
        ):
            return None, 404
        details["known_for"] = [credit for credit in (details.get("known_for") or [])[:3] if isinstance(credit, dict)]
        if include_credits and not details["known_for"]:
            credits = details.get("combined_credits") or {}
            roles = (credits.get("cast") or []) + (credits.get("crew") or []) if isinstance(credits, dict) else []
            seen = set()
            for credit in sorted(
                (item for item in roles if isinstance(item, dict)),
                key=lambda item: item.get("popularity") if isinstance(item.get("popularity"), (int, float)) else 0,
                reverse=True,
            ):
                identity = (credit.get("media_type"), credit.get("id"))
                if identity[0] not in {"movie", "tv"} or not valid_person_id(identity[1]) or identity in seen or not (credit.get("title") or credit.get("name")):
                    continue
                seen.add(identity)
                details["known_for"].append(credit)
                if len(details["known_for"]) == 3:
                    break
        # Verify fallback profiles just as uploaded-log discoveries do.
        if not tmdb_image_path("https://image.tmdb.org/t/p/original" + str(details.get("profile_path") or "")):
            details["profile_path"] = None
            images = tmdb_get(f"/person/{person_id}/images")
            details["_tmdb_profile_checked"] = isinstance(images, dict) and isinstance(images.get("profiles"), list)
            if isinstance(images, dict):
                details["profile_path"] = next(
                    (
                        image["file_path"]
                        for image in (images.get("profiles") or [])
                        if isinstance(image, dict) and tmdb_image_path("https://image.tmdb.org/t/p/original" + str(image.get("file_path") or ""))
                    ),
                    None,
                )
        return details, 200

    def valid_person_name(value) -> bool:
        return isinstance(value, str) and bool(value.strip()) and len(value) <= 200 and not any(unicodedata.category(char) in {"Cc", "Cs"} or char == "|" for char in value)

    def poster_search_payload(details: dict) -> dict:
        person = popular_people_payload([details], {})[0]
        record = next((item for item in people_store.list() if item.get("tmdb_id") == details["id"]), {})
        person["already_added"] = bool(record.get("manual_requests"))
        missing_styles = person["people_image_status"] == "incomplete"
        person["can_add"] = missing_styles and bool(person.get("tmdb_image"))
        person["sources"] = ["missing"] if missing_styles else []
        person["metadata_tags"] = ["TMDb Ready"] if person["can_add"] else []
        reason = None
        if person["people_image_status"] == "complete":
            reason = "All styles are available."
        elif not person.get("tmdb_image"):
            if person["tmdb_image_status"] == "missing":
                person["metadata_tags"] = ["Missing TMDb"]
                reason = "A verified TMDb profile image is required before requesting a poster."
            else:
                person["metadata_tags"] = ["TMDb verification pending"]
                reason = "TMDb image verification is unavailable. Please try again later."
        elif not missing_styles:
            reason = "Repository verification is unavailable. Please try again later."
        person["request_unavailable_reason"] = reason
        return person

    @app.get("/api/people/search")
    @people_service_errors
    def search_people_posters():
        query = request.args.get("q", "").strip()
        if not valid_person_name(query):
            return jsonify(error="Enter a name or TMDb person ID of up to 200 characters."), 400
        numeric = query.isdecimal()
        if numeric and (not query.isascii() or not valid_person_id(int(query))):
            return jsonify(error="Enter a valid numeric TMDb person ID."), 400
        limited = public_people_limit("search")
        if limited:
            return limited
        if numeric:
            details, status = verified_person(int(query), include_credits=True)
            if details is None:
                return jsonify(error="TMDb is unavailable. Please try again later." if status == 503 else "Person not found on TMDb."), status
            return jsonify(people=[poster_search_payload(details)])
        matches = tmdb_get("/search/person", {"query": query, "page": 1, "include_adult": "false"})
        if not isinstance(matches, dict) or not isinstance(matches.get("results"), list):
            return jsonify(error="TMDb search is unavailable. Please try again later."), 503
        # Offer identities before fetching galleries; never resolve ambiguity by name.
        choices = []
        seen = set()
        for item in matches["results"][:20]:
            if not isinstance(item, dict) or not valid_person_id(item.get("id")) or not valid_person_name(item.get("name")) or item.get("adult") or item["id"] in seen:
                continue
            seen.add(item["id"])
            profile_path = tmdb_image_path("https://image.tmdb.org/t/p/original" + str(item.get("profile_path") or ""))
            choices.append(
                {
                    "tmdb_id": item["id"],
                    "name": item["name"],
                    "profile_image_url": f"https://image.tmdb.org/t/p/w185{profile_path}" if profile_path else None,
                    "known_for_department": item.get("known_for_department"),
                    "known_for": [credit.get("title") or credit.get("name") for credit in (item.get("known_for") or [])[:3] if isinstance(credit, dict)],
                }
            )
        return jsonify(choices=choices)

    @app.post("/api/people/request")
    @people_service_errors
    def request_people_poster():
        token = session.get("people_csrf", "")
        if not token or not hmac.compare_digest(request.headers.get("X-CSRF-Token", "").encode(), token.encode()):
            return jsonify(error="Refresh the People page before adding a person."), 403
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) != {"tmdb_id"} or not valid_person_id(payload.get("tmdb_id")):
            return jsonify(error="Provide a valid TMDb person ID."), 400
        limited = public_people_limit("request")
        if limited:
            return limited
        existing = next((item for item in people_store.list() if item.get("tmdb_id") == payload["tmdb_id"]), {})
        if existing.get("manual_requests"):
            return jsonify(tmdb_id=payload["tmdb_id"], already_added=True, message="Already requested")
        details, status = verified_person(payload["tmdb_id"])
        if details is None:
            return jsonify(error="Unable to verify this person with TMDb. Please try again later."), status
        person = poster_search_payload(details)
        if not person["can_add"]:
            return jsonify(error=person["request_unavailable_reason"]), 409
        user = discord_session_user()
        timestamp = datetime.now(UTC).isoformat()
        manual_request = {"id": user["id"] if user else None, "name": user["username"] if user else None, "requested_at": timestamp}
        try:
            record, created = people_store.upsert_with_status(
                {
                    "key": f"tmdb-{details['id']}",
                    "tmdb_id": details["id"],
                    "name": details["name"],
                    "tmdb_profile_path": details.get("profile_path"),
                    "tmdb_image_found": True if details.get("profile_path") else None,
                    "manual_requests": [manual_request],
                    "provenance_tags": ["Manually Added"],
                    "requested_by": [{"id": user["id"], "name": user["username"]}] if user else [],
                    "style_availability": person["style_availability"],
                    "people_image_status": person["people_image_status"],
                },
                manual_request_once=True,
            )
        except (OSError, ValueError):
            app.logger.warning("Unable to persist manual People request.")
            return jsonify(error="Unable to save this request. Please try again later."), 503
        already_added = not any(entry.get("id") == manual_request["id"] and entry["requested_at"] == timestamp for entry in record["manual_requests"])
        if created:
            analytics.record_people_submitted(1)
        return jsonify(tmdb_id=details["id"], already_added=already_added, message="Already requested" if already_added else "Poster requested"), 200 if already_added else 201

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
            people=candidates[first_index : first_index + per_page],
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
            if person.get("tmdb_id") and not {"Missing TMDb", "TMDb verification pending"}.intersection(person.get("metadata_tags", []))
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
            people_store.upsert({"key": record["key"], "manually_completed": True})
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
        record = store.get(scan_id)
        download_name = _download_artifact_names(record or {})["log"]
        return send_file(
            path.resolve(),
            mimetype="text/plain; charset=utf-8",
            conditional=True,
            as_attachment=True,
            download_name=download_name,
        )

    @app.get("/api/scans/<scan_id>/download/<kind>")
    def download_stored_scan(scan_id, kind):
        if kind not in {"config", "both"}:
            abort(404)
        record = store.get(scan_id)
        path = store.log_path(scan_id)
        if record is None or path is None:
            abort(404)

        config = _stored_log_index(path)["config"]
        if not config:
            return jsonify(error="No redacted config block was found in this log."), 409

        config = _config_with_schema_directive(config, record.get("metadata") or {})

        names = _download_artifact_names(record)
        if kind == "config":
            return send_file(
                BytesIO(config.encode("utf-8")),
                mimetype="text/yaml; charset=utf-8",
                as_attachment=True,
                download_name=names["config"],
            )

        temporary = tempfile.NamedTemporaryFile(prefix="logscan-download-", suffix=".zip", delete=False)
        temporary_path = Path(temporary.name)
        temporary.close()
        try:
            with zipfile.ZipFile(temporary_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
                archive.write(path, arcname=names["log"])
                archive.writestr(names["config"], config)
            response = send_file(
                temporary_path,
                mimetype="application/zip",
                as_attachment=True,
                download_name=names["archive"],
            )
            response.call_on_close(lambda: temporary_path.unlink(missing_ok=True))
            return response
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise

    @app.post("/api/scans/<scan_id>/optimize-config")
    def optimize_stored_config(scan_id):
        record = store.get(scan_id)
        path = store.log_path(scan_id)
        if record is None or path is None:
            abort(404)
        try:
            config = _stored_log_index(path)["config"]
            if config:
                config = _config_with_schema_directive(config, record.get("metadata") or {})
            return jsonify(optimize_config(config))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400

    @app.post("/api/scans/<scan_id>/validate-config")
    def validate_stored_config(scan_id):
        record = store.get(scan_id)
        if record is None:
            abort(404)
        metadata = record.get("metadata") or {}
        if metadata.get("tool_name") == "imagemaid":
            return jsonify(error="Kometa schema validation does not apply to ImageMaid logs."), 409
        cached_failures = metadata.get("schema_validation_failures")
        if isinstance(cached_failures, list) and _schema_validation_is_fresh(metadata):
            return jsonify(
                branch=metadata.get("schema_validation_branch", "master"),
                failures=cached_failures,
                schema_directive_missing=bool(metadata.get("schema_directive_missing")),
            )
        path = store.log_path(scan_id)
        if path is None:
            abort(404)
        try:
            log_content = path
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
                schema_validation_checked_at=datetime.now(UTC).isoformat(),
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
