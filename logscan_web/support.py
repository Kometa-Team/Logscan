from __future__ import annotations

import json
import re
import secrets
import time
from datetime import UTC, datetime, timedelta
from functools import wraps
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, session, url_for

DISCORD_API_URL = "https://discord.com/api/v10"
DISCORD_AUTHORIZE_URL = "https://discord.com/oauth2/authorize"
DISCORD_USER_AGENT = "Kometa-Logscan/1.0 (+https://github.com/Kometa-Team/Logscan)"
ACCOUNT_SESSION_SECONDS = 30 * 24 * 60 * 60
SUPPORT_ROLE_FALLBACK_SECONDS = 8 * 60 * 60


def discord_session_user() -> dict | None:
    """Return the fresh, verified Discord identity for the current session."""
    if time.time() - session.get("support_authorized_at", 0) > ACCOUNT_SESSION_SECONDS:
        return None
    return session.get("discord_user") or session.get("support_user")


def support_session_role_hint() -> bool:
    """Return the last verified role for navigation only, never authorization."""
    return bool(discord_session_user() and (session.get("support_access") or session.get("support_user")))


def support_role_refresh_required() -> bool:
    """Return whether a cached support member must repeat the OAuth role check."""
    if not support_session_role_hint() or current_app.config.get("DISCORD_BOT_TOKEN", ""):
        return False
    verified_at = session.get("support_role_verified_at", session.get("support_authorized_at", 0))
    return time.time() - verified_at > SUPPORT_ROLE_FALLBACK_SECONDS


def support_session_authorized() -> bool:
    """Return whether the current Discord member still has a support role."""
    user = discord_session_user()
    if not user:
        return False
    legacy_support_session = bool(session.get("support_user") and "support_access" not in session)
    if legacy_support_session:
        return True

    bot_token = current_app.config.get("DISCORD_BOT_TOKEN", "")
    if not bot_token:
        if not session.get("support_access"):
            return False
        verified_at = session.get("support_role_verified_at", session.get("support_authorized_at", 0))
        return time.time() - verified_at <= SUPPORT_ROLE_FALLBACK_SECONDS

    if hasattr(g, "discord_support_access"):
        return g.discord_support_access
    try:
        member = _discord_request(
            f"/guilds/{current_app.config['DISCORD_GUILD_ID']}/members/{user['id']}",
            headers={"Authorization": f"Bot {bot_token}"},
        )
        g.discord_support_access = bool(
            current_app.config["DISCORD_SUPPORT_ROLE_IDS"].intersection(member.get("roles", []))
        )
    except (HTTPError, URLError, KeyError, ValueError):
        current_app.logger.warning(
            "Discord support role revalidation failed; denying privileged access",
            exc_info=True,
        )
        g.discord_support_access = False
    return g.discord_support_access


SUPPORT_CONFIG_KEYS = (
    "DISCORD_CLIENT_ID",
    "DISCORD_CLIENT_SECRET",
    "DISCORD_GUILD_ID",
    "DISCORD_SUPPORT_ROLE_IDS",
    "LOGSCAN_SECRET_KEY",
)


def create_support_blueprint(store, retention_seconds: int) -> Blueprint:
    blueprint = Blueprint("support", __name__, url_prefix="/support")

    def oauth_configured() -> bool:
        return all(current_app.config.get(key) for key in SUPPORT_CONFIG_KEYS)

    def discord_login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not oauth_configured():
                missing = [key for key in SUPPORT_CONFIG_KEYS if not current_app.config.get(key)]
                current_app.logger.warning(
                    "Discord sign-in unavailable: missing configuration: %s",
                    ", ".join(missing),
                )
                abort(503, description="Discord sign-in is not configured.")
            if not discord_session_user():
                return redirect(url_for("support.login", next=request.full_path.rstrip("?")))
            return view(*args, **kwargs)

        return wrapped

    @blueprint.get("/login")
    def login():
        if not oauth_configured():
            abort(503, description="Discord sign-in is not configured.")
        return render_template("support_login.html", error=request.args.get("error"), next=request.args.get("next", ""))

    @blueprint.get("/authorize")
    def authorize():
        if not oauth_configured():
            abort(503, description="Discord sign-in is not configured.")
        state = secrets.token_urlsafe(32)
        destination = request.args.get("next", "")
        session.clear()
        session["oauth_state"] = state
        session["oauth_next"] = destination if destination.startswith("/") and not destination.startswith("//") else url_for("support.logs", view="mine")
        params = {
            "client_id": current_app.config["DISCORD_CLIENT_ID"],
            "redirect_uri": current_app.config["DISCORD_REDIRECT_URI"],
            "response_type": "code",
            "scope": "identify guilds.members.read",
            "state": state,
        }
        current_app.logger.warning("Discord OAuth authorization started")
        return redirect(f"{DISCORD_AUTHORIZE_URL}?{urlencode(params)}")

    @blueprint.get("/callback")
    def callback():
        if not oauth_configured():
            abort(503, description="Discord sign-in is not configured.")
        expected_state = session.pop("oauth_state", None)
        if not expected_state or not secrets.compare_digest(request.args.get("state", ""), expected_state):
            current_app.logger.warning("Discord OAuth rejected: invalid or expired state")
            abort(400, description="Discord sign-in state was invalid or expired.")
        code = request.args.get("code")
        if not code:
            current_app.logger.warning(
                "Discord OAuth cancelled: %s",
                request.args.get("error", "authorization code missing"),
            )
            return redirect(url_for("support.login", error="Discord sign-in was cancelled."))
        operation = "token exchange"
        try:
            token = _discord_token(code)
            operation = "user identity"
            user = _discord_get("/users/@me", token)
            operation = "guild membership"
            member = _discord_get(f"/users/@me/guilds/{current_app.config['DISCORD_GUILD_ID']}/member", token)
        except HTTPError as exc:
            current_app.logger.error(
                "Discord support authorization failed during %s: Discord HTTP %s: %s",
                operation,
                exc.code,
                _discord_http_error(exc),
            )
            return redirect(url_for("support.login", error="Discord could not verify your server membership."))
        except URLError as exc:
            current_app.logger.error(
                "Discord support authorization failed: Discord network error: %s",
                exc.reason,
            )
            return redirect(url_for("support.login", error="Discord could not verify your server membership."))
        except (KeyError, ValueError):
            current_app.logger.exception("Discord support authorization failed: invalid Discord response")
            return redirect(url_for("support.login", error="Discord could not verify your server membership."))
        support_access = bool(current_app.config["DISCORD_SUPPORT_ROLE_IDS"].intersection(member.get("roles", [])))
        destination = session.pop("oauth_next", url_for("support.logs", view="mine"))
        session.clear()
        session.permanent = True
        session["support_authorized_at"] = int(time.time())
        session["support_access"] = support_access
        session["support_role_verified_at"] = int(time.time())
        current_app.logger.warning(
            "Discord access granted: user_id=%s guild_id=%s support_access=%s",
            user["id"],
            current_app.config["DISCORD_GUILD_ID"],
            support_access,
        )
        session["discord_user"] = {
            "id": user["id"],
            "username": user.get("global_name") or user.get("username") or "Discord user",
            "avatar": _discord_avatar_url(user),
        }
        return redirect(destination)

    @blueprint.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @blueprint.get("/logs")
    @discord_login_required
    def logs():
        query = request.args.get("q", "").strip()
        source_filter = request.args.get("source", "all").casefold()
        launcher_filter = request.args.get("launcher", "all").casefold()
        branch_filter = request.args.get("branch", "all").casefold()
        severity_filter = request.args.get("severity", "all").casefold()
        sort_key = request.args.get("sort", "created_at")
        direction = request.args.get("direction", "desc")
        page_size_value = request.args.get("page_size", "25").casefold()
        try:
            page_size = (
                None
                if page_size_value == "all"
                else min(100, max(10, int(page_size_value)))
            )
            page = max(1, int(request.args.get("page", 1)))
        except ValueError:
            page_size, page = 25, 1

        now = datetime.now(UTC)
        user = discord_session_user()
        support_access = support_session_authorized()
        view_mode = "all" if request.args.get("view") == "all" and support_access else "mine"
        is_support_console = view_mode == "all"
        records = store.list()
        if not is_support_console:
            records = [
                record for record in records
                if str((record.get("overview") or {}).get("uploaded_by_id") or "") == str(user["id"])
            ]
        rows = [_support_row(record, retention_seconds, now) for record in records]
        total_logs = len(rows)
        query_key = query.casefold()
        if query_key:
            rows = [row for row in rows if query_key in row["search_text"]]
        if source_filter in {"discord", "web"}:
            rows = [row for row in rows if row["source"] == source_filter]
        if launcher_filter == "quickstart":
            rows = [row for row in rows if row["quickstart_run"]]
        elif launcher_filter == "direct":
            rows = [row for row in rows if not row["quickstart_run"]]
        else:
            launcher_filter = "all"
        if branch_filter in {"nightly", "develop", "master"}:
            rows = [row for row in rows if row["kometa_branch"].casefold() == branch_filter]
        else:
            branch_filter = "all"
        if severity_filter in {"critical", "error", "warning", "schema", "advice"}:
            rows = [row for row in rows if row["counts"][severity_filter] > 0]
        elif severity_filter == "none":
            rows = [row for row in rows if row["finding_count"] == 0]

        sorters = {
            "title": lambda row: row["filename"].casefold(),
            "uploader": lambda row: row["uploader"].casefold(),
            "source": lambda row: row["source"],
            "created_at": lambda row: row["created_at"],
            "updated_at": lambda row: row["updated_at"],
            "expires_at": lambda row: row["expires_at"],
            "size": lambda row: row["size_bytes"],
            "lines": lambda row: row["line_count"],
            "findings": lambda row: row["finding_count"],
            "version": lambda row: row["kometa_version"].casefold(),
        }
        if sort_key not in sorters:
            sort_key = "created_at"
        if direction not in {"asc", "desc"}:
            direction = "desc"
        rows.sort(key=sorters[sort_key], reverse=direction == "desc")

        filtered_logs = len(rows)
        page_count = (
            1
            if page_size is None
            else max(1, (filtered_logs + page_size - 1) // page_size)
        )
        page = min(page, page_count)
        start = 0 if page_size is None else (page - 1) * page_size
        visible_rows = rows if page_size is None else rows[start : start + page_size]
        return render_template(
            "support_logs.html",
            rows=visible_rows,
            total_logs=total_logs,
            filtered_logs=filtered_logs,
            page=page,
            page_count=page_count,
            page_size="all" if page_size is None else page_size,
            query=query,
            source_filter=source_filter,
            launcher_filter=launcher_filter,
            branch_filter=branch_filter,
            severity_filter=severity_filter,
            sort_key=sort_key,
            direction=direction,
            discord_user=user,
            support_access=support_access,
            is_support_console=is_support_console,
            view_mode=view_mode,
        )

    @blueprint.post("/logs/delete-selected")
    @discord_login_required
    def delete_selected_logs():
        payload = request.get_json(silent=True) or {}
        supplied_ids = payload.get("scan_ids")
        if not isinstance(supplied_ids, list):
            abort(400, description="Select one or more logs to delete.")
        scan_ids = list(dict.fromkeys(
            value.strip() for value in supplied_ids
            if isinstance(value, str) and value.strip()
        ))
        if not scan_ids or len(scan_ids) > 1000:
            abort(400, description="Select between 1 and 1,000 logs to delete.")

        user = discord_session_user()
        support_access = support_session_authorized()
        records = []
        for scan_id in scan_ids:
            record = store.get(scan_id)
            owns_log = str(((record or {}).get("overview") or {}).get("uploaded_by_id") or "") == str(user["id"])
            if record is None or (not support_access and not owns_log):
                abort(404)
            records.append((scan_id, record))

        deleted = sum(store.delete_authorized(scan_id) for scan_id, _record in records)
        current_app.logger.warning(
            "Stored logs bulk deleted: requested=%d deleted=%d user_id=%s support_access=%s",
            len(scan_ids),
            deleted,
            user.get("id", "unknown"),
            support_access,
        )
        return {"deleted": deleted}

    @blueprint.post("/logs/<scan_id>/delete")
    @discord_login_required
    def delete_log(scan_id):
        user = discord_session_user()
        record = store.get(scan_id)
        owns_log = str(((record or {}).get("overview") or {}).get("uploaded_by_id") or "") == str(user["id"])
        if not support_session_authorized() and not owns_log:
            abort(404)
        if not store.delete_authorized(scan_id):
            abort(404)
        current_app.logger.warning(
            "Stored log deleted: scan_id=%s user_id=%s",
            scan_id,
            user.get("id", "unknown"),
        )
        return redirect(url_for("support.logs", view="all" if request.args.get("view") == "all" and support_session_authorized() else "mine"))

    return blueprint


def _discord_token(code: str) -> str:
    data = urlencode({
        "client_id": current_app.config["DISCORD_CLIENT_ID"],
        "client_secret": current_app.config["DISCORD_CLIENT_SECRET"],
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": current_app.config["DISCORD_REDIRECT_URI"],
    }).encode()
    return _discord_request("/oauth2/token", data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})["access_token"]


def _discord_get(path: str, token: str) -> dict:
    return _discord_request(path, headers={"Authorization": f"Bearer {token}"})


def _discord_request(path: str, *, data: bytes | None = None, headers: dict | None = None) -> dict:
    url = path if path.startswith("http") else f"{DISCORD_API_URL}{path}"
    request_headers = {"User-Agent": DISCORD_USER_AGENT, **(headers or {})}
    with urlopen(Request(url, data=data, headers=request_headers), timeout=10) as response:
        return json.load(response)


def _discord_http_error(error: HTTPError) -> str:
    try:
        payload = json.loads(error.read(2048).decode("utf-8", errors="replace"))
        return str(payload.get("error_description") or payload.get("message") or payload.get("error") or "unknown error")
    except (json.JSONDecodeError, AttributeError):
        return "unknown error"


def _discord_avatar_url(user: dict) -> str:
    avatar = user.get("avatar")
    return f"https://cdn.discordapp.com/avatars/{user['id']}/{avatar}.png?size=64" if avatar else ""


def _parsed_datetime(value, fallback: datetime | None = None) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except (TypeError, ValueError):
        return fallback or datetime.fromtimestamp(0, UTC)


def _kometa_branch(metadata: dict) -> str:
    branch = str(metadata.get("kometa_branch") or "").casefold()
    if branch in {"nightly", "develop", "master"}:
        return branch
    version = str(metadata.get("kometa_version") or "")
    match = re.search(r"\b(?:docker|git):\s*(nightly|develop|master)\b", version, re.IGNORECASE)
    return match.group(1).casefold() if match else "unknown"


def _support_row(record: dict, retention_seconds: int, now: datetime) -> dict:
    metadata = record.get("metadata") or {}
    overview = record.get("overview") or {}
    recommendations = record.get("recommendations") or []
    counts = {
        severity: sum(item.get("severity") == severity for item in recommendations)
        for severity in ("critical", "error", "warning", "schema", "advice")
    }
    persisted_schema_count = metadata.get("schema_validation_count")
    schema_count_available = isinstance(persisted_schema_count, int)
    if schema_count_available:
        counts["schema"] = persisted_schema_count
    if metadata.get("schema_directive_missing") and not any(
        item.get("id") == "live_schema_directive_advice" for item in recommendations
    ):
        counts["advice"] += 1
    created = _parsed_datetime(record.get("created_at"))
    updated = _parsed_datetime(record.get("updated_at"), created)
    expires = created + timedelta(seconds=retention_seconds)
    uploader = overview.get("uploaded_by") or "Web upload"
    source = overview.get("upload_source") or ("discord" if overview.get("message_url") else "web")
    filename = record.get("filename") or "Untitled log"
    row = {
        "id": record.get("id", ""),
        "filename": filename,
        "uploader": uploader,
        "uploader_id": overview.get("uploaded_by_id"),
        "source": source,
        "created_at": created,
        "updated_at": updated,
        "expires_at": expires,
        "remaining_seconds": max(0, int((expires - now).total_seconds())),
        "size_bytes": int(metadata.get("size_bytes") or 0),
        "line_count": int(metadata.get("line_count") or 0),
        "archive_compressed_size": int(metadata.get("archive_compressed_size") or 0),
        "archive_uncompressed_size": int(metadata.get("archive_uncompressed_size") or 0),
        "archive_compression_ratio": float(metadata.get("archive_compression_ratio") or 0),
        "archive_reduction_percent": float(metadata.get("archive_reduction_percent") or 0),
        "finding_count": sum(counts.values()),
        "schema_count_available": schema_count_available,
        "counts": counts,
        "kometa_version": metadata.get("kometa_version") or "Unknown",
        "kometa_branch": _kometa_branch(metadata),
        "platform": metadata.get("runtime_platform") or "Unknown",
        "installation": metadata.get("installation_method") or "Unknown",
        "quickstart_run": bool(metadata.get("quickstart_run")),
        "quickstart_version": metadata.get("quickstart_version"),
        "quickstart_branch": metadata.get("quickstart_branch") or "unknown",
        "complete": bool(metadata.get("complete")),
        "message_url": overview.get("message_url"),
    }
    row["search_text"] = " ".join(
        str(row[key]) for key in (
            "filename", "uploader", "uploader_id", "id", "kometa_version", "platform",
            "kometa_branch", "installation", "quickstart_version", "quickstart_branch",
        )
    ).casefold()
    return row
