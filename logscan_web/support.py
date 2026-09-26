from __future__ import annotations

import json
import secrets
import time
from datetime import UTC, datetime, timedelta
from functools import wraps
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from flask import Blueprint, abort, current_app, redirect, render_template, request, session, url_for

DISCORD_API_URL = "https://discord.com/api/v10"
DISCORD_AUTHORIZE_URL = "https://discord.com/oauth2/authorize"
DISCORD_USER_AGENT = "Kometa-Logscan/1.0 (+https://github.com/Kometa-Team/Logscan)"
SESSION_MAX_AGE_SECONDS = 8 * 60 * 60
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

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not oauth_configured():
                missing = [key for key in SUPPORT_CONFIG_KEYS if not current_app.config.get(key)]
                current_app.logger.warning(
                    "Discord support access unavailable: missing configuration: %s",
                    ", ".join(missing),
                )
                abort(503, description="Support access is not configured.")
            if not session.get("support_user") or time.time() - session.get("support_authorized_at", 0) > SESSION_MAX_AGE_SECONDS:
                session.clear()
                return redirect(url_for("support.login", next=request.full_path.rstrip("?")))
            return view(*args, **kwargs)

        return wrapped

    @blueprint.get("/login")
    def login():
        if not oauth_configured():
            abort(503, description="Support access is not configured.")
        return render_template("support_login.html", error=request.args.get("error"), next=request.args.get("next", ""))

    @blueprint.get("/authorize")
    def authorize():
        if not oauth_configured():
            abort(503, description="Support access is not configured.")
        state = secrets.token_urlsafe(32)
        destination = request.args.get("next", "")
        session.clear()
        session["oauth_state"] = state
        session["oauth_next"] = destination if destination.startswith("/") and not destination.startswith("//") else url_for("support.logs")
        params = {
            "client_id": current_app.config["DISCORD_CLIENT_ID"],
            "redirect_uri": current_app.config["DISCORD_REDIRECT_URI"],
            "response_type": "code",
            "scope": "identify guilds.members.read",
            "state": state,
        }
        current_app.logger.warning("Discord support OAuth authorization started")
        return redirect(f"{DISCORD_AUTHORIZE_URL}?{urlencode(params)}")

    @blueprint.get("/callback")
    def callback():
        if not oauth_configured():
            abort(503, description="Support access is not configured.")
        expected_state = session.pop("oauth_state", None)
        if not expected_state or not secrets.compare_digest(request.args.get("state", ""), expected_state):
            current_app.logger.warning("Discord support OAuth rejected: invalid or expired state")
            abort(400, description="Discord sign-in state was invalid or expired.")
        code = request.args.get("code")
        if not code:
            current_app.logger.warning(
                "Discord support OAuth cancelled: %s",
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
        if not current_app.config["DISCORD_SUPPORT_ROLE_IDS"].intersection(member.get("roles", [])):
            current_app.logger.warning(
                "Discord support access denied: user_id=%s guild_id=%s configured_roles=%d member_roles=%d",
                user.get("id", "unknown"),
                current_app.config["DISCORD_GUILD_ID"],
                len(current_app.config["DISCORD_SUPPORT_ROLE_IDS"]),
                len(member.get("roles", [])),
            )
            session.clear()
            return render_template("support_login.html", error="Your Discord account does not have a configured support role.", next=""), 403
        destination = session.pop("oauth_next", url_for("support.logs"))
        session.clear()
        session["support_authorized_at"] = int(time.time())
        current_app.logger.warning(
            "Discord support access granted: user_id=%s guild_id=%s",
            user["id"],
            current_app.config["DISCORD_GUILD_ID"],
        )
        session["support_user"] = {
            "id": user["id"],
            "username": user.get("global_name") or user.get("username") or "Discord user",
            "avatar": _discord_avatar_url(user),
        }
        return redirect(destination)

    @blueprint.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("support.login"))

    @blueprint.get("/logs")
    @login_required
    def logs():
        query = request.args.get("q", "").strip()
        source_filter = request.args.get("source", "all").casefold()
        severity_filter = request.args.get("severity", "all").casefold()
        sort_key = request.args.get("sort", "created_at")
        direction = request.args.get("direction", "desc")
        try:
            page_size = min(100, max(10, int(request.args.get("page_size", 25))))
            page = max(1, int(request.args.get("page", 1)))
        except ValueError:
            page_size, page = 25, 1

        now = datetime.now(UTC)
        rows = [_support_row(record, retention_seconds, now) for record in store.list()]
        total_logs = len(rows)
        query_key = query.casefold()
        if query_key:
            rows = [row for row in rows if query_key in row["search_text"]]
        if source_filter in {"discord", "web"}:
            rows = [row for row in rows if row["source"] == source_filter]
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
        page_count = max(1, (filtered_logs + page_size - 1) // page_size)
        page = min(page, page_count)
        start = (page - 1) * page_size
        return render_template(
            "support_logs.html",
            rows=rows[start : start + page_size],
            total_logs=total_logs,
            filtered_logs=filtered_logs,
            page=page,
            page_count=page_count,
            page_size=page_size,
            query=query,
            source_filter=source_filter,
            severity_filter=severity_filter,
            sort_key=sort_key,
            direction=direction,
            support_user=session["support_user"],
        )

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


def _support_row(record: dict, retention_seconds: int, now: datetime) -> dict:
    metadata = record.get("metadata") or {}
    overview = record.get("overview") or {}
    recommendations = record.get("recommendations") or []
    counts = {
        severity: sum(item.get("severity") == severity for item in recommendations)
        for severity in ("critical", "error", "warning", "schema", "advice")
    }
    created = _parsed_datetime(record.get("created_at"))
    updated = _parsed_datetime(record.get("updated_at"), created)
    expires = created + timedelta(seconds=retention_seconds)
    uploader = overview.get("uploaded_by") or "Web upload"
    source = "discord" if overview.get("uploaded_by") or overview.get("message_url") else "web"
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
        "finding_count": len(recommendations),
        "counts": counts,
        "kometa_version": metadata.get("kometa_version") or "Unknown",
        "kometa_branch": metadata.get("kometa_branch") or "unknown",
        "platform": metadata.get("runtime_platform") or "Unknown",
        "installation": metadata.get("installation_method") or "Unknown",
        "complete": bool(metadata.get("complete")),
        "message_url": overview.get("message_url"),
    }
    row["search_text"] = " ".join(
        str(row[key]) for key in ("filename", "uploader", "uploader_id", "id", "kometa_version", "platform", "installation")
    ).casefold()
    return row
