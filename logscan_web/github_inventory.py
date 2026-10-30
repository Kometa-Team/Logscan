"""Persistent conditional GitHub inventory requests with shared rate-limit backoff."""

import hashlib
import json
import math
import re
import threading
import time
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request


class InventoryResponse(BytesIO):
    def __init__(self, entry: dict):
        super().__init__(json.dumps(entry["body"]).encode("utf-8"))
        self.headers = {"Age": str(max(0, int(time.time() - entry["checked_at"])))}
        self.status = 200


class GitHubInventoryCache:
    def __init__(self, directory: Path, *, max_age: int = 3600):
        self.directory = directory
        self.max_age = max_age
        self.lock = threading.Lock()
        self.limit = self._read(directory / "rate-limit.json") or {}
        if any(not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 for value in self.limit.values()):
            self.limit = {}
        self.authentication = self._read(directory / "authentication.json") or {}
        if not isinstance(self.authentication.get("checked_at", 0), (int, float)) or not math.isfinite(self.authentication.get("checked_at", 0)):
            self.authentication = {}

    def authentication_status(self, configured):
        if not configured:
            return {"state": "missing", "expires_at": None}
        state = self.authentication.get("state", "unknown")
        expires_at = self.authentication.get("expires_at")
        if not isinstance(expires_at, (int, float)) or not math.isfinite(expires_at):
            expires_at = None
        if expires_at is not None and expires_at <= time.time():
            state = "expired"
        return {"state": state if state in {"valid", "rejected", "expired"} else "unknown", "expires_at": expires_at}

    def _authentication_result(self, state, headers):
        expires_at = self.authentication.get("expires_at")
        value = headers.get("GitHub-Authentication-Token-Expiration")
        if value:
            try:
                parsed = datetime.fromisoformat(value.strip().removesuffix(" UTC"))
                expires_at = (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).timestamp()
            except (TypeError, ValueError, OverflowError):
                pass
        self.authentication = {"state": state, "checked_at": time.time(), "expires_at": expires_at}
        self._write(self.directory / "authentication.json", self.authentication)

    @staticmethod
    def _read(path):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else None
        except (OSError, ValueError):
            return None

    def _write(self, path, value):
        # A read-only or full cache must not prevent an otherwise valid request.
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            temporary = path.with_suffix(".json.tmp")
            temporary.write_text(json.dumps(value), encoding="utf-8")
            temporary.replace(path)
        except OSError:
            pass

    def _backoff(self, headers):
        now = time.time()
        delay = min(3600, max(60, float(self.limit.get("backoff", 0)) * 2))
        deadlines = []
        retry_after = headers.get("Retry-After")
        if retry_after:
            try:
                deadlines.append(now + max(0, float(retry_after)))
            except ValueError:
                try:
                    parsed = parsedate_to_datetime(retry_after)
                    deadlines.append((parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).timestamp())
                except (TypeError, ValueError, OverflowError):
                    pass
        if headers.get("X-RateLimit-Remaining") == "0":
            try:
                deadlines.append(float(headers["X-RateLimit-Reset"]) + 1)
            except (KeyError, TypeError, ValueError):
                pass
        self.limit = {"retry_at": max([now + 1, *deadlines]) if deadlines else now + delay, "backoff": delay}
        self._write(self.directory / "rate-limit.json", self.limit)

    def open(self, request: Request, *, open_url, timeout=10):
        """Return a fresh response, reusing immutable trees and conditional GETs.

        Serialize API requests so one rate-limit response stops the other styles
        and directory lookups. Raw README and image requests remain independent.
        """
        with self.lock:
            url = request.full_url
            path = self.directory / (hashlib.sha256(url.encode("utf-8")).hexdigest() + ".json")
            # The caller already keeps parsed inventories in memory. Keep raw
            # trees on disk so large repositories are not retained twice.
            entry = self._read(path)
            if entry is not None and not (
                isinstance(entry.get("body"), dict)
                and isinstance(entry.get("checked_at"), (float, int))
                and math.isfinite(entry["checked_at"])
                and isinstance(entry.get("etag", ""), str)
                and isinstance(entry.get("last_modified", ""), str)
            ):
                entry = None
            now = time.time()
            authenticated = bool(request.get_header("Authorization"))
            immutable = re.search(r"/git/trees/([0-9a-f]{40})(?:\?|$)", url)
            if entry is not None and (
                0 <= now - entry["checked_at"] < self.max_age or (immutable and entry["body"].get("sha") == immutable[1] and entry["body"].get("truncated") is False)
            ):
                # Immutable subtree content never becomes stale at its SHA.
                if immutable:
                    entry = {**entry, "checked_at": now}
                return InventoryResponse(entry)
            authentication = self.authentication_status(authenticated)
            if authenticated and (authentication["state"] == "expired" or (authentication["state"] == "rejected" and now - float(self.authentication.get("checked_at", 0)) < 300)):
                raise HTTPError(url, 401, "GitHub token has expired or is invalid", {}, None)
            retry_at = float(self.limit.get("retry_at", 0))
            if retry_at > now:
                raise HTTPError(url, 429, "GitHub inventory requests paused until the rate limit resets", {"Retry-After": str(int(retry_at - now) + 1)}, None)
            headers = dict(request.header_items())
            if entry is not None:
                if entry.get("etag"):
                    headers["If-None-Match"] = entry["etag"]
                if entry.get("last_modified"):
                    headers["If-Modified-Since"] = entry["last_modified"]
            try:
                with open_url(Request(url, headers=headers), timeout=timeout) as response:
                    body = json.loads(response.read().decode("utf-8"))
                    if not isinstance(body, dict):
                        raise ValueError("Invalid GitHub inventory response")
                    result = {
                        "body": body,
                        "checked_at": now - max(0, int(response.headers.get("Age", "0"))),
                        "etag": response.headers.get("ETag", ""),
                        "last_modified": response.headers.get("Last-Modified", ""),
                    }
                    response_headers = response.headers
            except HTTPError as exc:
                response_headers = exc.headers or {}
                if authenticated and exc.code == 401:
                    self._authentication_result("rejected", response_headers)
                if exc.code == 304 and entry is not None:
                    result = {
                        **entry,
                        "checked_at": time.time(),
                        "etag": response_headers.get("ETag", entry.get("etag", "")),
                        "last_modified": response_headers.get("Last-Modified", entry.get("last_modified", "")),
                    }
                else:
                    rate_limited = exc.code == 429 or response_headers.get("X-RateLimit-Remaining") == "0" or (exc.code == 403 and response_headers.get("Retry-After"))
                    if exc.code == 403 and not rate_limited:
                        # Secondary rate limits may have remaining quota and no
                        # Retry-After header; GitHub explains them in the body.
                        detail = exc.read(65536).decode("utf-8", errors="replace").casefold() if exc.fp else ""
                        rate_limited = "rate limit" in detail
                    if rate_limited:
                        self._backoff(response_headers)
                    raise
            if authenticated:
                self._authentication_result("valid", response_headers)
            if response_headers.get("X-RateLimit-Remaining") == "0":
                self._backoff(response_headers)
            elif self.limit:
                self.limit = {}
                self._write(self.directory / "rate-limit.json", self.limit)
            if result.get("etag") or result.get("last_modified") or immutable:
                self._write(path, result)
            return InventoryResponse(result)
