"""Persist the seven public poster indexes independently of GitHub API quota."""

import json
import time
from datetime import UTC, datetime
from urllib.error import HTTPError
from urllib.request import Request

from .people_images import parse_people_readme


class PeopleReadmeCache:
    def __init__(self, directory, *, max_age=3600):
        self.directory = directory
        self.max_age = max_age

    def load(self, style, *, open_url):
        # The caller serializes refreshes; different styles use different files.
        path = self.directory / f"{style.key}.json"
        entry = None
        try:
            saved = json.loads(path.read_text(encoding="utf-8"))
            if (
                isinstance(saved, dict)
                and isinstance(saved.get("text"), str)
                and isinstance(saved.get("checked_at"), (float, int))
                and isinstance(saved.get("etag", ""), str)
                and isinstance(saved.get("last_modified", ""), str)
            ):
                entry = saved
        except (OSError, ValueError):
            pass
        now = time.time()
        refreshed = entry is None or not 0 <= now - entry["checked_at"] < self.max_age
        if refreshed:
            headers = {"Accept": "text/plain", "User-Agent": "Kometa-Logscan/1.0"}
            if entry is not None:
                if entry.get("etag"):
                    headers["If-None-Match"] = entry["etag"]
                if entry.get("last_modified"):
                    headers["If-Modified-Since"] = entry["last_modified"]
            try:
                # Public raw files never need a token and have their own cache.
                with open_url(Request(style.readme_url, headers=headers), timeout=10) as response:
                    entry = {
                        "text": response.read().decode("utf-8"),
                        "checked_at": now - max(0, int(response.headers.get("Age", "0"))),
                        "etag": response.headers.get("ETag", ""),
                        "last_modified": response.headers.get("Last-Modified", ""),
                    }
            except HTTPError as exc:
                if exc.code != 304 or entry is None:
                    raise
                entry = {**entry, "checked_at": now}
        inventory = parse_people_readme(style, entry["text"])
        if inventory is None:
            raise ValueError("The repository image index was incomplete.")
        if not 0 <= now - entry["checked_at"] < self.max_age:
            raise ValueError("The repository image index was expired.")
        inventory.checked_at = datetime.fromtimestamp(entry["checked_at"], UTC).isoformat()
        if refreshed:
            try:
                self.directory.mkdir(parents=True, exist_ok=True)
                temporary = path.with_suffix(".json.tmp")
                temporary.write_text(json.dumps(entry), encoding="utf-8")
                temporary.replace(path)
            except OSError:
                pass
        return inventory
