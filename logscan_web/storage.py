"""Small filesystem-backed store for uploaded logs and scan results."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
import threading
from datetime import UTC, datetime
from pathlib import Path


class ScanStore:
    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def create(self, filename: str, content: bytes, result) -> tuple[str, str]:
        scan_id = secrets.token_urlsafe(18)
        delete_token = secrets.token_urlsafe(32)
        directory = self.root / scan_id
        directory.mkdir()
        (directory / "log").write_bytes(content)
        record = {
            "id": scan_id,
            "filename": result.filename,
            "created_at": datetime.now(UTC).isoformat(),
            "recommendations": result.recommendations,
            "metadata": result.metadata,
            "overview": result.overview,
            "categories": result.categories,
            "delete_token_hash": hashlib.sha256(delete_token.encode()).hexdigest(),
        }
        temporary = directory / "result.json.tmp"
        temporary.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        temporary.replace(directory / "result.json")
        return scan_id, delete_token

    def create_batch(self, scans: list[dict], unscanned_files: list[str] | None = None) -> tuple[str, str]:
        batch_id = secrets.token_urlsafe(18)
        admin_token = secrets.token_urlsafe(32)
        directory = self.root / "batches"
        directory.mkdir(exist_ok=True)
        record = {"id": batch_id, "scans": scans, "unscanned_files": unscanned_files or [], "admin_token_hash": hashlib.sha256(admin_token.encode()).hexdigest()}
        (directory / f"{batch_id}.json").write_text(json.dumps(record), encoding="utf-8")
        return batch_id, admin_token

    def get_batch(self, batch_id: str, admin_token: str | None = None) -> dict | None:
        try:
            record = json.loads((self.root / "batches" / f"{batch_id}.json").read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        if admin_token is not None and not hmac.compare_digest(hashlib.sha256(admin_token.encode()).hexdigest(), record["admin_token_hash"]):
            return None
        return record

    def delete_batch(self, batch_id: str, admin_token: str) -> bool:
        """Delete every scan in an authorized batch and its batch record."""
        record = self.get_batch(batch_id, admin_token)
        if record is None:
            return False
        for scan in record["scans"]:
            self.delete(scan["id"], scan["delete_token"])
        try:
            (self.root / "batches" / f"{batch_id}.json").unlink()
        except FileNotFoundError:
            return False
        return True

    def get(self, scan_id: str) -> dict | None:
        if not self._valid_id(scan_id):
            return None
        try:
            return json.loads((self.root / scan_id / "result.json").read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def log_path(self, scan_id: str) -> Path | None:
        if self.get(scan_id) is None:
            return None
        path = self.root / scan_id / "log"
        return path if path.is_file() else None

    def delete(self, scan_id: str, token: str) -> bool:
        record = self.get(scan_id)
        if record is None:
            return False
        supplied = hashlib.sha256(token.encode()).hexdigest()
        if not hmac.compare_digest(supplied, record["delete_token_hash"]):
            return False
        directory = self.root / scan_id
        for name in ("log", "result.json", "result.json.tmp"):
            try:
                (directory / name).unlink()
            except FileNotFoundError:
                pass
        directory.rmdir()
        return True

    def delete_expired(self, max_age_seconds: int) -> int:
        """Delete scans whose recorded creation time is older than max_age_seconds."""
        cutoff = datetime.now(UTC).timestamp() - max_age_seconds
        deleted = 0
        for directory in self.root.iterdir():
            if not directory.is_dir() or not self._valid_id(directory.name):
                continue
            record = self.get(directory.name)
            if record is None:
                continue
            try:
                created = datetime.fromisoformat(record["created_at"]).timestamp()
            except (KeyError, TypeError, ValueError):
                created = 0
            if created >= cutoff:
                continue
            shutil.rmtree(directory)
            deleted += 1
        return deleted

    @staticmethod
    def _valid_id(scan_id: str) -> bool:
        return bool(scan_id) and scan_id.replace("-", "").replace("_", "").isalnum()


class PeopleStore:
    """A small durable backlog for People Posters work, independent of scan expiry."""

    def __init__(self, root: str | os.PathLike[str]):
        self.path = Path(root) / "people.json"
        self.lock = threading.Lock()

    def list(self) -> list[dict]:
        with self.lock:
            return self._read()

    def get(self, key: str) -> dict | None:
        return next((person for person in self.list() if person["key"] == key), None)

    def upsert(self, person: dict) -> dict:
        return self.upsert_with_status(person)[0]

    def upsert_with_status(self, person: dict) -> tuple[dict, bool]:
        with self.lock:
            people = self._read()
            existing = next((item for item in people if item["key"] == person["key"]), None)
            if existing:
                existing.update({key: value for key, value in person.items() if value is not None})
                existing["last_seen_at"] = datetime.now(UTC).isoformat()
                result = existing
                created = False
            else:
                result = {**person, "created_at": datetime.now(UTC).isoformat(), "last_seen_at": datetime.now(UTC).isoformat()}
                people.append(result)
                created = True
            self._write(people)
            return result.copy(), created

    def delete(self, key: str) -> bool:
        with self.lock:
            people = self._read()
            remaining = [person for person in people if person["key"] != key]
            if len(remaining) == len(people):
                return False
            self._write(remaining)
            return True

    def _read(self) -> list[dict]:
        try:
            result = json.loads(self.path.read_text(encoding="utf-8"))
            return result if isinstance(result, list) else []
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _write(self, people: list[dict]) -> None:
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(people, ensure_ascii=False), encoding="utf-8")
        temporary.replace(self.path)


class PopularPeopleCacheStore:
    """Durable, atomically-written snapshot shared by all web workers."""

    def __init__(self, root: str | os.PathLike[str]):
        self.path = Path(root) / "popular_people_cache.json"
        self.lock = threading.Lock()

    def load(self) -> dict | None:
        with self.lock:
            try:
                snapshot = json.loads(self.path.read_text(encoding="utf-8"))
            except (FileNotFoundError, json.JSONDecodeError):
                return None
            if not isinstance(snapshot, dict) or not isinstance(snapshot.get("people"), list) or not isinstance(snapshot.get("updated_at"), str):
                return None
            return snapshot

    def save(self, people: list[dict]) -> dict:
        snapshot = {"updated_at": datetime.now(UTC).isoformat(), "people": people}
        with self.lock:
            temporary = self.path.with_suffix(".tmp")
            temporary.write_text(json.dumps(snapshot, ensure_ascii=False), encoding="utf-8")
            temporary.replace(self.path)
        return snapshot


class TMDbFindCacheStore:
    """Durable IMDb-to-TMDb lookup cache used while building popular people."""

    def __init__(self, root: str | os.PathLike[str]):
        self.path = Path(root) / "tmdb_find_cache.json"
        self.lock = threading.Lock()

    def get(self, imdb_id: str, max_age_seconds: int) -> dict | None:
        with self.lock:
            records = self._read()
            record = records.get(imdb_id)
            if not isinstance(record, dict):
                return None
            try:
                fresh = datetime.fromisoformat(record["updated_at"]).timestamp() >= datetime.now(UTC).timestamp() - max_age_seconds
            except (KeyError, TypeError, ValueError):
                return None
            return record.get("person") if fresh and isinstance(record.get("person"), dict) else None

    def save(self, imdb_id: str, person: dict | None) -> None:
        with self.lock:
            records = self._read()
            records[imdb_id] = {"updated_at": datetime.now(UTC).isoformat(), "person": person}
            temporary = self.path.with_suffix(".tmp")
            temporary.write_text(json.dumps(records, ensure_ascii=False), encoding="utf-8")
            temporary.replace(self.path)

    def _read(self) -> dict:
        try:
            records = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
        return records if isinstance(records, dict) else {}


class PopularPeopleExclusionStore:
    """Durable TMDb person-ID exclusions for the Popular People page."""

    def __init__(self, root: str | os.PathLike[str]):
        self.path = Path(root) / "popular_people_exclusions.json"
        self.lock = threading.Lock()

    def list(self) -> set[int]:
        with self.lock:
            try:
                values = json.loads(self.path.read_text(encoding="utf-8"))
            except (FileNotFoundError, json.JSONDecodeError):
                return set()
            return {value for value in values if isinstance(value, int) and value > 0} if isinstance(values, list) else set()

    def add(self, person_id: int) -> bool:
        if person_id <= 0:
            return False
        with self.lock:
            try:
                values = json.loads(self.path.read_text(encoding="utf-8"))
            except (FileNotFoundError, json.JSONDecodeError):
                values = []
            exclusions = {value for value in values if isinstance(value, int) and value > 0} if isinstance(values, list) else set()
            if person_id in exclusions:
                return False
            exclusions.add(person_id)
            temporary = self.path.with_suffix(".tmp")
            temporary.write_text(json.dumps(sorted(exclusions)), encoding="utf-8")
            temporary.replace(self.path)
            return True


class PopularPeopleCheckStore:
    """Durable, timestamped checks that temporarily hide popular people."""

    def __init__(self, root: str | os.PathLike[str]):
        self.path = Path(root) / "popular_people_checked.json"
        self.lock = threading.Lock()

    def active_ids(self, max_age_seconds: int) -> set[int]:
        cutoff = datetime.now(UTC).timestamp() - max_age_seconds
        with self.lock:
            records = self._read()
            active = set()
            for person_id, checked_at in records.items():
                try:
                    timestamp = datetime.fromisoformat(checked_at).timestamp()
                except (TypeError, ValueError):
                    continue
                if timestamp >= cutoff:
                    active.add(person_id)
            return active

    def mark(self, person_id: int) -> bool:
        if person_id <= 0:
            return False
        with self.lock:
            records = self._read()
            records[person_id] = datetime.now(UTC).isoformat()
            self._write(records)
            return True

    def _read(self) -> dict[int, str]:
        try:
            values = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
        return {int(person_id): checked_at for person_id, checked_at in values.items() if str(person_id).isdigit() and isinstance(checked_at, str)} if isinstance(values, dict) else {}

    def _write(self, records: dict[int, str]) -> None:
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps({str(person_id): checked_at for person_id, checked_at in records.items()}), encoding="utf-8")
        temporary.replace(self.path)


class PopularPeopleFlagStore:
    """Durable review flags and their reasons for Popular People."""

    def __init__(self, root: str | os.PathLike[str]):
        self.path = Path(root) / "popular_people_flags.json"
        self.lock = threading.Lock()

    def list(self) -> dict[int, dict[str, str]]:
        with self.lock:
            return self._read()

    def upsert(self, person_id: int, reason: str) -> bool:
        if person_id <= 0 or not reason.strip():
            return False
        with self.lock:
            flags = self._read()
            flags[person_id] = {"reason": reason.strip(), "flagged_at": datetime.now(UTC).isoformat()}
            self._write(flags)
            return True

    def delete(self, person_id: int) -> bool:
        with self.lock:
            flags = self._read()
            if person_id not in flags:
                return False
            del flags[person_id]
            self._write(flags)
            return True

    def _write(self, flags: dict[int, dict[str, str]]) -> None:
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps({str(person_id): flag for person_id, flag in flags.items()}, ensure_ascii=False), encoding="utf-8")
        temporary.replace(self.path)

    def _read(self) -> dict[int, dict[str, str]]:
        try:
            values = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
        return {
            int(person_id): record
            for person_id, record in values.items()
            if str(person_id).isdigit() and isinstance(record, dict) and isinstance(record.get("reason"), str)
        } if isinstance(values, dict) else {}
