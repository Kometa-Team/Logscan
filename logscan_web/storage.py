"""Small filesystem-backed store for uploaded logs and scan results."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
import sqlite3
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit


class ScanStore:
    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root)
        self.lock = threading.RLock()
        self.root.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _transaction(self):
        # SQLite serializes filesystem mutations across worker processes too.
        with self.lock:
            connection = sqlite3.connect(self.root / "dedup.sqlite3", timeout=60)
            try:
                connection.execute("CREATE TABLE IF NOT EXISTS fingerprints (digest TEXT PRIMARY KEY, scan_id TEXT NOT NULL)")
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    @staticmethod
    def fingerprint(content: bytes | Path) -> str:
        digest = hashlib.sha256()
        if isinstance(content, Path):
            with content.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
        else:
            digest.update(content)
        return digest.hexdigest()

    def _write_record(self, record: dict) -> None:
        directory = self.root / record["id"]
        temporary = directory / "result.json.tmp"
        temporary.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        temporary.replace(directory / "result.json")

    @staticmethod
    def _uploads(record: dict) -> list[dict]:
        if "uploads" in record:
            return record["uploads"]
        overview = record.get("overview") or {}
        return [
            {
                "token_hash": record["delete_token_hash"],
                "uploaded_by": overview.get("uploaded_by"),
                "uploaded_by_id": overview.get("uploaded_by_id"),
                "upload_source": overview.get("upload_source", "web"),
                "message_url": overview.get("message_url"),
            }
        ]

    @classmethod
    def owns(cls, record: dict | None, user_id: str) -> bool:
        return bool(record and any(str(upload.get("uploaded_by_id") or "") == str(user_id) for upload in cls._uploads(record)))

    def create_or_reuse(self, filename: str, content: bytes | Path, result, max_age_seconds: int) -> tuple[str, str, bool]:
        digest = self.fingerprint(content)
        with self._transaction() as index:
            # Backfill old records and recover a completed write after an interrupted transaction.
            indexed = {row[0] for row in index.execute("SELECT scan_id FROM fingerprints")}
            for record in self.list():
                path = self.log_path(record["id"])
                if record["id"] not in indexed and path is not None:
                    old_digest = record.get("content_sha256") or self.fingerprint(path)
                    index.execute("INSERT OR IGNORE INTO fingerprints VALUES (?, ?)", (old_digest, record["id"]))
            row = index.execute("SELECT scan_id FROM fingerprints WHERE digest = ?", (digest,)).fetchone()
            record = self.get(row[0]) if row else None
            if record:
                try:
                    live = datetime.fromisoformat(record["created_at"]).timestamp() + max_age_seconds > datetime.now(UTC).timestamp()
                except (KeyError, TypeError, ValueError):
                    live = False
                if not live or self.log_path(record["id"]) is None:
                    self._delete_record(record["id"], index)
                    record = None
            if record:
                token = secrets.token_urlsafe(32)
                uploads = self._uploads(record)
                overview = result.overview
                uploads.append(
                    {
                        "token_hash": hashlib.sha256(token.encode()).hexdigest(),
                        "uploaded_by": overview.get("uploaded_by"),
                        "uploaded_by_id": overview.get("uploaded_by_id"),
                        "upload_source": overview.get("upload_source", "web"),
                        "message_url": overview.get("message_url"),
                    }
                )
                record["uploads"] = uploads
                self._write_record(record)
                return record["id"], token, True
            if row:
                index.execute("DELETE FROM fingerprints WHERE digest = ?", (digest,))
            scan_id, token = self.create(filename, content, result)
            record = self.get(scan_id)
            record["content_sha256"] = digest
            self._write_record(record)
            index.execute("INSERT INTO fingerprints VALUES (?, ?)", (digest, scan_id))
            return scan_id, token, False

    def create(self, filename: str, content: bytes, result) -> tuple[str, str]:
        scan_id = secrets.token_urlsafe(18)
        delete_token = secrets.token_urlsafe(32)
        directory = self.root / scan_id
        directory.mkdir()
        if isinstance(content, Path):
            shutil.copyfile(content, directory / "log")
        else:
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

    def list(self) -> list[dict]:
        """Return stored scan records with filesystem update timestamps."""
        records = []
        for directory in self.root.iterdir():
            if not directory.is_dir() or not self._valid_id(directory.name):
                continue
            result_path = directory / "result.json"
            record = self.get(directory.name)
            if record is None:
                continue
            try:
                updated_at = datetime.fromtimestamp(result_path.stat().st_mtime, UTC).isoformat()
            except OSError:
                updated_at = record.get("created_at")
            records.append({**record, "updated_at": updated_at})
        return records

    def log_path(self, scan_id: str) -> Path | None:
        if self.get(scan_id) is None:
            return None
        path = self.root / scan_id / "log"
        return path if path.is_file() else None

    def update_metadata(self, scan_id: str, **values) -> bool:
        """Persist trusted derived metadata for an existing scan."""
        with self._transaction():
            record = self.get(scan_id)
            if record is None:
                return False
            record.setdefault("metadata", {}).update(values)
            result_path = self.root / scan_id / "result.json"
            temporary = self.root / scan_id / "result.json.tmp"
            temporary.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
            temporary.replace(result_path)
            return True

    def replace_analysis(self, scan_id: str, result) -> bool:
        """Atomically replace derived scan output without changing record identity."""
        with self._transaction():
            record = self.get(scan_id)
            if record is None:
                return False
            record.update(
                {
                    "filename": result.filename,
                    "recommendations": result.recommendations,
                    "metadata": result.metadata,
                    "overview": result.overview,
                    "categories": result.categories,
                }
            )
            result_path = self.root / scan_id / "result.json"
            temporary = self.root / scan_id / "result.json.tmp"
            temporary.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
            temporary.replace(result_path)
            return True

    def delete(self, scan_id: str, token: str) -> bool:
        with self._transaction() as index:
            record = self.get(scan_id)
            if record is None:
                return False
            supplied = hashlib.sha256(token.encode()).hexdigest()
            uploads = self._uploads(record)
            matched = next((upload for upload in uploads if hmac.compare_digest(supplied, upload["token_hash"])), None)
            if matched is None:
                return False
            owner = str(matched.get("uploaded_by_id") or "")
            remaining = [upload for upload in uploads if (str(upload.get("uploaded_by_id") or "") != owner if owner else not hmac.compare_digest(supplied, upload["token_hash"]))]
            return self._remove_uploads(record, remaining, index)

    def delete_for_owner(self, scan_id: str, user_id: str) -> bool:
        with self._transaction() as index:
            record = self.get(scan_id)
            if not self.owns(record, user_id):
                return False
            remaining = [upload for upload in self._uploads(record) if str(upload.get("uploaded_by_id") or "") != str(user_id)]
            return self._remove_uploads(record, remaining, index)

    def _remove_uploads(self, record: dict, remaining: list[dict], index) -> bool:
        if not remaining:
            return self._delete_record(record["id"], index)
        record["uploads"] = remaining
        # Preserve attribution only for uploaders who still retain this scan.
        for key in ("uploaded_by", "uploaded_by_id", "upload_source", "message_url"):
            record.setdefault("overview", {})[key] = remaining[0].get(key)
        self._write_record(record)
        return True

    def delete_authorized(self, scan_id: str) -> bool:
        """Delete an existing scan after its caller has performed authorization."""
        with self._transaction() as index:
            return self._delete_record(scan_id, index)

    def _delete_record(self, scan_id: str, index) -> bool:
        if self.get(scan_id) is None:
            return False
        directory = self.root / scan_id
        for name in ("log", "result.json", "result.json.tmp"):
            try:
                (directory / name).unlink()
            except FileNotFoundError:
                pass
        directory.rmdir()
        index.execute("DELETE FROM fingerprints WHERE scan_id = ?", (scan_id,))
        return True

    def delete_expired(self, max_age_seconds: int) -> int:
        """Delete scans whose recorded creation time is older than max_age_seconds."""
        cutoff = datetime.now(UTC).timestamp() - max_age_seconds
        deleted = 0
        with self._transaction() as index:
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
                self._delete_record(directory.name, index)
                deleted += 1
        return deleted

    @staticmethod
    def _valid_id(scan_id: str) -> bool:
        return bool(scan_id) and scan_id.replace("-", "").replace("_", "").isalnum()


class AnonymousAnalyticsStore:
    """Daily aggregates containing no request, user, filename, or log identifiers."""

    def __init__(self, root: str | os.PathLike[str]):
        self.path = Path(root) / "usage_analytics.json"
        self.lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock:
            if not self.path.exists():
                self._write(self._read())

    def record_rejection(self, category: str, source: str) -> None:
        with self.lock:
            data = self._read()
            day = self._day(data)
            self._increment(day["rejections"], category)
            self._increment(day["rejection_sources"], source)
            self._write(data)

    def import_legacy_baseline(self, stats: dict) -> None:
        """Preserve counters collected before detailed analytics were introduced."""
        with self.lock:
            data = self._read()
            if data.get("legacy_usage_imported"):
                return
            totals = self._totals(data)
            try:
                started = datetime.fromisoformat(str(stats.get("started_at", "")))
                day_key = started.date().isoformat()
                if started.isoformat() < data["started_at"]:
                    data["started_at"] = started.isoformat()
            except (TypeError, ValueError):
                day_key = datetime.now(UTC).date().isoformat()
            day = data["days"].setdefault(day_key, self._empty_day())
            fields = {
                "successful_logs": "logs_submitted",
                "lines_processed": "lines_processed",
                "people_submitted": "people_submitted",
                "people_addressed": "people_addressed",
            }
            for analytics_key, legacy_key in fields.items():
                baseline = max(0, int(stats.get(legacy_key, 0)))
                difference = max(0, baseline - totals[analytics_key])
                day[analytics_key] = day.get(analytics_key, 0) + difference
                if analytics_key == "successful_logs" and difference:
                    self._increment(day.setdefault("sources", {}), "legacy", difference)
            data["legacy_usage_imported"] = True
            self._write(data)

    def record_success(
        self,
        *,
        logs: int,
        lines: int,
        bytes_processed: int,
        source: str,
        batch: bool,
        versions: list[str],
        kometa_branches: list[str],
        launchers: list[str],
        quickstart_versions: list[str],
        quickstart_branches: list[str],
        recommendations: list[dict],
        people: int,
        plex: dict[str, list[str]] | None = None,
        kometa_platforms: list[str] | None = None,
        quickstart_platforms: list[str] | None = None,
        installation_methods: list[str] | None = None,
        tools: list[str] | None = None,
        imagemaid_versions: list[str] | None = None,
        imagemaid_modes: list[str] | None = None,
        duplicates: int = 0,
        imagemaid: list[dict] | None = None,
    ) -> None:
        with self.lock:
            data = self._read()
            day = self._day(data)
            day["successful_logs"] += max(0, int(logs))
            day["lines_processed"] += max(0, int(lines))
            day["bytes_processed"] += max(0, int(bytes_processed))
            day["people_submitted"] += max(0, int(people))
            day["batches"] += int(bool(batch))
            day["duplicates_reused"] += max(0, int(duplicates))
            for tool in tools or []:
                self._increment(day["tools"], tool)
            for version in imagemaid_versions or []:
                self._increment(day["imagemaid_versions"], version)
            for mode in imagemaid_modes or []:
                self._increment(day["imagemaid_modes"], mode)
            for metadata in imagemaid or []:
                counts = metadata.get("imagemaid_counts") or {}
                day["imagemaid_files_removed"] += sum(max(0, int(counts.get(key) or 0)) for key in ("restore_removed_files", "photo_removed_files", "bloat_removed_files"))
                day["imagemaid_bytes_recovered"] += sum(max(0, int(counts.get(key) or 0)) for key in ("restore_recovered_bytes", "photo_recovered_bytes", "bloat_recovered_bytes"))
                day["imagemaid_cleanup_reports"] += int(bool(metadata.get("imagemaid_cleanup_reported")))
                day["imagemaid_runtime_seconds"] += max(0, int(metadata.get("run_time_seconds") or 0))
                day["imagemaid_completed_runs"] += int(bool(metadata.get("complete")))
                self._increment(day["imagemaid_platforms"], metadata.get("runtime_platform", "Unknown"))
                self._increment(day["imagemaid_branches"], metadata.get("imagemaid_branch", "unknown"))
            self._increment(day["sources"], source, max(0, int(logs)))
            for version in versions:
                self._increment(day["kometa_versions"], version)
            for branch in kometa_branches:
                self._increment(day["kometa_branches"], branch)
            for launcher in launchers:
                self._increment(day["launchers"], launcher)
            for version in quickstart_versions:
                self._increment(day["quickstart_versions"], version)
            for branch in quickstart_branches:
                self._increment(day["quickstart_branches"], branch)
            for platform in kometa_platforms or []:
                self._increment(day["kometa_platforms"], platform)
            for platform in quickstart_platforms or []:
                self._increment(day["quickstart_platforms"], platform)
            for method in installation_methods or []:
                self._increment(day["installation_methods"], method)
            plex = plex or {}
            for source_key, analytics_key in (
                ("versions", "plex_versions"),
                ("platforms", "plex_platforms"),
                ("update_channels", "plex_update_channels"),
                ("library_types", "plex_library_types"),
                ("agents", "plex_agents"),
                ("scanners", "plex_scanners"),
            ):
                for value in plex.get(source_key, []):
                    self._increment(day[analytics_key], value)
            for finding in recommendations:
                self._increment(day["recommendations_by_id"], finding.get("id", "unknown"))
                self._increment(day["recommendations_by_severity"], finding.get("severity", "unknown"))
            self._write(data)

    def record_people_submitted(self, people: int) -> None:
        with self.lock:
            data = self._read()
            day = self._day(data)
            day["people_submitted"] += max(0, int(people))
            self._write(data)

    def record_addressed(self, records: list[dict]) -> None:
        now = datetime.now(UTC)
        with self.lock:
            data = self._read()
            known = set(data["addressed_keys"])
            day = self._day(data)
            changed = False
            for record in records:
                key = record.get("key")
                if not key:
                    continue
                digest = hashlib.sha256(str(key).encode()).hexdigest()
                if digest in known:
                    continue
                known.add(digest)
                day["people_addressed"] += 1
                try:
                    created = datetime.fromisoformat(record["created_at"])
                    duration = max(0, int((now - created).total_seconds()))
                except (KeyError, TypeError, ValueError):
                    duration = None
                if duration is not None:
                    day["address_seconds_total"] += duration
                    day["address_duration_count"] += 1
                changed = True
            if changed:
                data["addressed_keys"] = sorted(known)
                self._write(data)

    def snapshot(self) -> dict:
        with self.lock:
            data = self._read()
        totals = self._totals(data)
        return {"started_at": data["started_at"], "totals": totals, "days": data["days"]}

    def _totals(self, data: dict) -> dict:
        totals = self._empty_day()
        for day in data["days"].values():
            for key in (
                "successful_logs",
                "lines_processed",
                "bytes_processed",
                "people_submitted",
                "people_addressed",
                "address_seconds_total",
                "address_duration_count",
                "batches",
                "duplicates_reused",
                "imagemaid_files_removed",
                "imagemaid_bytes_recovered",
                "imagemaid_cleanup_reports",
                "imagemaid_runtime_seconds",
                "imagemaid_completed_runs",
            ):
                totals[key] += day.get(key, 0)
            for key in (
                "sources",
                "tools",
                "imagemaid_versions",
                "imagemaid_modes",
                "imagemaid_platforms",
                "imagemaid_branches",
                "rejections",
                "rejection_sources",
                "kometa_versions",
                "kometa_branches",
                "launchers",
                "quickstart_versions",
                "quickstart_branches",
                "kometa_platforms",
                "quickstart_platforms",
                "installation_methods",
                "plex_versions",
                "plex_platforms",
                "plex_update_channels",
                "plex_library_types",
                "plex_agents",
                "plex_scanners",
                "recommendations_by_id",
                "recommendations_by_severity",
            ):
                for label, count in day.get(key, {}).items():
                    self._increment(totals[key], label, count)
        count = totals.pop("address_duration_count")
        seconds = totals.pop("address_seconds_total")
        totals["average_address_seconds"] = round(seconds / count) if count else None
        return totals

    @staticmethod
    def _increment(values: dict, key: str, amount: int = 1) -> None:
        safe_key = str(key or "unknown")[:80]
        values[safe_key] = values.get(safe_key, 0) + amount

    @staticmethod
    def _empty_day() -> dict:
        return {
            "successful_logs": 0,
            "lines_processed": 0,
            "bytes_processed": 0,
            "people_submitted": 0,
            "people_addressed": 0,
            "address_seconds_total": 0,
            "address_duration_count": 0,
            "batches": 0,
            "duplicates_reused": 0,
            "tools": {},
            "imagemaid_versions": {},
            "imagemaid_modes": {},
            "imagemaid_platforms": {},
            "imagemaid_branches": {},
            "imagemaid_files_removed": 0,
            "imagemaid_bytes_recovered": 0,
            "imagemaid_cleanup_reports": 0,
            "imagemaid_runtime_seconds": 0,
            "imagemaid_completed_runs": 0,
            "sources": {},
            "rejections": {},
            "rejection_sources": {},
            "kometa_versions": {},
            "kometa_branches": {},
            "launchers": {},
            "quickstart_versions": {},
            "quickstart_branches": {},
            "kometa_platforms": {},
            "quickstart_platforms": {},
            "installation_methods": {},
            "recommendations_by_id": {},
            "plex_versions": {},
            "plex_platforms": {},
            "plex_update_channels": {},
            "plex_library_types": {},
            "plex_agents": {},
            "plex_scanners": {},
            "recommendations_by_severity": {},
        }

    def _day(self, data: dict) -> dict:
        day_key = datetime.now(UTC).date().isoformat()
        day = data["days"].setdefault(day_key, {})
        if not isinstance(day, dict):
            day = {}
            data["days"][day_key] = day
        for key, default in self._empty_day().items():
            if isinstance(default, dict):
                if not isinstance(day.get(key), dict):
                    day[key] = {}
            elif not isinstance(day.get(key), int):
                day[key] = default
        return day

    def _read(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        days = data.get("days") if isinstance(data.get("days"), dict) else {}
        # Before tool-level tracking, every successful scan was a Kometa log.
        for day in days.values():
            tools = day.setdefault("tools", {})
            unclassified = max(0, day.get("successful_logs", 0) - sum(tools.values()))
            if unclassified:
                self._increment(tools, "kometa", unclassified)
        return {
            "started_at": data.get("started_at") if isinstance(data.get("started_at"), str) else datetime.now(UTC).isoformat(),
            "days": days,
            "addressed_keys": data.get("addressed_keys") if isinstance(data.get("addressed_keys"), list) else [],
            "legacy_usage_imported": data.get("legacy_usage_imported") is True,
        }

    def _write(self, data: dict) -> None:
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        temporary.replace(self.path)


class UsageStatsStore:
    """Durable lifetime activity counters that are independent of scan expiry."""

    def __init__(self, root: str | os.PathLike[str]):
        self.path = Path(root) / "usage_stats.json"
        self.lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock:
            if not self.path.exists():
                self._write(self._default())

    def snapshot(self) -> dict:
        with self.lock:
            stats = self._read()
            return {
                "logs_submitted": stats["logs_submitted"],
                "lines_processed": stats["lines_processed"],
                "people_submitted": stats["people_submitted"],
                "people_addressed": stats["people_addressed"],
                "started_at": stats["started_at"],
            }

    def record_submission(self, *, logs: int = 0, lines: int = 0, people: int = 0) -> dict:
        with self.lock:
            stats = self._read()
            stats["logs_submitted"] += max(0, int(logs))
            stats["lines_processed"] += max(0, int(lines))
            stats["people_submitted"] += max(0, int(people))
            self._write(stats)
            return stats.copy()

    def ensure_people_baseline(self, people: int) -> None:
        """Seed a new stats file from the durable backlog without lowering later totals."""
        with self.lock:
            stats = self._read()
            baseline = max(0, int(people))
            if baseline > stats["people_submitted"]:
                stats["people_submitted"] = baseline
                self._write(stats)

    def mark_addressed(self, person_keys) -> int:
        with self.lock:
            stats = self._read()
            addressed = set(stats["addressed_person_keys"])
            new_keys = {str(key) for key in person_keys if key and str(key) not in addressed}
            if new_keys:
                addressed.update(new_keys)
                stats["addressed_person_keys"] = sorted(addressed)
                stats["people_addressed"] += len(new_keys)
                self._write(stats)
            return len(new_keys)

    @staticmethod
    def _default() -> dict:
        return {
            "logs_submitted": 0,
            "lines_processed": 0,
            "people_submitted": 0,
            "people_addressed": 0,
            "addressed_person_keys": [],
            "started_at": datetime.now(UTC).isoformat(),
        }

    def _read(self) -> dict:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            raw = {}
        defaults = self._default()
        if not isinstance(raw, dict):
            return defaults
        for key in ("logs_submitted", "lines_processed", "people_submitted", "people_addressed"):
            value = raw.get(key)
            defaults[key] = value if isinstance(value, int) and value >= 0 else 0
        keys = raw.get("addressed_person_keys")
        defaults["addressed_person_keys"] = [str(key) for key in keys if key] if isinstance(keys, list) else []
        if isinstance(raw.get("started_at"), str):
            defaults["started_at"] = raw["started_at"]
        return defaults

    def _write(self, stats: dict) -> None:
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(stats, ensure_ascii=False), encoding="utf-8")
        temporary.replace(self.path)


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

    def reconcile_image_availability(self, inventories: dict[str, dict[str, str]]) -> list[dict]:
        """Update a repository snapshot in one write without changing log history."""
        from .people_images import assess_people_images

        with self.lock:
            people = self._read()
            changed = False
            for person in people:
                assessed = assess_people_images(person, inventories)
                for field in ("style_availability", "people_image_status"):
                    if person.get(field) != assessed[field]:
                        person[field] = assessed[field]
                        changed = True
            if changed:
                self._write(people)
            return people

    def upsert(self, person: dict) -> dict:
        return self.upsert_with_status(person)[0]

    def upsert_with_status(self, person: dict) -> tuple[dict, bool]:
        from .people_images import person_name_key

        with self.lock:
            people = self._read()
            existing = next((item for item in people if item["key"] == person["key"]), None)
            if existing is None:
                incoming_names = {person_name_key(person.get(field)) for field in ("name", "original_name") if person.get(field)}
                name_matches = [
                    item
                    for item in people
                    if (not item.get("tmdb_id") or not person.get("tmdb_id"))
                    and not (person.get("identity_ambiguous") and item.get("tmdb_id"))
                    and incoming_names & {person_name_key(item.get(field)) for field in ("name", "original_name") if item.get(field)}
                ]
                existing = name_matches[0] if len(name_matches) == 1 else None
            if existing:
                incoming_requesters = person.get("requested_by", [])
                incoming_provenance_tags = person.get("provenance_tags", [])
                merged_fields = ("source_styles", "detection_reasons", "log_provenance")
                merged = {field: list(existing.get(field, [])) for field in merged_fields}
                for field in merged_fields:
                    for value in person.get(field, []):
                        if field == "log_provenance" and value.get("log_url"):
                            path = urlsplit(value["log_url"]).path
                            previous = next((item for item in merged[field] if urlsplit(item.get("log_url") or "").path == path), None)
                            if previous is not None:
                                previous.update({key: item for key, item in value.items() if item is not None})
                                continue
                        if value not in merged[field]:
                            merged[field].append(value)
                # An unresolved repeat must not downgrade an already resolved identity.
                updates = {key: value for key, value in person.items() if value is not None and key not in {"requested_by", "provenance_tags", *merged_fields}}
                if existing.get("tmdb_id") and not person.get("tmdb_id"):
                    updates.pop("key", None)
                existing.update(updates)
                existing.update({field: values for field, values in merged.items() if values})
                requesters = list(existing.get("requested_by", []))
                for requester in incoming_requesters:
                    requester_id = requester.get("id")
                    requester_name = requester.get("name", "").casefold()
                    match = next(
                        (
                            item
                            for item in requesters
                            if (requester_id and item.get("id") == requester_id) or (not requester_id and requester_name and item.get("name", "").casefold() == requester_name)
                        ),
                        None,
                    )
                    if match:
                        match.update({key: value for key, value in requester.items() if value})
                    else:
                        requesters.append(requester)
                if requesters:
                    existing["requested_by"] = requesters
                provenance_tags = [str(tag) for tag in existing.get("provenance_tags", []) if isinstance(tag, str) and tag]
                for tag in incoming_provenance_tags:
                    if isinstance(tag, str) and tag and tag not in provenance_tags:
                        provenance_tags.append(tag)
                if provenance_tags:
                    existing["provenance_tags"] = provenance_tags
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
        self.save_many({imdb_id: person})

    def save_many(self, people: dict[str, dict | None]) -> None:
        """Persist a batch of resolved people with a single atomic write."""
        with self.lock:
            records = self._read()
            updated_at = datetime.now(UTC).isoformat()
            records.update({imdb_id: {"updated_at": updated_at, "person": person} for imdb_id, person in people.items()})
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
    """Durable TMDb person-ID exclusions for the People queue."""

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
        return (
            {int(person_id): checked_at for person_id, checked_at in values.items() if str(person_id).isdigit() and isinstance(checked_at, str)} if isinstance(values, dict) else {}
        )

    def _write(self, records: dict[int, str]) -> None:
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps({str(person_id): checked_at for person_id, checked_at in records.items()}), encoding="utf-8")
        temporary.replace(self.path)


class PopularPeopleFlagStore:
    """Durable review flags and their reasons for the People queue."""

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
        return (
            {int(person_id): record for person_id, record in values.items() if str(person_id).isdigit() and isinstance(record, dict) and isinstance(record.get("reason"), str)}
            if isinstance(values, dict)
            else {}
        )
