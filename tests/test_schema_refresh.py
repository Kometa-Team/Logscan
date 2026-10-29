import importlib
import json
import os
import threading
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.error import HTTPError

import pytest

from logscan_web.recommendations import schema_fingerprint
from logscan_web.storage import AnonymousAnalyticsStore, ScanStore, UsageStatsStore
from logscan_web.support import _support_row

OLD_SCHEMA = {"type": "object", "properties": {"timeout": {"type": "integer"}}}
NEW_SCHEMA = {"type": "object", "properties": {"timeout": {"type": "string"}}}


class Response:
    def __init__(self, schema):
        self.payload = json.dumps(schema).encode()
        self.headers = {"ETag": '"new"', "Last-Modified": "Thu, 29 Oct 2026 12:00:00 GMT"}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_STORE", str(tmp_path))
    with patch("threading.Thread"):
        module = importlib.import_module("logscan_web.app")
    event = threading.Event()
    threads = Mock()
    monkeypatch.setattr(module.threading, "Thread", threads)
    monkeypatch.setattr(module.threading, "Event", Mock(return_value=event))
    monkeypatch.setattr(module.time, "sleep", Mock())
    app = module.create_app()
    app.config.update(TESTING=True)
    return SimpleNamespace(
        app=app,
        module=module,
        store=ScanStore(tmp_path),
        root=tmp_path,
        refresh=app.extensions["refresh_retained_schema_validation"],
        event=event,
        threads=threads,
    )


def cache_schema(service, branch="master", schema=OLD_SCHEMA, *, expired=True):
    directory = service.root / ".schema-cache"
    directory.mkdir(exist_ok=True)
    path = directory / f"{branch}.json"
    path.write_text(json.dumps(schema), encoding="utf-8")
    (directory / f"{branch}.metadata.json").write_text(json.dumps({"etag": '"old"'}), encoding="utf-8")
    if expired:
        old = time.time() - 7200
        os.utime(path, (old, old))
    return path


def retained_scan(service, filename="meta.log", *, branch="master", tool="kometa", version=None, checked_at=None, config="timeout: 60"):
    content = (f"Version: 2.5.3 (Branch: {branch})\nRedacted Config\n" f"[config.py:1] [DEBUG] | {config} |\nInitializing cache database at /config/cache\n").encode()
    result = SimpleNamespace(
        filename=filename,
        recommendations=[{"id": "existing-warning", "severity": "warning", "title": "Keep this finding"}],
        metadata={
            "tool_name": tool,
            "analysis_version": service.module.ANALYSIS_VERSION,
            "quickstart_run": False,
            "schema_validation_version": service.module.SCHEMA_VALIDATION_VERSION if version is None else version,
            "schema_validation_checked_at": checked_at or datetime.now(UTC).isoformat(),
            "schema_validation_branch": branch,
            "schema_validation_digest": schema_fingerprint(OLD_SCHEMA),
            "schema_validation_failures": [],
            "schema_validation_count": 0,
        },
        overview={"uploaded_by": "Support", "uploaded_by_id": "42", "message_url": "https://example.test/message"},
        categories=[],
    )
    scan_id, _token = service.store.create(filename, content, result)
    return scan_id


def test_changed_schema_revalidates_every_retained_log_on_its_branch(service):
    master_ids = [retained_scan(service, name) for name in ("first.log", "second.log")]
    develop_id = retained_scan(service, "nightly.log", branch="develop")
    imagemaid_id = retained_scan(service, "imagemaid.log", tool="imagemaid")
    before = {scan_id: service.store.get(scan_id) for scan_id in (*master_ids, develop_id, imagemaid_id)}
    source_logs = {scan_id: service.store.log_path(scan_id).read_bytes() for scan_id in before}
    stats = (AnonymousAnalyticsStore(service.root).snapshot(), UsageStatsStore(service.root).snapshot())
    cache_schema(service)
    cache_schema(service, "develop", expired=False)

    with (
        patch("logscan_web.recommendations.urlopen", return_value=Response(NEW_SCHEMA)) as fetch,
        patch.object(service.module, "validate_redacted_config", wraps=service.module.validate_redacted_config) as validate,
    ):
        service.refresh()
        assert fetch.call_count == 1
        assert "/master/" in fetch.call_args.args[0].full_url
        assert fetch.call_args.args[0].get_header("If-none-match") == '"old"'
        assert validate.call_count == 2
        service.refresh()
        assert validate.call_count == 2
        assert fetch.call_count == 1
        # Completed fingerprints survive a process restart without another sweep.
        restarted = service.module.create_app()
        restarted.extensions["refresh_retained_schema_validation"]()
        assert validate.call_count == 2
        assert fetch.call_count == 1

    for scan_id in master_ids:
        after = service.store.get(scan_id)
        metadata = after["metadata"]
        assert metadata["schema_validation_digest"] == schema_fingerprint(NEW_SCHEMA)
        assert metadata["schema_validation_count"] == 1
        assert metadata["schema_validation_failures"][0]["config_line"] == 1
        assert metadata["schema_validation_checked_at"] != before[scan_id]["metadata"]["schema_validation_checked_at"]
        assert _support_row(after, 48 * 3600, datetime.now(UTC))["counts"]["schema"] == 1
        assert {key: value for key, value in after.items() if key != "metadata"} == {key: value for key, value in before[scan_id].items() if key != "metadata"}
    for scan_id in (develop_id, imagemaid_id):
        assert service.store.get(scan_id) == before[scan_id]
    assert {scan_id: service.store.log_path(scan_id).read_bytes() for scan_id in before} == source_logs
    assert (AnonymousAnalyticsStore(service.root).snapshot(), UsageStatsStore(service.root).snapshot()) == stats


def test_version_eight_startup_forces_fetch_and_revalidation_despite_fresh_cache(service):
    assert service.module.SCHEMA_VALIDATION_VERSION == 8
    scan_id = retained_scan(service, version=7)
    cache_schema(service, expired=False)
    service.threads.reset_mock()
    with patch("logscan_web.recommendations.urlopen", return_value=Response(NEW_SCHEMA)) as fetch:
        service.app.extensions["backfill_retained_scans"]()
    fetch.assert_called_once()
    metadata = service.store.get(scan_id)["metadata"]
    assert metadata["schema_validation_version"] == 8
    assert metadata["schema_validation_digest"] == schema_fingerprint(NEW_SCHEMA)
    assert metadata["schema_validation_count"] == 1
    assert service.threads.call_args.kwargs["name"] == "kometa-schema-refresh"
    service.threads.return_value.start.assert_called()


@pytest.mark.parametrize("not_modified", [True, False])
def test_unchanged_schema_does_not_revalidate_logs(service, not_modified):
    scan_id = retained_scan(service)
    before = service.store.get(scan_id)
    cache_schema(service)
    # A new ETag or JSON key order alone must not trigger a sweep.
    reordered = {"properties": OLD_SCHEMA["properties"], "type": "object"}
    kwargs = {"side_effect": HTTPError("https://example.test", 304, "Not Modified", {}, None)} if not_modified else {"return_value": Response(reordered)}
    with patch("logscan_web.recommendations.urlopen", **kwargs), patch.object(service.module, "validate_redacted_config") as validate:
        service.refresh()
    validate.assert_not_called()
    assert service.store.get(scan_id) == before


def test_failed_refresh_uses_cache_and_retries_later(service):
    scan_id = retained_scan(service)
    before = service.store.get(scan_id)
    cache_schema(service)
    with patch("logscan_web.recommendations.urlopen", side_effect=TimeoutError), patch.object(service.module, "validate_redacted_config") as validate:
        service.refresh()
    validate.assert_not_called()
    assert service.store.get(scan_id) == before
    with patch("logscan_web.recommendations.urlopen", return_value=Response(NEW_SCHEMA)) as fetch:
        service.refresh()
    fetch.assert_called_once()
    assert service.store.get(scan_id)["metadata"]["schema_validation_count"] == 1


def test_schema_correction_removes_obsolete_findings_and_counts(service):
    scan_id = retained_scan(service)
    service.store.update_metadata(
        scan_id,
        schema_validation_digest=schema_fingerprint(NEW_SCHEMA),
        schema_validation_failures=[{"message": "Expected a string", "config_line": 1}],
        schema_validation_count=1,
    )
    cache_schema(service, schema=NEW_SCHEMA)
    with patch("logscan_web.recommendations.urlopen", return_value=Response(OLD_SCHEMA)):
        service.refresh()
    record = service.store.get(scan_id)
    assert record["metadata"]["schema_validation_failures"] == []
    assert record["metadata"]["schema_validation_count"] == 0
    assert _support_row(record, 48 * 3600, datetime.now(UTC))["counts"]["schema"] == 0


def test_failed_scan_is_retried_without_revalidating_successful_scans(service):
    scan_ids = [retained_scan(service, name) for name in ("first.log", "second.log")]
    cache_schema(service)
    original = service.module.validate_redacted_config
    failed = []

    def fail_once(path, **kwargs):
        if not failed:
            failed.append(path.parent.name)
            raise RuntimeError("Temporarily unavailable")
        return original(path, **kwargs)

    with patch("logscan_web.recommendations.urlopen", return_value=Response(NEW_SCHEMA)), patch.object(service.module, "validate_redacted_config", side_effect=fail_once):
        service.refresh()
    assert service.store.get(failed[0])["metadata"]["schema_validation_digest"] == schema_fingerprint(OLD_SCHEMA)
    with patch.object(service.module, "validate_redacted_config", wraps=original) as validate, patch("logscan_web.recommendations.urlopen") as fetch:
        service.refresh()
    validate.assert_called_once()
    fetch.assert_not_called()
    assert all(service.store.get(scan_id)["metadata"]["schema_validation_count"] == 1 for scan_id in scan_ids)


def test_result_page_discovery_wakes_sweep_and_invalidates_fresh_old_results(service):
    stale_time = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    first = retained_scan(service, checked_at=stale_time)
    fresh = retained_scan(service, "fresh.log")
    untouched = retained_scan(service, "untouched.log")
    cache_schema(service)
    with patch("logscan_web.recommendations.urlopen", return_value=Response(NEW_SCHEMA)) as fetch:
        client = service.app.test_client()
        response = client.post(f"/api/scans/{first}/validate-config")
        assert response.status_code == 200
        assert len(response.get_json()["failures"]) == 1
        assert service.event.is_set()
        # A fresh timestamp cannot hide a known schema fingerprint mismatch.
        response = client.post(f"/api/scans/{fresh}/validate-config")
        assert response.status_code == 200
        assert len(response.get_json()["failures"]) == 1
        # The worker also catches logs that nobody opens.
        service.refresh()
        fetch.assert_called_once()
    assert service.store.get(untouched)["metadata"]["schema_validation_count"] == 1


def test_missing_config_is_marked_checked_without_repeated_sweeps(service):
    scan_id = retained_scan(service)
    service.store.log_path(scan_id).write_bytes(b"Version: 2.5.3\nNo configuration block here\n")
    cache_schema(service)
    with patch("logscan_web.recommendations.urlopen", return_value=Response(NEW_SCHEMA)):
        service.refresh()
    with patch.object(service.module, "validate_redacted_config") as validate:
        service.refresh()
    validate.assert_not_called()
    metadata = service.store.get(scan_id)["metadata"]
    assert metadata["schema_validation_digest"] == schema_fingerprint(NEW_SCHEMA)
    assert metadata["schema_validation_count"] == 0


def test_missing_schema_does_not_prevent_other_branch_from_refreshing(service):
    master = retained_scan(service)
    develop = retained_scan(service, "nightly.log", branch="develop")

    def fetch(request, **_kwargs):
        if "/master/" in request.full_url:
            raise TimeoutError
        return Response(NEW_SCHEMA)

    with patch("logscan_web.recommendations.urlopen", side_effect=fetch):
        service.refresh()
    assert service.store.get(master)["metadata"]["schema_validation_digest"] == schema_fingerprint(OLD_SCHEMA)
    assert service.store.get(develop)["metadata"]["schema_validation_digest"] == schema_fingerprint(NEW_SCHEMA)
