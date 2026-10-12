from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from io import BytesIO
from unittest.mock import patch
import gzip
import zipfile

import pytest

from logscan_web.scanner import ScanError, detect_log_tool, find_scannable_upload_path, scan_archive_logs, scan_archive_path, scan_log
from logscan_web.storage import ScanStore
from logscan_web.imagemaid import recovered_bytes


def imagemaid_log():
    return b"\n".join(
        [
            b"[Quickstart] Run marker: started=2026-10-12T10:00:00 config=test tool=imagemaid mode=remove quickstart=0.10.13 branch=develop",
            b"[2026-10-12 10:00:00,000] [imagemaid.py:1] [INFO] | Version: 1.1.1 (Python 3.13) |",
            b"[imagemaid.py:2] [INFO] | Run Command: python imagemaid.py --mode remove |",
            b"[imagemaid.py:3] [INFO] | Running in Remove Mode |",
            b"[imagemaid.py:4] [INFO] | Scanning for PhotoTranscoder Images |",
            b"[imagemaid.py:5] [INFO] | Found 20 PhotoTranscoder Images to Remove |",
            b"[imagemaid.py:6] [INFO] | Runtime: 0:00:12 |",
            b"[imagemaid.py:7] [INFO] | Removing PhotoTranscoder Images |",
            b"[imagemaid.py:8] [INFO] | Removed 18 PhotoTranscoder Images |",
            b"[imagemaid.py:9] [INFO] | Space Recovered: 1.5 MB |",
            b"[imagemaid.py:10] [INFO] | Runtime: 0:00:05 |",
            b"[imagemaid.py:11] [ERROR] | Permission denied |",
            b"[2026-10-12 10:01:00,000] [imagemaid.py:12] [INFO] | ImageMaid Finished |",
            b"[imagemaid.py:13] [INFO] | Total Runtime | 0:01:00 |",
        ]
    )


KOMETA = b"[kometa.py:1] [INFO] | Version: 2.5.0 |\n[kometa.py:2] [INFO] | Finished: now Run Time: 0:01:00 |"


@pytest.mark.parametrize("filename,content,tool", [("meta.log", imagemaid_log(), "imagemaid"), ("imagemaid.log", KOMETA, "kometa"), ("random.txt", imagemaid_log(), "imagemaid")])
def test_content_detection_ignores_filename(filename, content, tool):
    assert detect_log_tool(content) == tool
    assert scan_log(filename, content).metadata["tool_name"] == tool


def test_bare_imagemaid_header_and_completed_run():
    content = b"| Version: 1.1.1 |\n| Run Command: python imagemaid.py --mode report |\n| Running in Report Mode |\n|=== ImageMaid Finished ===|\n| Total Runtime | 0:00:05 |"
    result = scan_log("unknown.log", content)
    assert result.metadata["tool_name"] == "imagemaid"
    assert result.metadata["complete"]


@pytest.mark.parametrize("value,expected", [("23.79 GBs", int(23.79 * 1024**3)), ("6.43 MBs", int(6.43 * 1024**2)), ("0 Bytes", 0), ("2 KiB", 2048), ("1..5 MB", None)])
def test_reported_space_units(value, expected):
    assert recovered_bytes(value) == expected


def test_bloat_cleanup_and_report_only_logs():
    content = imagemaid_log() + b"\n[imagemaid.py:20] [INFO] | Removed 7 Bloat Images |\n[imagemaid.py:21] [INFO] | Space Recovered: 2 GBs |"
    counts = scan_log("meta.log", content).metadata["imagemaid_counts"]
    assert counts["bloat_removed_files"] == 7 and counts["bloat_recovered_bytes"] == 2 * 1024**3
    report = b"[imagemaid.py:1] [INFO] | Running in Report Mode |\n[imagemaid.py:2] [INFO] | Reporting Bloat Images |\n[imagemaid.py:3] [INFO] | Found 25 Bloat Images |"
    counts = scan_log("report.log", report).metadata["imagemaid_counts"]
    assert counts["bloat_removed_files"] == 0 and counts["bloat_recovered_bytes"] == 0


@pytest.mark.parametrize("content", [b"random text imagemaid.py", b"| Version: 1.1.1 |\nImageMaid", KOMETA + b"\n[imagemaid.py:1] [INFO] hello"])
def test_unknown_and_concatenated_tool_logs_rejected(content):
    with pytest.raises(ScanError):
        scan_log("imagemaid.log", content)


def test_imagemaid_counts_runtime_errors_and_quickstart():
    result = scan_log("test.log", imagemaid_log())
    metadata = result.metadata
    assert metadata["complete"] and metadata["quickstart_run"]
    assert metadata["imagemaid_mode"] == "remove"
    assert metadata["quickstart_version"] == "0.10.13"
    assert metadata["imagemaid_counts"]["photo_removed_files"] == 18
    assert metadata["imagemaid_counts"]["photo_recovered_bytes"] == 1572864
    assert metadata["log_counts"]["error"] == 1
    assert result.recommendations[0]["evidence_lines"] == [12]
    assert result.overview["section_run_times"][0]["duration"] == "0:00:12"
    assert not result.missing_people
    assert "schema" not in [group["key"] for group in result.categories]
    assert "kometa_version" not in metadata


def test_mixed_archives_gzip_and_large_path(tmp_path):
    bundle = BytesIO()
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("kometa.log", KOMETA)
        archive.writestr("meta.log", imagemaid_log())
    assert [result.metadata["tool_name"] for _, _, result in scan_archive_logs("mixed.zip", bundle.getvalue())] == ["kometa", "imagemaid"]
    path = tmp_path / "uploaded"
    path.write_bytes(gzip.compress(imagemaid_log()))
    assert find_scannable_upload_path("meta.log.gz", path) == [("meta.log", len(imagemaid_log()))]
    assert scan_archive_path("meta.log.gz", path)[0][2].metadata["tool_name"] == "imagemaid"
    path.write_bytes(imagemaid_log())
    with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
        result = scan_archive_path("meta.log", path)[0][2]
        assert result.metadata["imagemaid_counts"]["photo_removed_files"] == 18
        assert result.metadata["complete"]


def test_content_reuse_survives_restart_and_multiple_owners(tmp_path):
    first = scan_log("first.log", KOMETA)
    first.overview.update(uploaded_by="Alice", uploaded_by_id="1")
    store = ScanStore(tmp_path)
    scan_id, token, reused = store.create_or_reuse("first.log", KOMETA, first, 172800)
    assert not reused
    second = scan_log("renamed.log", KOMETA)
    second.overview.update(uploaded_by="Bob", uploaded_by_id="2")
    other_store = ScanStore(tmp_path)
    duplicate_id, duplicate_token, reused = other_store.create_or_reuse("renamed.log", KOMETA, second, 172800)
    assert duplicate_id == scan_id and reused and token != duplicate_token
    assert len(store.list()) == 1
    assert store.owns(store.get(scan_id), "1") and store.owns(store.get(scan_id), "2")
    assert not store.delete(scan_id, "invalid")
    assert store.delete(scan_id, duplicate_token)
    assert store.get(scan_id) is not None and not store.owns(store.get(scan_id), "2")
    assert store.delete(scan_id, token)
    assert store.get(scan_id) is None
    fresh_id, _, reused = store.create_or_reuse("again.log", KOMETA, first, 172800)
    assert fresh_id != scan_id and not reused


@pytest.mark.parametrize("expired,missing_log", [(True, False), (False, True)])
def test_expired_or_missing_log_not_reused(tmp_path, expired, missing_log):
    store = ScanStore(tmp_path)
    result = scan_log("meta.log", KOMETA)
    scan_id, _, _ = store.create_or_reuse("meta.log", KOMETA, result, 172800)
    if expired:
        record = store.get(scan_id)
        record["created_at"] = (datetime.now(UTC) - timedelta(days=3)).isoformat()
        store._write_record(record)
    if missing_log:
        store.log_path(scan_id).unlink()
    new_id, _, reused = store.create_or_reuse("meta.log", KOMETA, result, 172800)
    assert new_id != scan_id and not reused


def test_concurrent_instances_create_one_retained_log(tmp_path):
    result = scan_log("meta.log", KOMETA)

    def submit(_):
        return ScanStore(tmp_path).create_or_reuse("meta.log", KOMETA, result, 172800)

    with ThreadPoolExecutor(max_workers=8) as pool:
        submissions = list(pool.map(submit, range(8)))
    assert len({scan_id for scan_id, _, _ in submissions}) == 1
    assert len({token for _, token, _ in submissions}) == 8
    assert sum(not reused for _, _, reused in submissions) == 1
    assert len(ScanStore(tmp_path).list()) == 1


def _submit_from_process(root):
    return ScanStore(root).create_or_reuse("meta.log", KOMETA, scan_log("meta.log", KOMETA), 172800)


def test_worker_processes_share_the_deduplication_index(tmp_path):
    with ProcessPoolExecutor(max_workers=3) as pool:
        submissions = list(pool.map(_submit_from_process, [str(tmp_path)] * 6))
    assert len({scan_id for scan_id, _, _ in submissions}) == 1
    assert sum(not reused for _, _, reused in submissions) == 1


def test_legacy_receipt_and_expiration_cleanup(tmp_path):
    store = ScanStore(tmp_path)
    result = scan_log("legacy.log", KOMETA)
    scan_id, original_token = store.create("legacy.log", KOMETA, result)
    reused_id, _, reused = store.create_or_reuse("new-name.log", KOMETA, result, 172800)
    assert reused and reused_id == scan_id
    record = store.get(scan_id)
    record["created_at"] = (datetime.now(UTC) - timedelta(days=3)).isoformat()
    store._write_record(record)
    assert store.delete_expired(172800) == 1
    new_id, _, reused = store.create_or_reuse("again.log", KOMETA, result, 172800)
    assert new_id != scan_id and not reused
    assert not store.delete(new_id, original_token)


def test_bot_web_dedup_tool_analytics_and_private_grants(tmp_path, monkeypatch):
    # Import only after test_people has configured its isolated global app store.
    from logscan_web.app import create_app

    monkeypatch.setenv("SCAN_STORE", str(tmp_path))
    monkeypatch.setenv("LOGSCAN_API_KEY", "test-secret")
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    assert client.get("/api/capabilities").json["tools"] == ["kometa", "imagemaid"]
    validation = client.post("/api/bot/validate", data={"log": (BytesIO(imagemaid_log()), "meta.log")}, headers={"Authorization": "Bearer test-secret"})
    assert validation.status_code == 200 and len(validation.json["files"]) == 1
    first = client.post(
        "/api/bot/scan", data={"log": (BytesIO(imagemaid_log()), "meta.log"), "uploaded_by": "Alice", "uploaded_by_id": "1"}, headers={"Authorization": "Bearer test-secret"}
    ).json["scans"][0]
    second = client.post("/api/scan", data={"log": (BytesIO(gzip.compress(imagemaid_log())), "renamed.log.gz")}).json
    assert first["id"] == second["id"] and second["already_uploaded"]
    assert first["delete_token"] != second["delete_token"]
    assert first["expires_at"] == second["expires_at"]
    html = client.get(f'/scan/{first["id"]}').get_data(as_text=True)
    assert '"uploads"' not in html and '"content_sha256"' not in html and '"delete_token_hash"' not in html
    assert client.post(f'/api/scans/{first["id"]}/validate-config').status_code == 409
    totals = client.get("/api/analytics").json["totals"]
    assert totals["tools"] == {"imagemaid": 1}
    assert totals["kometa_versions"] == {}
    assert totals["duplicates_reused"] == 1 and totals["successful_logs"] == 1
    assert totals["imagemaid_files_removed"] == 18
    assert totals["imagemaid_bytes_recovered"] == 1572864
    assert totals["imagemaid_cleanup_reports"] == 1
    assert totals["imagemaid_versions"] == {"1.1.1": 1} and totals["imagemaid_modes"] == {"remove": 1}
    assert totals["imagemaid_completed_runs"] == 1 and totals["imagemaid_runtime_seconds"] == 60
    page = client.get("/").get_data(as_text=True)
    assert 'aria-label="Cumulative ImageMaid cleanup"' in page and "1.5 MB" in page and "<dd>18</dd>" in page
    assert "<dt>Kometa logs uploaded</dt><dd>0</dd>" in page
    assert "<dt>ImageMaid logs uploaded</dt><dd>1</dd>" in page
    assert "<dt>Plex image bloat files removed</dt><dd>18</dd>" in page
    assert page.index("Kometa logs processed") < page.index("ImageMaid cleanup")
    assert "Missing people images identified" in page and "Missing people images resolved" in page
    analytics_page = client.get("/analytics").get_data(as_text=True)
    assert analytics_page.count('<details class="analytics-group"') == 6
    assert '<details class="analytics-group" open' not in analytics_page
    for tool in ("kometa", "imagemaid", "quickstart", "plex"):
        assert f"/static/{tool}.png" in analytics_page
