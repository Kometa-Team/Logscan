import bz2
import gzip
import py7zr
import json
import lzma
from io import BytesIO
from jsonschema import Draft7Validator
import zipfile
import zstandard as zstd
import os
import tempfile
import tarfile
import threading
import time
import unittest
from types import SimpleNamespace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch


STORE = tempfile.TemporaryDirectory()
os.environ["SCAN_STORE"] = STORE.name
os.environ["TMDB_API_KEY"] = "test-key"

Path(STORE.name, "popular_people_cache.json").write_text(json.dumps({
    "updated_at": datetime.now(UTC).isoformat(),
    "people": [
        {"id": 1, "name": "Alice Person", "profile_path": "/alice.jpg", "known_for_department": "Acting"},
        {"id": 2, "name": "Completed Person", "profile_path": "/complete.jpg", "known_for_department": "Acting"},
    ],
}), encoding="utf-8")

from logscan_web.app import add_missing_people_recommendations, app, create_app
from logscan_web.scanner import (
    MAX_FILE_BYTES,
    STREAM_SCAN_THRESHOLD,
    extract_missing_people,
    extract_plex_configurations,
    extract_section_run_times,
    find_scannable_upload_path,
    normalized_platform,
    normalized_installation,
    extract_quickstart_metadata,
    apply_documentation_branch,
    scan_archive_logs,
    scan_archive_path,
    scan_log,
)
from logscan_web.recommendations import (
    DISCORD_GUIDANCE,
    DOCUMENTATION_URLS,
    RULES,
    _actionable_schema_errors,
    _schema_failure_guidance,
    _schema_path,
    _unexpected_properties,
    has_yaml_language_server_directive,
    schema_branch_for_log,
    validate_redacted_config,
)
from logscan_web.storage import AnonymousAnalyticsStore, PeopleStore, UsageStatsStore


class Response:
    def __init__(self, payload, content_type="application/json"):
        self.payload = payload.encode("utf-8") if isinstance(payload, str) else json.dumps(payload).encode("utf-8")
        self.headers = {"Content-Type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


def fake_urlopen(request, timeout=0):
    url = request.full_url
    if "raw.githubusercontent.com" in url:
        readme = "* [Completed Person](https://example.test/completed.jpg)\n" if "People-Images/refs" in url else ""
        return Response(readme, "text/plain")
    if "/person/1?" in url:
        return Response({"id": 1, "name": "Alice Person", "profile_path": "/alice.jpg", "known_for_department": "Acting"})
    if "/person/3?" in url:
        return Response({"id": 3, "name": "Bob Person", "profile_path": "/bob.jpg", "known_for_department": "Directing"})
    if "/person/5?" in url:
        return Response({"id": 5, "name": "Blocked Person", "profile_path": None, "known_for_department": "Acting"})
    if "/person/6?" in url:
        return Response({"id": 6, "name": "Hikaru Kondo", "profile_path": "/hikaru.jpg", "known_for_department": "Acting"})
    if "/person/7?" in url:
        return Response({"id": 7, "name": "Hikaru", "profile_path": "/other-hikaru.jpg", "known_for_department": "Acting"})
    raise AssertionError(f"Unexpected URL: {url}")


class MissingPeopleExtractionTests(unittest.TestCase):
    def test_pending_recommendation_links_to_filtered_people_queue(self):
        result = SimpleNamespace(
            recommendations=[],
            metadata={"counts": {"advice": 0}},
            overview={"recommendation_count": 0},
        )
        people_url = "https://logscan.example/people?tags=Missing+Kometa&tags=Requested+by+User"
        add_missing_people_recommendations(
            result,
            [{"name": "Hikaru Kondô", "tmdb_image_found": True}],
            {},
            people_url,
        )
        self.assertIn(people_url, result.recommendations[0]["solution"])

    def test_repository_filename_is_fully_url_decoded(self):
        content = (
            "Collection Warning: No Poster Found at "
            "https://raw.githubusercontent.com/Kometa-Team/People-Images/master/"
            "Hikaru%20Kond%C3%B4.jpg\n"
        )
        self.assertEqual(extract_missing_people(content), [
            {"name": "Hikaru Kondô", "tmdb_image_found": False},
        ])


class UploadLimitTests(unittest.TestCase):
    def test_extracted_log_limit_is_one_gibibyte_and_visible(self):
        self.assertEqual(MAX_FILE_BYTES, 1024 ** 3)
        html = app.test_client().get("/").get_data(as_text=True)
        self.assertIn("1 GB max after extraction", html)


class StreamingScanTests(unittest.TestCase):
    def test_spooled_validation_streams_identity_without_running_full_scan(self):
        marker = b"[kometa.py:1] [INFO] | Version: 2.5.0 |\n"
        with tempfile.NamedTemporaryFile(delete=False) as upload:
            upload.write(b"x" * (1024 * 1024 - 8))
            upload.write(marker)
            path = Path(upload.name)
        try:
            with patch("logscan_web.scanner.scan_log", side_effect=AssertionError("full scan should not run")):
                self.assertEqual(
                    find_scannable_upload_path("meta.log", path),
                    [("meta.log", path.stat().st_size)],
                )
        finally:
            path.unlink(missing_ok=True)

    def test_spooled_validation_scans_gzip_upload(self):
        content = b"[kometa.py:1] [INFO] | Version: 2.5.0 |\n"
        with tempfile.NamedTemporaryFile(delete=False) as upload:
            upload.write(gzip.compress(content))
            path = Path(upload.name)
        try:
            self.assertEqual(
                find_scannable_upload_path("meta.log.gz", path),
                [("meta.log", len(content))],
            )
        finally:
            path.unlink(missing_ok=True)

    def test_spooled_validation_scans_standalone_compression_formats(self):
        content = b"[kometa.py:1] [INFO] | Version: 2.5.0 |\n"
        formats = {
            "meta.log.bz2": bz2.compress(content),
            "meta.log.xz": lzma.compress(content),
            "meta.log.zst": zstd.ZstdCompressor().compress(content),
        }
        for filename, compressed in formats.items():
            with (
                self.subTest(filename=filename),
                tempfile.NamedTemporaryFile(delete=False) as upload,
            ):
                upload.write(compressed)
                path = Path(upload.name)
            try:
                self.assertEqual(
                    find_scannable_upload_path(filename, path),
                    [("meta.log", len(content))],
                )
                self.assertEqual(scan_log(filename, compressed).filename, "meta.log.log")
            finally:
                path.unlink(missing_ok=True)

    def test_spooled_validation_scans_all_compressed_tar_formats(self):
        content = b"[kometa.py:1] [INFO] | Version: 2.5.0 |\n"
        raw_tar = BytesIO()
        with tarfile.open(fileobj=raw_tar, mode="w") as archive:
            entry = tarfile.TarInfo("meta.log")
            entry.size = len(content)
            archive.addfile(entry, BytesIO(content))
        tar_content = raw_tar.getvalue()
        formats = {
            "logs.tar.gz": gzip.compress(tar_content),
            "logs.tgz": gzip.compress(tar_content),
            "logs.tar.bz2": bz2.compress(tar_content),
            "logs.tbz2": bz2.compress(tar_content),
            "logs.tar.xz": lzma.compress(tar_content),
            "logs.txz": lzma.compress(tar_content),
            "logs.tar.zst": zstd.ZstdCompressor().compress(tar_content),
        }
        for filename, compressed in formats.items():
            with (
                self.subTest(filename=filename),
                tempfile.NamedTemporaryFile(delete=False) as upload,
            ):
                upload.write(compressed)
                path = Path(upload.name)
            try:
                self.assertEqual(
                    find_scannable_upload_path(filename, path),
                    [("meta.log", len(content))],
                )
                self.assertTrue(
                    scan_log(filename, compressed).filename.endswith(".log")
                )
            finally:
                path.unlink(missing_ok=True)

    def test_spooled_validation_scans_7z_upload(self):
        content = b"[kometa.py:1] [INFO] | Version: 2.5.0 |\n"
        with tempfile.NamedTemporaryFile(suffix=".7z", delete=False) as upload:
            path = Path(upload.name)
        try:
            with py7zr.SevenZipFile(path, mode="w") as archive:
                archive.writestr(content, "meta.log")
            self.assertEqual(
                find_scannable_upload_path("meta.7z", path),
                [("meta.log", len(content))],
            )
        finally:
            path.unlink(missing_ok=True)
    def test_stored_log_viewer_returns_bounded_line_windows(self):
        lines = [
            "[kometa.py:1] [INFO] | Version: 2.5.0 |",
            *[f"[kometa.py:{number}] [INFO] | line {number} |" for number in range(2, 2502)],
        ]
        content = "\n".join(lines).encode()
        response = app.test_client().post(
            "/api/scan",
            data={"log": (BytesIO(content), "large-meta.log")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        scan_id = response.get_json()["id"]

        page = app.test_client().get(f"/api/scans/{scan_id}/log?start=1200&count=25")
        self.assertEqual(page.status_code, 200)
        payload = page.get_json()
        self.assertEqual(payload["start"], 1200)
        self.assertEqual(payload["total"], len(lines))
        self.assertEqual(len(payload["lines"]), 25)
        self.assertIn("line 1200", payload["lines"][0])

        download = app.test_client().get(f"/api/scans/{scan_id}/log")
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.data, content)
        self.assertEqual(download.headers["Content-Disposition"], 'attachment; filename=large-meta.log')
    def test_frontend_renders_anonymous_jobs_inline_and_follows_authenticated_redirects(self):
        script = Path("logscan_web/static/app.js").read_text(encoding="utf-8")
        self.assertIn("function renderCompletedJob(result)", script)
        self.assertIn("renderCompletedJob(job.result)", script)
        self.assertIn("location.assign(job.redirect_url)", script)

    def test_web_upload_reports_live_job_status_and_private_result(self):
        job_id = "12345678-1234-1234-1234-123456789abc"
        response = app.test_client().post(
            "/api/scan",
            data={"log": (BytesIO(b"[kometa.py:1] [WARNING] | timed out.\n"), "meta.log")},
            content_type="multipart/form-data",
            headers={"X-Scan-Job-ID": job_id},
        )
        self.assertEqual(response.status_code, 202)

        deadline = time.monotonic() + 5
        while True:
            status = app.test_client().get(f"/api/scan-jobs/{job_id}")
            self.assertEqual(status.status_code, 200)
            payload = status.get_json()
            if payload["phase"] in {"complete", "failed"}:
                break
            if time.monotonic() >= deadline:
                self.fail(f"Background scan did not finish: {payload}")
            time.sleep(0.01)
        self.assertEqual(payload["phase"], "complete")
        self.assertGreaterEqual(payload["elapsed_seconds"], 0)
        self.assertNotIn("redirect_url", payload)
        self.assertEqual(payload["result"]["filename"], "meta.log")
        self.assertIn("delete_token", payload["result"])

    def test_signed_in_web_upload_preserves_verified_identity_through_background_scan(self):
        client = app.test_client()
        with client.session_transaction() as discord_session:
            discord_session["support_authorized_at"] = 9999999999
            discord_session["support_access"] = False
            discord_session["discord_user"] = {
                "id": "web-user-42",
                "username": "Web User",
                "avatar": "",
            }
        job_id = "signed-in-web-background-123456"
        response = client.post(
            "/api/scan",
            data={"log": (BytesIO(b"[kometa.py:1] [WARNING] | timed out.\n"), "signed-in.log")},
            content_type="multipart/form-data",
            headers={"X-Scan-Job-ID": job_id},
        )
        self.assertEqual(response.status_code, 202)
        deadline = time.monotonic() + 5
        while True:
            payload = client.get(f"/api/scan-jobs/{job_id}").get_json()
            if payload["phase"] in {"complete", "failed"}:
                break
            if time.monotonic() >= deadline:
                self.fail(f"Signed-in background scan did not finish: {payload}")
            time.sleep(0.01)
        self.assertEqual(payload["phase"], "complete", payload)
        self.assertRegex(payload["redirect_url"], r"^http://localhost/scan/[^#]+#delete=.+$")
        self.assertNotIn("result", payload)
        records = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in Path(STORE.name).glob("*/result.json")
        ]
        record = next(record for record in records if record["filename"] == "signed-in.log")
        self.assertEqual(record["overview"]["uploaded_by"], "Web User")
        self.assertEqual(record["overview"]["uploaded_by_id"], "web-user-42")
        self.assertEqual(record["overview"]["upload_source"], "web")
        self.assertIsNone(record["overview"]["message_url"])
        script = Path("logscan_web/static/app.js").read_text(encoding="utf-8")
        self.assertIn("if (value.messageUrl)", script)
        self.assertIn('["discord.com", "www.discord.com"].includes(messageUrl.hostname)', script)

    def test_direct_scan_link_shows_authentication_state_and_returns_after_sign_in(self):
        client = app.test_client()
        upload = client.post(
            "/api/scan",
            data={"log": (BytesIO(b"[kometa.py:1] [WARNING] | timed out.\n"), "direct-link.log")},
            content_type="multipart/form-data",
        ).get_json()
        path = f"/scan/{upload['id']}"
        anonymous = client.get(path).get_data(as_text=True)
        self.assertIn("Viewing anonymously", anonymous)
        self.assertIn(f"/support/authorize?next={path}", anonymous)

        with client.session_transaction() as discord_session:
            discord_session["support_authorized_at"] = 9999999999
            discord_session["support_access"] = False
            discord_session["discord_user"] = {
                "id": "viewer-42",
                "username": "Discord Viewer",
                "avatar": "https://cdn.example/viewer.png",
            }
        authenticated = client.get(path).get_data(as_text=True)
        self.assertIn("Signed in as", authenticated)
        self.assertIn("Discord Viewer", authenticated)
        self.assertIn('src="https://cdn.example/viewer.png"', authenticated)
        self.assertIn("My uploads", authenticated)

    def test_direct_batch_link_shows_authentication_state_and_my_uploads(self):
        client = app.test_client()
        upload = client.post(
            "/api/scan",
            data={
                "log": [
                    (BytesIO(b"[kometa.py:1] [WARNING] | first timed out.\n"), "batch-first.log"),
                    (BytesIO(b"[kometa.py:1] [WARNING] | second timed out.\n"), "batch-second.log"),
                ],
            },
            content_type="multipart/form-data",
        ).get_json()
        path = upload["batch_result_url"].replace("http://localhost", "")
        anonymous = client.get(path).get_data(as_text=True)
        self.assertIn("Batch complete", anonymous)
        self.assertIn("Viewing anonymously", anonymous)
        self.assertIn(f"/support/authorize?next={path}", anonymous)

        with client.session_transaction() as discord_session:
            discord_session["support_authorized_at"] = 9999999999
            discord_session["support_access"] = False
            discord_session["discord_user"] = {
                "id": "batch-viewer-42",
                "username": "Batch Viewer",
                "avatar": "https://cdn.example/batch-viewer.png",
            }
        authenticated = client.get(path).get_data(as_text=True)
        self.assertIn("Signed in as", authenticated)
        self.assertIn("Batch Viewer", authenticated)
        self.assertIn('src="https://cdn.example/batch-viewer.png"', authenticated)
        self.assertIn("My uploads", authenticated)

    def test_bot_upload_runs_in_background_and_preserves_requester(self):
        job_id = "discord-background-123456789012"
        previous_key = app.config["LOGSCAN_API_KEY"]
        app.config["LOGSCAN_API_KEY"] = "test-secret"
        try:
            response = app.test_client().post(
                "/api/bot/scan",
                data={
                    "log": (BytesIO(b"[kometa.py:1] [WARNING] | timed out.\n"), "discord.log"),
                    "uploaded_by": "ExampleUser",
                    "uploaded_by_id": "12345",
                    "source_url": "https://discord.com/channels/1/2/3",
                },
                content_type="multipart/form-data",
                headers={
                    "Authorization": "Bearer test-secret",
                    "X-Scan-Job-ID": job_id,
                },
            )
            self.assertEqual(response.status_code, 202)

            deadline = time.monotonic() + 5
            while True:
                payload = app.test_client().get(f"/api/scan-jobs/{job_id}").get_json()
                if payload["phase"] in {"complete", "failed"}:
                    break
                if time.monotonic() >= deadline:
                    self.fail(f"Discord background scan did not finish: {payload}")
                time.sleep(0.01)
            self.assertEqual(payload["phase"], "complete")
            self.assertIn("result", payload)
            scan = payload["result"]["scans"][0]
            self.assertEqual(scan["overview"]["uploaded_by"], "ExampleUser")
            self.assertEqual(scan["overview"]["uploaded_by_id"], "12345")
            self.assertIn("delete_token", scan)
        finally:
            app.config["LOGSCAN_API_KEY"] = previous_key

    def test_bot_validation_waits_behind_active_scan(self):
        started = threading.Event()
        release = threading.Event()
        original_scan_archive_logs = scan_archive_logs

        def blocked_scan(*args, **kwargs):
            started.set()
            release.wait(timeout=5)
            return original_scan_archive_logs(*args, **kwargs)

        scan_job = "active-scan-before-validation-1234"
        validation_job = "queued-validation-after-scan-12"
        previous_key = app.config["LOGSCAN_API_KEY"]
        app.config["LOGSCAN_API_KEY"] = "test-secret"
        try:
            with patch("logscan_web.app.scan_archive_logs", side_effect=blocked_scan):
                scan_response = app.test_client().post(
                    "/api/scan",
                    data={"log": (BytesIO(b"[kometa.py:1] [WARNING] | timed out.\n"), "active.log")},
                    content_type="multipart/form-data",
                    headers={"X-Scan-Job-ID": scan_job},
                )
                self.assertEqual(scan_response.status_code, 202)
                self.assertTrue(started.wait(timeout=2))
                validation_response = app.test_client().post(
                    "/api/bot/validate",
                    data={"log": (BytesIO(b"[kometa.py:1] [WARNING] | timed out.\n"), "waiting.log")},
                    content_type="multipart/form-data",
                    headers={
                        "Authorization": "Bearer test-secret",
                        "X-Scan-Job-ID": validation_job,
                    },
                )
                self.assertEqual(validation_response.status_code, 202)
                queued = app.test_client().get(f"/api/scan-jobs/{validation_job}").get_json()
                self.assertEqual(queued["phase"], "queued")
                self.assertEqual(queued["queue_position"], 2)
                self.assertEqual(queued["ahead_count"], 1)
                release.set()

                deadline = time.monotonic() + 5
                while app.test_client().get(f"/api/scan-jobs/{validation_job}").get_json()["phase"] != "complete":
                    if time.monotonic() >= deadline:
                        self.fail("Queued validation did not complete")
                    time.sleep(0.01)
        finally:
            release.set()
            app.config["LOGSCAN_API_KEY"] = previous_key

    def test_bot_validation_runs_through_background_queue(self):
        job_id = "discord-validation-123456789012"
        previous_key = app.config["LOGSCAN_API_KEY"]
        app.config["LOGSCAN_API_KEY"] = "test-secret"
        try:
            response = app.test_client().post(
                "/api/bot/validate",
                data={"log": (BytesIO(b"[kometa.py:1] [WARNING] | timed out.\n"), "validate.log")},
                content_type="multipart/form-data",
                headers={
                    "Authorization": "Bearer test-secret",
                    "X-Scan-Job-ID": job_id,
                },
            )
            self.assertEqual(response.status_code, 202)

            deadline = time.monotonic() + 5
            seen_phases = set()
            while True:
                payload = app.test_client().get(f"/api/scan-jobs/{job_id}").get_json()
                seen_phases.add(payload["phase"])
                if payload["phase"] in {"complete", "failed"}:
                    break
                if time.monotonic() >= deadline:
                    self.fail(f"Discord validation did not finish: {payload}")
                time.sleep(0.01)
            self.assertEqual(payload["phase"], "complete")
            self.assertEqual(payload["result"]["files"][0]["filename"], "validate.log")
            self.assertGreater(payload["result"]["files"][0]["content_size"], 0)
            self.assertTrue(seen_phases & {"queued", "validating"})
        finally:
            app.config["LOGSCAN_API_KEY"] = previous_key

    def test_queued_web_scan_reports_position_and_ahead_count(self):
        started = threading.Event()
        release = threading.Event()
        original_scan_archive_logs = scan_archive_logs
        first_call = True

        def controlled_scan(*args, **kwargs):
            nonlocal first_call
            if first_call:
                first_call = False
                started.set()
                release.wait(timeout=5)
            return original_scan_archive_logs(*args, **kwargs)

        first_job = "queue-position-first-123456789"
        second_job = "queue-position-second-12345678"
        with patch("logscan_web.app.scan_archive_logs", side_effect=controlled_scan):
            first = app.test_client().post(
                "/api/scan",
                data={"log": (BytesIO(b"[kometa.py:1] [WARNING] | timed out.\n"), "first.log")},
                content_type="multipart/form-data",
                headers={"X-Scan-Job-ID": first_job},
            )
            self.assertEqual(first.status_code, 202)
            self.assertTrue(started.wait(timeout=2))
            second = app.test_client().post(
                "/api/scan",
                data={"log": (BytesIO(b"[kometa.py:1] [WARNING] | timed out.\n"), "second.log")},
                content_type="multipart/form-data",
                headers={"X-Scan-Job-ID": second_job},
            )
            self.assertEqual(second.status_code, 202)
            queued = app.test_client().get(f"/api/scan-jobs/{second_job}").get_json()
            self.assertEqual(queued["phase"], "queued")
            self.assertEqual(queued["queue_position"], 2)
            self.assertEqual(queued["ahead_count"], 1)
            release.set()

            deadline = time.monotonic() + 5
            while app.test_client().get(f"/api/scan-jobs/{second_job}").get_json()["phase"] != "complete":
                if time.monotonic() >= deadline:
                    self.fail("Queued scan did not complete")
                time.sleep(0.01)

    def test_disk_backed_http_upload_persists_before_removing_temporary_file(self):
        content = b"[kometa.py:1] [WARNING] | timed out.\n"
        archive_bytes = BytesIO()
        with zipfile.ZipFile(archive_bytes, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("meta.log", content)
        with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
            response = app.test_client().post(
                "/api/scan",
                data={"log": (BytesIO(archive_bytes.getvalue()), "meta.zip")},
                content_type="multipart/form-data",
            )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(Path(STORE.name, payload["id"], "log").is_file())
    def test_disk_backed_gzip_scan_matches_regular_scan(self):
        content = "\n".join([
            "[kometa.py:1] [INFO] | Version: 2.4.8-build21 (Branch: nightly) |",
            "[kometa.py:2] [WARNING] | timed out.",
        ]).encode()
        expected = scan_log("meta.log.log", content)
        with tempfile.NamedTemporaryFile(suffix=".gz", delete=False) as upload:
            upload.write(gzip.compress(content))
            upload_path = Path(upload.name)
        scans = []
        try:
            with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
                scans = scan_archive_path("meta.log.gz", upload_path)
            self.assertEqual(len(scans), 1)
            self.assertIsInstance(scans[0][1], Path)
            self.assertEqual(scans[0][2].recommendations, expected.recommendations)
            self.assertEqual(scans[0][2].metadata["line_count"], 2)
        finally:
            upload_path.unlink(missing_ok=True)
            for _name, scan_content, _result in scans:
                if isinstance(scan_content, Path):
                    scan_content.unlink(missing_ok=True)
    def test_disk_backed_zip_scan_matches_regular_scan(self):
        content = "\n".join([
            "[kometa.py:1] [INFO] | Version: 2.4.8-build21 (Branch: nightly) |",
            "[kometa.py:2] [WARNING] | timed out.",
            "[Quickstart] Run marker: quickstart=0.10.6-build7 branch=develop",
            "[Quickstart] Metadata Start",
            "[Quickstart] version=0.10.6-build7 branch=develop mode=managed flags=--run,--read-only",
            "[Quickstart] platform=Linux launcher=compose",
            "[Quickstart] Metadata End",
        ]).encode()
        expected = scan_log("meta.log", content)
        archive_bytes = BytesIO()
        with zipfile.ZipFile(archive_bytes, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("meta.log", content)

        with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
            scans = scan_archive_logs("meta.zip", archive_bytes.getvalue())
        self.assertEqual(len(scans), 1)
        _filename, disk_content, actual = scans[0]
        try:
            self.assertIsInstance(disk_content, Path)
            self.assertEqual(actual.recommendations, expected.recommendations)
            self.assertEqual(actual.metadata, expected.metadata)
            self.assertEqual(actual.missing_people, expected.missing_people)
        finally:
            disk_content.unlink(missing_ok=True)

    def test_disk_backed_scan_preserves_plex_configuration_sections(self):
        content = "\n".join([
            "[kometa.py:1] [INFO] | Version: 2.4.8-build21 (Branch: nightly) |",
            "[config.py:2] [INFO] | Plex Configuration |",
            "[config.py:3] [INFO] | Connected to server NZWHS01 version 1.31.2.6810-a607d384f |",
            "[config.py:4] [INFO] | Connected to library TestMovies |",
            "[config.py:5] [INFO] | Library Connection Successful |",
            "[builder.py:6] [INFO] | Type: imdb_awards |",
            "[kometa.py:6] [INFO] | Finished Unrelated Collection Run Time: 0:12:34 |",
            "[builder.py:7] [INFO] | Scanning Metadata and Images |",
            "[config.py:8] [INFO] | Run Order: operations |",
        ]).encode()
        archive_bytes = BytesIO()
        with zipfile.ZipFile(archive_bytes, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("meta.log", content)

        with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
            scans = scan_archive_logs("meta.zip", archive_bytes.getvalue())
        _filename, disk_content, result = scans[0]
        try:
            sections = result.overview["plex_configurations"]
            self.assertEqual(len(sections), 1)
            self.assertIn("Connected to library TestMovies", sections[0]["lines"])
            self.assertNotIn("Run Order: operations", sections[0]["lines"])
            self.assertNotIn("Finished Unrelated Collection Run Time: 0:12:34", sections[0]["lines"])
            self.assertNotIn("Type: imdb_awards", sections[0]["lines"])
        finally:
            disk_content.unlink(missing_ok=True)

    def test_large_log_threshold_and_runtime_results_match_regular_scan(self):
        self.assertEqual(STREAM_SCAN_THRESHOLD, 64 * 1024 * 1024)
        lines = [
            "[2026-09-26 22:17:45,061] [kometa.py:1] [INFO] | Version: 2.5.1 (Branch: master) |",
            "[2026-09-26 22:17:45,061] [plex.py:2] [INFO] | Scheduled maintenance running between 2:00 and 5:00 |",
        ]
        lines.extend(
            f"[2026-09-27 01:{index % 60:02d}:00,000] [kometa.py:{index + 3}] [INFO] | Finished Section {index:03d} Run Time: 0:00:01 |"
            for index in range(225)
        )
        lines.extend([
            "[2026-09-27 05:00:17,563] [kometa.py:300] [INFO] | Finished People's Choice Awards 2008 Collection |",
            "[2026-09-27 05:00:17,563] [kometa.py:300] [INFO] | Collection Run Time: 3:00:17 |",
        ])
        archive_bytes = BytesIO()
        with zipfile.ZipFile(archive_bytes, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("meta.log", "\n".join(lines).encode())

        with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", MAX_FILE_BYTES):
            regular_scans = scan_archive_logs("meta.zip", archive_bytes.getvalue())
        with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
            large_scans = scan_archive_logs("meta.zip", archive_bytes.getvalue())
        _regular_name, regular_content, regular_result = regular_scans[0]
        _large_name, large_content, large_result = large_scans[0]
        try:
            self.assertEqual(
                large_result.overview["section_run_times"],
                regular_result.overview["section_run_times"],
            )
            self.assertEqual(len(large_result.overview["section_run_times"]), 226)
            self.assertEqual(large_result.overview["section_run_times"][0]["duration"], "0:00:17")
        finally:
            if isinstance(regular_content, Path):
                regular_content.unlink(missing_ok=True)
            if isinstance(large_content, Path):
                large_content.unlink(missing_ok=True)

    def test_large_log_findings_keep_every_evidence_occurrence(self):
        lines = [
            "[kometa.py:1] [INFO] | Version: 2.5.1 (Branch: master) |",
            "[config.py:2] [WARNING] | Service request timed out. |",
            "[config.py:3] [WARNING] | Service request timed out. |",
            "[config.py:4] [INFO] | unrelated line |",
            "[config.py:5] [WARNING] | Service request timed out. |",
            "[kometa.py:6] [INFO] | Finished: 2026-10-02 12:00:00 Run Time: 0:00:05 |",
        ]
        archive_bytes = BytesIO()
        with zipfile.ZipFile(archive_bytes, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("meta.log", "\n".join(lines).encode())

        with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", MAX_FILE_BYTES):
            regular_scans = scan_archive_logs("meta.zip", archive_bytes.getvalue())
        with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
            large_scans = scan_archive_logs("meta.zip", archive_bytes.getvalue())
        _regular_name, regular_content, regular_result = regular_scans[0]
        _large_name, large_content, large_result = large_scans[0]
        try:
            regular = next(item for item in regular_result.recommendations if item["id"] == "timeout")
            large = next(item for item in large_result.recommendations if item["id"] == "timeout")
            self.assertEqual(regular["evidence_lines"], [2, 3, 5])
            self.assertEqual(large["evidence_lines"], regular["evidence_lines"])
            warning = next(item for item in large_result.recommendations if item["id"] == "kometa_warning")
            self.assertEqual(warning["evidence_lines"], [2, 3, 5])
        finally:
            if isinstance(regular_content, Path):
                regular_content.unlink(missing_ok=True)
            if isinstance(large_content, Path):
                large_content.unlink(missing_ok=True)

    def test_disk_backed_scan_keeps_all_runtimes_and_adjusts_late_maintenance_section(self):
        lines = [
            "[2026-09-29 00:00:00,000] [kometa.py:1] [INFO] | Version: 2.5.1 (Branch: master) |",
            "[2026-09-29 01:56:00,000] [config.py:2] [INFO] | Scheduled maintenance running between 02:00 and 05:00 |",
        ]
        lines.extend(
            f"[2026-09-29 01:{index % 60:02d}:00,000] [kometa.py:{index + 3}] [INFO] | Finished Section {index:03d} Run Time: 0:00:01 |"
            for index in range(225)
        )
        lines.extend([
            "[2026-09-29 02:00:05,000] [kometa.py:300] [CRITICAL] | Plex Critical Error: Response 503 (service_unavailable) received during maintenance. |",
            "[2026-09-29 05:04:00,000] [kometa.py:301] [INFO] | Finished People's Choice Awards Run Time: 3:08:00 |",
        ])
        archive_bytes = BytesIO()
        with zipfile.ZipFile(archive_bytes, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("meta.log", "\n".join(lines).encode())

        with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
            scans = scan_archive_logs("meta.zip", archive_bytes.getvalue())
        _filename, disk_content, result = scans[0]
        try:
            runtimes = result.overview["section_run_times"]
            self.assertEqual(len(runtimes), 226)
            self.assertEqual(runtimes[0]["name"], "People's Choice Awards")
            self.assertEqual(runtimes[0]["duration"], "0:08:00")
            self.assertEqual(runtimes[-1]["duration"], "0:00:01")
        finally:
            disk_content.unlink(missing_ok=True)

class RuntimeMetadataTests(unittest.TestCase):
    def test_section_run_times_are_sorted_and_zero_values_are_excluded(self):
        prefix = "[kometa.py:1] [INFO] |"
        content = "\n".join([
            f"{prefix} Finished Collections |",
            f"{prefix} Run Time: 0:03:00 |",
            f"{prefix} Finished Zero Work |",
            f"{prefix} Run Time: 0:00:00 |",
            f"{prefix} Finished Metadata Run Time: 0:12:30 |",
            f"{prefix} Finished Overlays |",
            f"{prefix} Run Time: 1:02:03 |",
        ])

        runtimes = extract_section_run_times(content)

        self.assertEqual(
            [(item["name"], item["duration"], item["line"]) for item in runtimes],
            [
                ("Overlays", "1:02:03", 6),
                ("Metadata", "0:12:30", 5),
                ("Collections", "0:03:00", 1),
            ],
        )

    def test_section_run_time_excludes_confirmed_plex_maintenance_overlap(self):
        content = "\n".join([
            "[2026-09-29 01:56:00,000] [config.py:1] [INFO] | Scheduled maintenance running between 02:00 and 05:00 |",
            "[2026-09-29 02:00:05,000] [kometa.py:2] [CRITICAL] | Plex Critical Error: Response 503 (service_unavailable) received. Plex may be running startup or maintenance tasks. |",
            "[2026-09-29 05:04:00,000] [kometa.py:3] [INFO] | Finished People's Choice Awards Run Time: 3:08:00 |",
        ])

        runtimes = extract_section_run_times(content)

        self.assertEqual(len(runtimes), 1)
        self.assertEqual(runtimes[0]["name"], "People's Choice Awards")
        self.assertEqual(runtimes[0]["duration"], "0:08:00")
        self.assertEqual(runtimes[0]["seconds"], 480)
        self.assertEqual(runtimes[0]["reported_duration"], "3:08:00")

    def test_section_run_time_handles_silent_plex_maintenance(self):
        content = "\n".join([
            "[2026-09-29 01:56:00,000] [config.py:1] [INFO] | Scheduled maintenance running between 02:00 and 05:00 |",
            "[2026-09-29 05:04:00,000] [kometa.py:2] [INFO] | Finished People's Choice Awards Run Time: 3:08:00 |",
        ])

        runtimes = extract_section_run_times(content)

        self.assertEqual(runtimes[0]["duration"], "0:08:00")
        self.assertEqual(runtimes[0]["reported_duration"], "3:08:00")

    def test_section_run_time_matches_silent_production_maintenance_gap(self):
        content = "\n".join([
            "[2026-09-26 22:17:45,061] [plex.py:871] [INFO] | Scheduled maintenance running between 2:00 and 5:00 |",
            "[2026-09-27 05:00:17,563] [kometa.py:1470] [INFO] | Finished People's Choice Awards 2008 Collection |",
            "[2026-09-27 05:00:17,563] [kometa.py:1470] [INFO] | Collection Run Time: 3:00:17 |",
        ])

        runtimes = extract_section_run_times(content)

        self.assertEqual(runtimes[0]["duration"], "0:00:17")
        self.assertEqual(runtimes[0]["seconds"], 17)
        self.assertEqual(runtimes[0]["reported_duration"], "3:00:17")

    def test_section_run_time_outside_maintenance_is_unchanged(self):
        content = "\n".join([
            "[2026-09-29 01:00:00,000] [config.py:1] [INFO] | Scheduled maintenance running between 02:00 and 05:00 |",
            "[2026-09-29 06:08:00,000] [kometa.py:2] [INFO] | Finished Morning Collection Run Time: 0:08:00 |",
        ])

        runtimes = extract_section_run_times(content)

        self.assertEqual(runtimes[0]["duration"], "0:08:00")
        self.assertNotIn("reported_duration", runtimes[0])
    def test_section_run_time_handles_overnight_maintenance_window(self):
        content = "\n".join([
            "[2026-09-29 22:56:00,000] [config.py:1] [INFO] | Scheduled maintenance running between 23:00 and 02:00 |",
            "[2026-09-29 23:00:05,000] [kometa.py:2] [CRITICAL] | Plex Critical Error: Response 503 (service_unavailable) received during maintenance. |",
            "[2026-09-30 02:04:00,000] [kometa.py:3] [INFO] | Finished Overnight Collection Run Time: 3:08:00 |",
        ])

        runtimes = extract_section_run_times(content)

        self.assertEqual(runtimes[0]["duration"], "0:08:00")
        self.assertEqual(runtimes[0]["seconds"], 480)
    def test_severity_dots_use_the_semantic_color_scale(self):
        css = Path("logscan_web/static/styles.css").read_text(encoding="utf-8")
        expected = {
            "critical": "#f43f5e",
            "error": "#fb923c",
            "warning": "#fbbf24",
            "schema": "#a78bfa",
            "advice": "#60a5fa",
        }

        for severity, color in expected.items():
            with self.subTest(severity=severity):
                self.assertIn(f"--{severity}: {color};", css)
                self.assertIn(f".{severity} .severity-dot {{ color: var(--{severity});", css)

    def test_wsl_runtime_finding_includes_actionable_configuration(self):
        content = "\n".join([
            "[kometa.py:1] [INFO] | Version: 2.3.1-build24 (Branch: master) |",
            "[kometa.py:2] [INFO] | Platform: Linux-5.15.0-microsoft-standard-WSL2 |",
            "[kometa.py:3] [INFO] | Memory: 6 GB |",
        ])

        result = scan_log("meta.log", content.encode())
        finding = next(item for item in result.recommendations if item["id"] == "wsl_memory")

        self.assertIn("%UserProfile%\\.wslconfig", finding["message"])
        self.assertIn("`memory=8GB`", finding["message"])
        self.assertIn("`wsl --shutdown`", finding["message"])
        self.assertIn("https://learn.microsoft.com/windows/wsl/wsl-config", finding["message"])
        self.assertNotIn("wsl --set-memory", finding["message"])

    def test_runtime_findings_include_detected_values_and_maintenance_context(self):
        content = "\n".join([
            "[kometa.py:1] [INFO] | Version: 2.3.1-build24 (Branch: master) |",
            "[kometa.py:2] [INFO] | Memory: 3.50 GB |",
            "[config.py:3] [INFO] | overlay_files: |",
            "[config.py:4] [INFO] | Plex DB cache setting: 4096 MB |",
            "[kometa.py:5] [INFO] | --time (KOMETA_TIME): 01:00 |",
            "[config.py:6] [INFO] | Scheduled maintenance running between 02:00 and 05:00 |",
            "[kometa.py:7] [INFO] | Finished: now Run Time: 1 days, 01:00:00 |",
        ])

        result = scan_log("meta.log", content.encode())
        findings = {item["id"]: item for item in result.recommendations}

        self.assertIn("3.50 GB", findings["memory_overlay_insufficient"]["message"])
        self.assertIn("4.00 GB", findings["db_cache_exceeds_memory"]["message"])
        schedule = findings["schedule_over_24_hours"]["message"]
        self.assertIn("01:00", schedule)
        self.assertIn("02:00-05:00", schedule)
        self.assertIn("support.plex.tv/articles/202197488", schedule)

    def test_schedule_conflict_prescribes_maintenance_end_and_plex_settings(self):
        content = "\n".join([
            "[kometa.py:1] [INFO] | Version: 2.3.1-build24 (Branch: master) |",
            "[kometa.py:2] [INFO] | --time (KOMETA_TIME): 02:45 |",
            "[config.py:3] [INFO] | Scheduled maintenance running between 02:00 and 05:00 |",
            "[kometa.py:4] [INFO] | Finished: now Run Time: 20:03:44 |",
        ])

        result = scan_log("meta.log", content.encode())
        finding = next(item for item in result.recommendations if item["id"] == "schedule_conflict")
        message = finding["message"]

        self.assertIn("Recommended Kometa start: **5:00**", message)
        self.assertIn("Set Kometa to run at **5:00**", message)
        self.assertIn("Settings > Server > Scheduled Tasks", message)
        self.assertIn("Plex server defaults are **2:00 AM-5:00 AM**", message)
        self.assertIn("Plex server's local time", message)
        self.assertIn("support.plex.tv/articles/201553286-scheduled-tasks", message)
    def test_rating_rounding_uses_its_own_plex_version_range(self):
        def recommendations_for(version):
            content = "\n".join([
                "[kometa.py:1] [INFO] | Version: 1.21.0 (Docker) |",
                f"[plex.py:2] [INFO] | Connected to server LPlex version {version} |",
                "[config.py:3] [INFO] | mass_user_rating_update: imdb |",
            ])
            return {item["id"] for item in scan_log("meta.log", content.encode()).recommendations}

        self.assertIn("rating_rounding", recommendations_for("1.40.2.8351-9938371be"))
        self.assertNotIn("rating_rounding", recommendations_for("1.40.0.7998-c29d4c0c8"))
        self.assertNotIn("rating_rounding", recommendations_for("1.40.3.8555-fef15d30c"))
        self.assertNotIn("rating_rounding", recommendations_for("1.41.7.0"))
    def test_wiki_links_follow_master_and_develop_without_nightly_urls(self):
        recommendation = {
            "solution": "See https://kometa.wiki/en/latest/config/anidb",
            "message": "Help: https://www.kometa.wiki/en/latest/config/anidb",
        }

        apply_documentation_branch([recommendation], "develop")
        self.assertIn("https://www.kometa.wiki/en/develop/config/anidb", recommendation["solution"])
        self.assertNotIn("/en/latest/", recommendation["message"])
        apply_documentation_branch([recommendation], "nightly")
        self.assertIn("https://www.kometa.wiki/en/develop/config/anidb", recommendation["solution"])
        self.assertNotIn("/en/nightly/", recommendation["solution"])

    def test_scanned_develop_log_uses_develop_wiki(self):
        content = "\n".join([
            "[kometa.py:1] [INFO] | Version: 2.3.1-build24 (Branch: develop) |",
            "[config.py:2] [ERROR] | AniDB Error: Login failed |",
        ])

        result = scan_log("meta.log", content.encode())
        finding = next(item for item in result.recommendations if item["id"] == "anidb_auth")

        self.assertIn("https://www.kometa.wiki/en/develop/config/anidb", finding["solution"])
        self.assertNotIn("/en/nightly/", finding["message"])

    def test_schema_validation_ignores_redacted_values_but_keeps_real_issues(self):
        schema = {
            "type": "object",
            "properties": {
                "token": {"type": "integer"},
                "timeout": {"type": "integer"},
            },
            "additionalProperties": False,
        }
        config = {"token": "(redacted)", "timeout": "slow", "typo": True}

        errors = _actionable_schema_errors(schema, config)

        self.assertFalse(any(list(error.absolute_path) == ["token"] for error in errors))
        self.assertEqual({error.validator for error in errors}, {"type", "additionalProperties"})

        type_error = next(error for error in errors if error.validator == "type")
        guidance = _schema_failure_guidance(type_error, _schema_path(type_error))
        self.assertEqual(guidance["title"], "Wrong value type at timeout")
        self.assertIn("expects integer", guidance["explanation"])
        self.assertIn("Change the value at timeout", guidance["action"])
        self.assertEqual(guidance["accepted"], "Expected value type: integer.")

        unknown_error = next(error for error in errors if error.validator == "additionalProperties")
        unknown_guidance = _schema_failure_guidance(unknown_error, "typo", "typo")
        self.assertEqual(unknown_guidance["title"], "Unknown setting: typo")
        self.assertIn("misspelled", unknown_guidance["explanation"])

    def test_schema_guidance_names_list_position_and_available_options(self):
        schema = {
            "type": "object",
            "properties": {
                "TV": {
                    "type": "object",
                    "properties": {
                        "overlay_path": {
                            "type": "array",
                            "items": {"enum": ["default", "git", "url"]},
                        },
                    },
                },
            },
        }
        config = {"TV": {"overlay_path": ["default", "git", "invalid"]}}
        error = next(iter(Draft7Validator(schema).iter_errors(config)))
        path = _schema_path(error)
        guidance = _schema_failure_guidance(error, path)

        self.assertEqual(path, "TV.overlay_path.2")
        self.assertEqual(guidance["location"], "the third item under TV > overlay_path")
        self.assertEqual(guidance["title"], "Unsupported value at the third item under TV > overlay_path")
        self.assertEqual(guidance["accepted"], "Available options: 'default', 'git', 'url'.")

    def test_schema_validation_prefers_specific_nested_composite_errors(self):
        schema = {
            "type": "array",
            "items": {
                "anyOf": [
                    {"type": "string"},
                    {
                        "type": "object",
                        "properties": {
                            "default": {"const": "seasonal"},
                            "template_variables": {
                                "type": "object",
                                "properties": {"sort_by": {"type": "string"}},
                                "additionalProperties": False,
                            },
                        },
                        "required": ["default"],
                    },
                ],
            },
        }
        config = [{"default": "seasonal", "template_variables": {"sort_by": "random", "use_christmas": True}}]

        errors = _actionable_schema_errors(schema, config)

        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].validator, "additionalProperties")
        self.assertEqual(list(errors[0].absolute_path), [0, "template_variables"])
        self.assertEqual(_unexpected_properties(errors[0]), ["use_christmas"])

    def test_schema_validation_returns_exact_invalid_key_range(self):
        schema = {
            "type": "object",
            "properties": {
                "template_variables": {
                    "type": "object",
                    "properties": {"sort_by": {"type": "string"}},
                    "additionalProperties": False,
                },
            },
        }
        log = "\n".join([
            "Redacted Config",
            "[config.py:1] [INFO] | template_variables: |",
            "[config.py:2] [INFO] |   sort_by: random |",
            "[config.py:3] [INFO] |   use_christmas: true |",
            "[config.py:4] [INFO] | end |",
            "Initializing cache database at /config/cache",
        ])

        with patch("logscan_web.recommendations.urlopen", return_value=Response(schema)):
            failures = validate_redacted_config(log)

        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["title"], "Unknown setting: use_christmas")
        self.assertEqual(failures[0]["config_line"], 3)
        self.assertEqual(failures[0]["config_column"], 3)
        self.assertEqual(failures[0]["config_end_column"], 16)

    def test_schema_validation_stops_before_post_config_error(self):
        schema = {"type": "object", "properties": {"plex": {"type": "object"}}}
        log = "\n".join([
            "Redacted Config",
            "[config.py:309] [DEBUG] | plex: |",
            "[config.py:309] [DEBUG] |   timeout: 60 |",
            "[config.py:316] [DEBUG] | |",
            "[config.py:509] [ERROR] | Trakt is no longer supported, please see Announcements |",
            "[cache.py:52] [INFO] | Initializing cache database at /config/config.cache |",
        ])

        with patch("logscan_web.recommendations.urlopen", return_value=Response(schema)):
            self.assertEqual(validate_redacted_config(log), [])

    def test_yaml_parser_failure_has_navigable_config_position(self):
        log = "\n".join([
            "Redacted Config",
            "[config.py:1] [INFO] | plex: |",
            "[config.py:2] [INFO] |   timeout: \"unterminated |",
            "[config.py:3] [INFO] | end |",
            "Initializing cache database at /config/cache",
        ])

        failure = validate_redacted_config(log)[0]

        self.assertGreaterEqual(failure["config_line"], 2)
        self.assertGreaterEqual(failure["config_column"], 1)
        self.assertTrue(failure["title"].startswith("Invalid YAML at line "))
        self.assertIn("Correct the highlighted YAML", failure["action"])

    def test_browser_config_extraction_stops_at_post_config_errors(self):
        script = Path("logscan_web/static/app.js").read_text(encoding="utf-8")

        self.assertIn('["CRITICAL", "ERROR", "WARNING"].includes(match[1])', script)
        self.assertIn("match[2].replace", script)
    def test_schema_validation_reuses_persistent_branch_cache(self):
        schema = {"type": "object", "properties": {}}
        log = "\n".join([
            "Redacted Config",
            "[config.py:1] [INFO] | {} |",
            "Initializing cache database at /config/cache",
        ])
        with tempfile.TemporaryDirectory() as cache_dir:
            with patch("logscan_web.recommendations.urlopen", return_value=Response(schema)) as fetch:
                self.assertEqual(validate_redacted_config(log, schema_cache_dir=cache_dir), [])
            self.assertEqual(fetch.call_count, 1)
            self.assertTrue(Path(cache_dir, "master.json").is_file())

            with patch("logscan_web.recommendations.urlopen") as fetch:
                self.assertEqual(validate_redacted_config(log, schema_cache_dir=cache_dir), [])
            fetch.assert_not_called()

    def test_schema_validation_uses_stale_cache_when_refresh_fails(self):
        schema = {"type": "object", "properties": {}}
        log = "\n".join([
            "Redacted Config",
            "[config.py:1] [INFO] | {} |",
            "Initializing cache database at /config/cache",
        ])
        with tempfile.TemporaryDirectory() as cache_dir:
            cache_path = Path(cache_dir, "master.json")
            cache_path.write_text(json.dumps(schema), encoding="utf-8")
            stale = time.time() - 7200
            os.utime(cache_path, (stale, stale))
            with patch("logscan_web.recommendations.urlopen", side_effect=TimeoutError):
                self.assertEqual(validate_redacted_config(log, schema_cache_dir=cache_dir), [])

    def test_schema_results_are_persisted_and_drive_the_page_count(self):
        source = Path("logscan_web/app.py").read_text(encoding="utf-8")

        self.assertIn('result.metadata["schema_validation_failures"] = schema_failures', source)
        self.assertIn('metadata.setdefault("counts", {})["schema"] = schema_count', source)
        self.assertIn('metadata.get("schema_validation_version") == SCHEMA_VALIDATION_VERSION', source)

    def test_config_viewer_marks_exact_schema_issue_ranges(self):
        script = Path("logscan_web/static/app.js").read_text(encoding="utf-8")
        css = Path("logscan_web/static/styles.css").read_text(encoding="utf-8")

        self.assertIn("config_column: failure.config_column", script)
        self.assertIn("config_end_column: failure.config_end_column", script)
        self.assertIn('span.classList.add("schema-issue-token")', script)
        self.assertIn("text-decoration-style: wavy", css)
        self.assertIn("text-decoration-color: #fb7185", css)

    def test_config_download_adds_matching_yaml_schema_directive(self):
        script = Path("logscan_web/static/app.js").read_text(encoding="utf-8")
        self.assertIn("function configForDownload()", script)
        self.assertIn("yaml-language-server:", script)
        self.assertIn("refs/heads/${currentSchemaBranch}/json-schema/config-schema.json", script)
        self.assertIn('metadata.kometa_branch === "master" ? "master" : "develop"', script)
        self.assertIn("new Blob([configForDownload()]", script)

    def test_config_viewer_identifies_schema_branch(self):
        script = Path("logscan_web/static/app.js").read_text(encoding="utf-8")
        template = Path("logscan_web/templates/index.html").read_text(encoding="utf-8")

        self.assertIn('id="viewer-schema-branch" hidden', template)
        self.assertIn("Validated against Kometa ${currentSchemaBranch} schema", script)
        self.assertIn("schemaBranch.hidden = !isConfig", script)

    def test_config_download_uses_yaml_extension(self):
        script = Path("logscan_web/static/app.js").read_text(encoding="utf-8")
        self.assertIn('downloadFilename(kind = "log")', script)
        self.assertIn('kind === "config" ? ".yml" : ".log"', script)
        self.assertIn('downloadFilename("config")', script)

    def test_mobile_viewer_disables_per_line_text_autosizing(self):
        css = Path("logscan_web/static/styles.css").read_text(encoding="utf-8")
        self.assertIn("-webkit-text-size-adjust: none", css)
        self.assertIn(".log-code .log-line, .log-code .log-line span", css)
        self.assertIn("font-size: inherit", css)

    def test_schema_web_cards_explain_impact_and_fix(self):
        script = Path("logscan_web/static/app.js").read_text(encoding="utf-8")
        self.assertIn("Impact:", script)
        self.assertIn("How to fix:", script)
        self.assertIn("Available options:", Path("logscan_web/recommendations.py").read_text(encoding="utf-8"))
        self.assertIn("failure.location", script)
        self.assertIn("failure.accepted", script)
        self.assertIn("failure.explanation", script)
        self.assertIn("config_line: failure.config_line", script)
        self.assertIn("Open config.yml at line", script)
        self.assertIn("showConfigInViewer(configLine)", script)
        self.assertIn("schemaValidationFailures = validation.failures || []", script)
        self.assertIn("applySupportDestination(data, groups, recommendations);", script)
        template = Path("logscan_web/templates/index.html").read_text(encoding="utf-8")
        self.assertIn('id="previous-highlight"', template)
        self.assertIn("goToPreviousHighlightedLine", script)
        self.assertIn('goToHighlightedLine("previous")', script)
        self.assertIn('group.key === "schema"', script)
        self.assertIn("Review issues in config", script)
        self.assertIn("Longest section run times", script)
        self.assertIn('["100", "100 per page"]', script)
        self.assertIn('Previous section runtime page', script)
        self.assertIn('Next section runtime page', script)
        self.assertIn('runtimePageIndex', script)
        self.assertIn('function groupedLogSections(sections)', script)
        self.assertIn('document.createElement("optgroup")', script)
        self.assertIn('Collection files', script)
        self.assertIn('Metadata operations', script)
        self.assertIn('["Plex DB cache", dbCache]', script)
        self.assertIn('["PlexPass", plexPass]', script)
        self.assertIn('["all", `All (', script)
        self.assertIn('document.createElement("details")', script)
        self.assertIn('rank.textContent = `${start + index + 1} of ${sectionRunTimes.length}`', script)
        self.assertIn("async function openRuntimeLine", script)
        self.assertIn("block.includes(duration)", script)
        self.assertEqual(template.count('class="secondary-button compact"'), 2)
        self.assertIn("viewerNavigationLines", script)
        self.assertIn("runtimeTargetLine", script)
        self.assertIn("openRuntimeLine(runtime, visibleRunTimes)", script)
        self.assertIn('runtimeContext ? "ranked section" : "highlighted line"', script)
        self.assertIn("viewerNavigationLines.indexOf(highlightedRange.start)", script)
        self.assertIn("Jump to schema issue", script)
        self.assertIn("schemaRecommendationsForConfigLine", script)
        self.assertIn('"schema-validation-line"', script)

    def test_schema_issue_counts_use_one_canonical_collection(self):
        script = Path("logscan_web/static/app.js").read_text(encoding="utf-8")

        self.assertIn("function schemaIssueRecommendations", script)
        self.assertIn("const schemaIssueCount = schemaIssueRecommendations().length", script)
        self.assertIn("schemaIssueRecommendations(updated.recommendations).length", script)
        self.assertNotIn('id: "live_schema_passed"', script)

    def test_overview_identifies_quickstart_and_direct_launchers(self):
        script = Path("logscan_web/static/app.js").read_text(encoding="utf-8")

        self.assertIn('overview.run_launcher = metadata.quickstart_run', script)
        self.assertIn('environmentSection("quickstart", "Quickstart"', script)
        self.assertIn('badge.src = `/static/${kind}.png`', script)
        self.assertIn('sectionContent.scrollIntoView({ behavior: "smooth", block: "start" })', script)
        self.assertIn('plexConfigurationList(configurations)', script)
        self.assertIn('Connection details reported for each Plex library.', script)
        self.assertNotIn('[["Run command", overview.run_command]], true', script)
        self.assertIn("metadata.quickstart_run", script)
        self.assertIn('metadata.quickstart_version || "version unknown"', script)
        self.assertIn('"Direct Kometa run"', script)

    def test_summary_cards_show_plex_server_details(self):
        script = Path("logscan_web/static/app.js").read_text(encoding="utf-8")
        template = Path("logscan_web/templates/index.html").read_text(encoding="utf-8")

        self.assertIn('id="summary-grid"', template)
        self.assertIn('aria-label="Scan summary"', template)
        self.assertIn('className = "scan-metric-grid"', script)
        self.assertIn('findingTile("Errors", "error", metadata.counts.error)', script)
        self.assertIn('environmentSection("kometa", "Kometa"', script)
        self.assertIn('environmentSection("plex", "Plex"', script)
        self.assertIn('environmentSection("quickstart", "Quickstart"', script)
        self.assertIn('badge.src = `/static/${kind}.png`', script)
        self.assertIn('sectionContent.scrollIntoView({ behavior: "smooth", block: "start" })', script)
        self.assertIn('plexConfigurationList(configurations)', script)
        self.assertIn('Connection details reported for each Plex library.', script)
        self.assertNotIn('[["Run command", overview.run_command]], true', script)
        self.assertIn('const servers = overview.plex_servers || []', script)
    def test_overview_validation_status_tracks_live_schema_results(self):
        script = Path("logscan_web/static/app.js").read_text(encoding="utf-8")

        self.assertIn("overview.yaml_issue_count = schemaIssueCount", script)
        self.assertIn("schemaIssueCount.toLocaleString()", script)
        self.assertIn("Live schema validation unavailable", script)
        self.assertIn("No schema issues detected", script)
        self.assertIn("Live schema validation pending", script)

    def test_schema_dialog_constrains_long_paths_to_its_viewport(self):
        css = Path("logscan_web/static/styles.css").read_text(encoding="utf-8")

        self.assertIn(".help-dialog-shell { width: 100%; min-width: 0; max-width: 100%;", css)
        self.assertIn(".viewer-header > div { min-width: 0; flex: 1 1 auto; }", css)
        self.assertIn(".viewer-header h2 { width: 100%; max-width: 100%;", css)
        self.assertIn(".recommendation-dialog-content { min-width: 0;", css)
        self.assertIn("overflow-wrap: anywhere; word-break: break-word;", css)

    def test_overview_validation_card_opens_first_config_issue(self):
        script = Path("logscan_web/static/app.js").read_text(encoding="utf-8")
        css = Path("logscan_web/static/styles.css").read_text(encoding="utf-8")

        self.assertIn('label === "Configuration validation"', script)
        self.assertIn('item.classList.add("overview-validation-issue")', script)
        self.assertIn('item.setAttribute("role", "button")', script)
        self.assertIn("showConfigInViewer(Number(firstIssue?.config_line) || 0)", script)
        config_viewer = script[script.index("async function showConfigInViewer"):script.index("function populateSectionJump")]
        self.assertIn("if (!logViewer.open) logViewer.showModal()", config_viewer)
        self.assertIn(".overview-validation-issue:hover", css)
        self.assertIn("box-shadow: inset 3px 0 0 var(--schema)", css)

    def test_yaml_schema_directive_detection_uses_extracted_config(self):
        prefix = "[config.py:1] [INFO] |"
        without_directive = "\n".join([
            "Redacted Config",
            f"{prefix} libraries:",
            f"{prefix}   Movies:",
            f"{prefix} end",
            "Initializing cache database at /config/cache",
        ])
        with_directive = "\n".join([
            "Redacted Config",
            f"{prefix} # yaml-language-server: $schema=https://example.test/schema.json",
            f"{prefix} libraries:",
            f"{prefix} end",
            "Initializing cache database at /config/cache",
        ])
        self.assertFalse(has_yaml_language_server_directive(without_directive))
        self.assertTrue(has_yaml_language_server_directive(with_directive))

    def test_schema_branch_matches_release_channel(self):
        self.assertEqual(schema_branch_for_log("Version: 2.2.0 (Branch: master)"), "master")
        self.assertEqual(schema_branch_for_log("Version: 2.3.0 (Branch: develop)"), "develop")
        self.assertEqual(schema_branch_for_log("Version: 2.1.0 (Branch: nightly)"), "develop")
    def test_retired_nightly_branch_recommends_develop_or_master(self):
        content = "\n".join([
            "[kometa.py:1] [INFO] | Version: 2.4.8-build21 (Branch: nightly) |",
            "[kometa.py:2] [INFO] | Finished: Run Time: 0:01:00 |",
        ])

        result = scan_log("meta.log", content.encode())
        finding = next(item for item in result.recommendations if item["id"] == "retired_nightly_branch")

        self.assertEqual(finding["severity"], "warning")
        self.assertEqual(finding["evidence_lines"], [1])
        self.assertIn("develop", finding["message"])
        self.assertIn("master", finding["message"])
        self.assertEqual(result.metadata["kometa_branch"], "nightly")

    def test_traceback_is_critical(self):
        self.assertEqual(next(rule for rule in RULES.values() if rule.id == "traceback").category, "critical")
    def test_internal_server_error_is_critical(self):
        self.assertEqual(next(rule for rule in RULES.values() if rule.id == "internal_server").category, "critical")

    def test_recommendation_severities_match_discord_symbols(self):
        expected = {
            "checkfiles": "warning",
            "legacy_other_award": "warning",
            "id_conversion": "advice",
            "legacy_delete_unmanaged": "warning",
            "flixpatrol_parse": "error",
            "flixpatrol_subscription": "error",
            "legacy_git": "advice",
            "legacy_pmm": "advice",
            "image_size": "error",
            "incomplete_log": "error",
            "internal_server": "critical",
            "linuxserver": "warning",
            "mal_connection": "error",
            "mdblist_attribute": "error",
            "mdblist_api_key": "error",
            "mdblist_limit": "error",
            "metadata_attribute": "error",
            "legacy_missing": "warning",
            "plex_no_items": "warning",
            "omdb_api_key": "error",
            "omdb_limit": "error",
            "legacy_overlay_level": "warning",
            "plex_regex": "warning",
            "plex_library": "error",
            "plex_url": "error",
            "yaml": "critical",
            "run_order": "warning",
            "tmdb_key": "error",
            "tmdb_connection": "error",
            "service_config": "error",
            "trakt_connection": "error",
            "schedule_over_24_hours": "error",
            "schedule_overlap": "error",
            "schedule_conflict": "error",
            "schedule_maintenance_buffer": "error",
        }
        by_id = {rule.id: rule.category for rule in RULES.values()}
        self.assertEqual({rule_id: by_id[rule_id] for rule_id in expected}, expected)
    def test_every_verified_discord_documentation_url_is_kept(self):
        by_id = {rule.id: rule for rule in RULES.values()}

        self.assertGreaterEqual(len(DOCUMENTATION_URLS), 40)
        self.assertEqual(set(DOCUMENTATION_URLS) - set(by_id), set())
        for rule_id, url in DOCUMENTATION_URLS.items():
            with self.subTest(rule_id=rule_id):
                self.assertIn(url, by_id[rule_id].solution)

    def test_every_rich_discord_guidance_override_is_applied(self):
        by_id = {rule.id: rule for rule in RULES.values()}

        self.assertGreaterEqual(len(DISCORD_GUIDANCE), 45)
        for rule_id, (description, solution) in DISCORD_GUIDANCE.items():
            with self.subTest(rule_id=rule_id):
                self.assertEqual(by_id[rule_id].description, description)
                self.assertTrue(by_id[rule_id].solution.startswith(solution))

    def test_linuxserver_keeps_operational_discord_guidance(self):
        rule = next(rule for rule in RULES.values() if rule.id == "linuxserver")

        self.assertIn("`linuxserver/kometa`", rule.description)
        self.assertIn("different internal locations", rule.description)
        self.assertIn("3:00 AM", rule.description)
        self.assertIn("Plex scheduled maintenance", rule.description)
        self.assertIn("`kometateam/kometa`", rule.solution)
        self.assertIn("Docker and unRAID", rule.solution)
        self.assertIn("https://www.kometa.wiki/en/latest/kometa/install/images", rule.solution)
        self.assertNotIn("nightly", f"{rule.description} {rule.solution}".lower())
    def test_overlay_reset_uses_rich_reapply_guidance(self):
        rule = next(rule for rule in RULES.values() if rule.id == "overlay_reset")

        self.assertEqual(rule.title, "Reapply or reset overlays detected")
        self.assertIn("`reapply_overlays` should not be enabled", rule.description)
        self.assertIn("additional posters in Plex", rule.description)
        self.assertIn("particular repair or rebuild cases", rule.description)
        self.assertIn("ImageMaid", rule.solution)
        self.assertNotIn("reapplication", f"{rule.title} {rule.description} {rule.solution}".lower())
    def test_legacy_other_award_keeps_discord_guidance_and_url(self):
        content = "\n".join([
            "[kometa.py:1] [INFO] | Version: 2.3.1-build24 (Branch: master) |",
            "[config.py:2] [WARNING] | other_award: oscars |",
        ])

        result = scan_log("meta.log", content.encode())
        finding = next(item for item in result.recommendations if item["id"] == "legacy_other_award")

        self.assertIn("As of 1.20", finding["description"])
        self.assertIn("own individual files", finding["description"])
        self.assertIn(
            "https://www.kometa.wiki/en/latest/kometa/faqs/?h=other_award#pmm-120-release-changes",
            finding["solution"],
        )

    def test_pre_kometa_yaml_keeps_replacement_url_and_evidence(self):
        content = "\n".join([
            "[kometa.py:1] [INFO] | Version: 2.3.1-build24 (Branch: master) |",
            "[config.py:2] [INFO] |     - pmm: imdb |",
            "[config.py:3] [INFO] |     - pmm: oscars |",
        ])

        result = scan_log("meta.log", content.encode())
        finding = next(item for item in result.recommendations if item["id"] == "legacy_pmm")

        self.assertEqual(finding["title"], "Pre-Kometa YAML detected")
        self.assertIn("`- pmm:`", finding["solution"])
        self.assertIn("`- default:`", finding["solution"])
        self.assertIn("https://www.kometa.wiki/en/latest/config/overview/?h=configuration", finding["solution"])
        self.assertEqual(finding["evidence_lines"], [2, 3])

    def test_anidb_recommendations_keep_discord_guidance_and_url(self):
        content = "\n".join([
            "[kometa.py:1] [INFO] | Version: 2.3.1-build24 (Branch: master) |",
            "[config.py:2] [ERROR] | AniDB Error: Login failed |",
            "[config.py:3] [ERROR] | No Anime Found for AniDB ID: 69 |",
        ])

        result = scan_log("meta.log", content.encode())
        findings = {item["id"]: item for item in result.recommendations}

        auth = findings["anidb_auth"]
        self.assertIn("settings in config.yml", auth["description"])
        self.assertIn("https://www.kometa.wiki/en/latest/config/anidb", auth["solution"])
        self.assertEqual(auth["evidence_lines"], [2])
        connection = findings["anidb_connection"]
        self.assertIn("AniDB ID 69", connection["description"])
        self.assertIn("https://www.kometa.wiki/en/latest/config/anidb", connection["solution"])
        self.assertEqual(connection["evidence_lines"], [3])

    def test_removed_trakt_source_has_specific_recommendation(self):
        content = "\n".join([
            "[kometa.py:1] [INFO] | Version: 2.5.1-build6 (Branch: master) |",
            "[meta.py:172] [INFO] | File Loaded From: /config/collections-config/1-Movies_Tops.yml |",
            "[meta.py:173] [ERROR] | Trakt is no longer supported, please see the Announcements channel in the Kometa Discord server for further information |",
        ])

        result = scan_log("meta.log", content.encode())
        finding = next(item for item in result.recommendations if item["id"] == "trakt_unsupported")

        self.assertEqual(finding["severity"], "error")
        self.assertEqual(finding["evidence_lines"], [3])
        self.assertIn("no longer supports", finding["description"])
        self.assertIn("file identified immediately above", finding["solution"])
        self.assertIn("Announcements", finding["solution"])

    def test_missing_config_subattribute_explains_logged_default(self):
        content = "\n".join([
            "[kometa.py:1] [INFO] | Version: 2.5.1-build6 (Branch: master) |",
            "[config.py:641] [WARNING] | Config Warning: settings sub-attribute verify_ssl not found using True as default |",
            "[config.py:935] [INFO] |========================================================================================",
        ])

        result = scan_log("meta.log", content.encode())
        finding = next(item for item in result.recommendations if item["id"] == "config_subattribute_default")

        self.assertEqual(finding["severity"], "warning")
        self.assertEqual(finding["evidence_lines"], [2])
        self.assertIn("default value shown", finding["description"])
        self.assertIn("No change is required", finding["solution"])

    def test_runtime_platform_is_reduced_to_a_safe_family(self):
        self.assertEqual(normalized_platform("Linux-6.1.34-Unraid-x86_64"), "Linux")
        self.assertEqual(normalized_platform("Linux-5.15.0-microsoft-standard-WSL2"), "WSL")
        self.assertEqual(normalized_platform("Windows-11-10.0.26100"), "Windows")
        self.assertEqual(normalized_platform("Darwin-24.6.0-arm64"), "macOS")
        self.assertEqual(normalized_platform("private custom host value"), "Unknown")

    def test_installation_method_requires_an_explicit_header_marker(self):
        self.assertEqual(normalized_installation("1.19.0 (Docker)"), "Docker")
        self.assertEqual(normalized_installation("2.3.1 (Linuxserver)"), "Docker (LinuxServer)")
        self.assertEqual(normalized_installation("2.5.0 (Python 3.13.2)"), "Native Python")
        self.assertEqual(normalized_installation("2.5.0"), "Unknown")
    def test_plex_configuration_sections_are_exposed_in_log_overview(self):
        content = "\n".join([
            "[kometa.py:1] [INFO] | Version: 2.3.1-build24 (Branch: master) |",
            "[config.py:2] [INFO] | Plex Configuration |",
            "[config.py:3] [INFO] | Using Asset Directory: config/assets/Movies/ |",
            "[config.py:4] [INFO] | Connected to server NZWHS01 version 1.31.2.6810-a607d384f |",
            "[config.py:5] [INFO] | Running on Linux version 6.1.34-Unraid |",
            "[config.py:6] [INFO] | Connected to library TestMovies |",
            "[config.py:7] [INFO] | Type: Movie |",
            "[config.py:8] [INFO] | Agent: tv.plex.agents.movie |",
            "[config.py:9] [INFO] | Library Connection Successful |",
            "[builder.py:10] [INFO] | Scanning Metadata and Images |",
        ])

        sections = extract_plex_configurations(content)
        result = scan_log("meta.log", content.encode())

        self.assertEqual(len(sections), 1)
        self.assertEqual(sections[0]["title"], "Plex Configuration - Movie: TestMovies")
        self.assertIn("Connected to library TestMovies", sections[0]["lines"])
        self.assertIn("Agent: tv.plex.agents.movie", sections[0]["lines"])
        self.assertEqual(result.overview["plex_configurations"], sections)
        self.assertEqual(result.overview["plex_analytics"]["versions"], ["1.31.2.6810-a607d384f"])
        self.assertEqual(result.overview["plex_analytics"]["platforms"], ["Linux"])
        self.assertEqual(result.overview["plex_analytics"]["library_types"], ["Movie"])
        self.assertEqual(result.overview["plex_analytics"]["agents"], ["tv.plex.agents.movie"])
        self.assertEqual(result.overview["plex_servers"], [{
            "name": "NZWHS01",
            "version": "1.31.2.6810-a607d384f",
            "platform": "Linux version 6.1.34-Unraid",
        }])

    def test_plex_configuration_title_falls_back_for_partial_sections(self):
        content = "\n".join([
            "[config.py:1] [INFO] | Plex Configuration |",
            "[config.py:2] [INFO] | Connected to library Documentaries |",
            "[config.py:3] [INFO] | Plex Configuration |",
            "[config.py:4] [INFO] | Type: Show |",
            "[config.py:5] [INFO] | Plex Configuration |",
            "[config.py:6] [INFO] | Connected to server Plex version 1.2.3.4-abcd |",
        ])

        sections = extract_plex_configurations(content)

        self.assertEqual([section["title"] for section in sections], [
            "Plex Configuration - Documentaries",
            "Plex Configuration - Show",
            "Plex Configuration - Section 3",
        ])

    def test_quickstart_metadata_extractor_supports_backfill_and_direct_runs(self):
        quickstart = extract_quickstart_metadata(
            "[Quickstart] Run marker: quickstart=0.10.6-build7 branch=develop"
        )
        direct = extract_quickstart_metadata("[kometa.py:1] [INFO] | Version: 2.5.0 |")

        self.assertEqual(quickstart, {
            "quickstart_run": True,
            "quickstart_version": "0.10.6-build7",
            "quickstart_branch": "develop",
            "quickstart": {
                "detected": True, "version": "0.10.6-build7", "branch": "develop",
                "mode": None, "flags": [], "metadata": {},
            },
        })
        self.assertEqual(direct, {
            "quickstart_run": False,
            "quickstart_version": None,
            "quickstart_branch": "unknown",
            "quickstart": {
                "detected": False, "version": None, "branch": "unknown",
                "mode": None, "flags": [], "metadata": {},
            },
        })

    def test_quickstart_generated_header_exposes_safe_operational_metadata(self):
        prefix = "[2026-09-12 23:07:10,167] [config.py:315] [DEBUG] | # "
        content = "\n".join(prefix + value + " |" for value in [
            "dreamy_kare config created by Quickstart on 2026-09-12 23:02:21",
            "OS: Windows 11",
            "Docker: False",
            "CPU: Intel64 Family 6 Model 94 Stepping 3, GenuineIntel (8 cores)",
            "Memory: 14011 MB / 32657 MB (42%) | 18645 MB Free",
            "Python: 3.12.10",
            "Git: git version 2.55.0.windows.3",
            "Browser: private browser value",
            "Quickstart Port: 8008",
            "Quickstart Debug: Disabled",
            "Quickstart Theme: kometa",
            "Quickstart Optimize Template Defaults: Enabled",
            "Quickstart Config Archive History: 10",
            "Quickstart Kometa Log Retention: Keep all (0)",
            "Quickstart ImageMaid Log Retention: Keep all (0)",
            r"Quickstart Test Libraries Temp Path: C:\Users\private\tmp",
            "Kometa Runtime Mode: Quickstart-managed install",
            "Quickstart Session Lifetime Days: 30",
            "Quickstart: 0.10.6-build33 | Branch: run_command_fixes | Environment: Local-Windows",
        ])

        quickstart = extract_quickstart_metadata(content)["quickstart"]

        self.assertEqual(quickstart["version"], "0.10.6-build33")
        self.assertEqual(quickstart["branch"], "run_command_fixes")
        self.assertEqual(quickstart["mode"], "Quickstart-managed install")
        self.assertEqual(quickstart["metadata"], {
            "platform": "Local-Windows",
            "os": "Windows 11",
            "docker": "False",
            "cpu": "Intel64 Family 6 Model 94 Stepping 3, GenuineIntel (8 cores)",
            "memory": "14011 MB / 32657 MB (42%) | 18645 MB Free",
            "python": "3.12.10",
            "git": "git version 2.55.0.windows.3",
            "port": "8008",
            "debug": "Disabled",
            "theme": "kometa",
            "optimize_template_defaults": "Enabled",
            "config_archive_history": "10",
            "kometa_log_retention": "Keep all (0)",
            "imagemaid_log_retention": "Keep all (0)",
            "session_lifetime_days": "30",
        })
        serialized = json.dumps(quickstart)
        self.assertNotIn("private browser value", serialized)
        self.assertNotIn(r"C:\Users\private", serialized)
        self.assertNotIn("dreamy_kare", serialized)
    def test_quickstart_metadata_block_is_structured_and_private_values_are_omitted(self):
        content = "\n".join([
            "[Quickstart] Metadata Start",
            "[Quickstart] version=0.10.9 branch=develop mode=managed flags=--run,--read-only",
            "[Quickstart] platform=Linux workspace=private config=(redacted) launcher=compose",
            "[Quickstart] Metadata End",
        ])

        extracted = extract_quickstart_metadata(content)

        self.assertEqual(extracted["quickstart"]["version"], "0.10.9")
        self.assertEqual(extracted["quickstart"]["mode"], "managed")
        self.assertEqual(extracted["quickstart"]["flags"], ["--run", "--read-only"])
        self.assertEqual(extracted["quickstart"]["metadata"], {
            "platform": "Linux",
            "launcher": "compose",
        })
    def test_kometa_and_quickstart_channels_are_extracted_from_safe_markers(self):
        content = "\n".join([
            "[kometa.py:1] [INFO] | Version: 2.3.1-build24 (Python 3.12.1) (Branch: nightly) |",
            "[Quickstart] Run marker: started=private config=private quickstart=0.10.4-build302 branch=develop",
        ])
        metadata = scan_log("meta.log", content.encode())["metadata"] if isinstance(scan_log("meta.log", content.encode()), dict) else scan_log("meta.log", content.encode()).metadata
        self.assertEqual(metadata["kometa_branch"], "nightly")
        self.assertTrue(metadata["quickstart_run"])
        self.assertEqual(metadata["quickstart_version"], "0.10.4-build302")
        self.assertEqual(metadata["quickstart_branch"], "develop")


class AnonymousAnalyticsTests(unittest.TestCase):
    def test_legacy_baseline_preserves_larger_totals_only_once(self):
        with tempfile.TemporaryDirectory() as directory:
            analytics = AnonymousAnalyticsStore(directory)
            analytics.record_success(
                logs=50, lines=2282999, bytes_processed=100, source="web", batch=False,
                versions=[], kometa_branches=[], launchers=[], quickstart_versions=[],
                quickstart_branches=[], recommendations=[], people=0,
            )
            legacy = {
                "logs_submitted": 54,
                "lines_processed": 3393973,
                "people_submitted": 15,
                "people_addressed": 0,
                "started_at": "2026-09-20T12:00:00+00:00",
            }
            analytics.import_legacy_baseline(legacy)
            analytics.import_legacy_baseline(legacy)
            snapshot = analytics.snapshot()

        self.assertEqual(snapshot["totals"]["successful_logs"], 54)
        self.assertEqual(snapshot["totals"]["lines_processed"], 3393973)
        self.assertEqual(snapshot["totals"]["people_submitted"], 15)
        self.assertEqual(snapshot["totals"]["sources"]["legacy"], 4)
    def test_existing_daily_buckets_migrate_when_new_dimensions_are_added(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "usage_analytics.json").write_text(json.dumps({
                "started_at": datetime.now(UTC).isoformat(),
                "days": {datetime.now(UTC).date().isoformat(): {"successful_logs": 4}},
                "addressed_keys": [],
            }), encoding="utf-8")
            analytics = AnonymousAnalyticsStore(directory)
            analytics.record_success(
                logs=1, lines=10, bytes_processed=100, source="discord", batch=False,
                versions=["2.3.1-build24"], kometa_branches=["nightly"], launchers=["quickstart"],
                quickstart_versions=["0.10.4-build302"], quickstart_branches=["develop"],
                recommendations=[], people=0,
            )
            totals = analytics.snapshot()["totals"]
        self.assertEqual(totals["successful_logs"], 5)
        self.assertEqual(totals["kometa_branches"], {"nightly": 1})
        self.assertEqual(totals["quickstart_branches"], {"develop": 1})

    def test_daily_analytics_are_aggregate_and_persistent(self):
        with tempfile.TemporaryDirectory() as directory:
            analytics = AnonymousAnalyticsStore(directory)
            analytics.record_rejection("not_kometa_log", "web")
            analytics.record_success(
                logs=2, lines=1200, bytes_processed=5000, source="discord", batch=True,
                versions=["2.1.0", "unknown"], kometa_branches=["master", "nightly"],
                launchers=["direct", "quickstart"], quickstart_versions=["0.10.4-build302"],
                quickstart_branches=["develop"], recommendations=[{"id": "test_rule", "severity": "warning"}], people=3,
                kometa_platforms=["Linux", "Windows"], quickstart_platforms=["Linux"],
                installation_methods=["Docker", "Native Python"],
                plex={
                    "versions": ["1.31.2.6810-a607d384f"], "platforms": ["Linux"],
                    "update_channels": ["Public"], "library_types": ["Movie"],
                    "agents": ["tv.plex.agents.movie"], "scanners": ["Plex Movie"],
                },
            )
            analytics.record_addressed([{"key": "tmdb-1", "created_at": datetime.now(UTC).isoformat()}])
            analytics.record_addressed([{"key": "tmdb-1", "created_at": datetime.now(UTC).isoformat()}])
            snapshot = AnonymousAnalyticsStore(directory).snapshot()
            raw = Path(directory, "usage_analytics.json").read_text(encoding="utf-8")
        self.assertEqual(snapshot["totals"]["successful_logs"], 2)
        self.assertEqual(snapshot["totals"]["people_addressed"], 1)
        self.assertEqual(snapshot["totals"]["sources"], {"discord": 2})
        self.assertEqual(snapshot["totals"]["kometa_branches"], {"master": 1, "nightly": 1})
        self.assertEqual(snapshot["totals"]["launchers"], {"direct": 1, "quickstart": 1})
        self.assertEqual(snapshot["totals"]["quickstart_branches"], {"develop": 1})
        self.assertEqual(snapshot["totals"]["kometa_platforms"], {"Linux": 1, "Windows": 1})
        self.assertEqual(snapshot["totals"]["quickstart_platforms"], {"Linux": 1})
        self.assertEqual(snapshot["totals"]["installation_methods"], {"Docker": 1, "Native Python": 1})
        self.assertEqual(snapshot["totals"]["plex_versions"], {"1.31.2.6810-a607d384f": 1})
        self.assertEqual(snapshot["totals"]["plex_platforms"], {"Linux": 1})
        self.assertEqual(snapshot["totals"]["plex_library_types"], {"Movie": 1})
        self.assertEqual(snapshot["totals"]["plex_agents"], {"tv.plex.agents.movie": 1})
        self.assertNotIn("tmdb-1", raw)
        self.assertNotIn("NZWHS01", raw)
        self.assertNotIn("TestMovies", raw)
        self.assertNotIn("config/assets", raw)


class UsageStatsTests(unittest.TestCase):
    def test_counters_persist_and_addressed_people_are_only_counted_once(self):
        with tempfile.TemporaryDirectory() as directory:
            stats = UsageStatsStore(directory)
            stats.ensure_people_baseline(2)
            stats.record_submission(logs=2, lines=12500, people=1)
            stats.ensure_people_baseline(1)
            self.assertEqual(stats.mark_addressed(["tmdb-1", "tmdb-2"]), 2)
            self.assertEqual(stats.mark_addressed(["tmdb-1"]), 0)
            restored = UsageStatsStore(directory).snapshot()
        self.assertEqual(restored["logs_submitted"], 2)
        self.assertEqual(restored["lines_processed"], 12500)
        self.assertEqual(restored["people_submitted"], 3)
        self.assertEqual(restored["people_addressed"], 2)


class PeopleUnionTests(unittest.TestCase):
    def setUp(self):
        Path(STORE.name, "people.json").write_text(json.dumps([
            {"key": "tmdb-1", "tmdb_id": 1, "name": "Alice Person", "log_url": "/scan/alice", "requested_by": [{"name": "Request User", "id": "123"}]},
            {"key": "tmdb-3", "tmdb_id": 3, "name": "Bob Person", "log_url": "/scan/bob"},
            {"key": "tmdb-4", "tmdb_id": 4, "name": "Completed Person", "log_url": "/scan/completed"},
        ]), encoding="utf-8")
        for filename in ("popular_people_checked.json", "popular_people_exclusions.json", "popular_people_flags.json"):
            Path(STORE.name, filename).write_text("[]" if filename != "popular_people_flags.json" else "{}", encoding="utf-8")
        self.client = app.test_client()

    def request_people(self, sources="missing,trending", tag="", selected_tags=()):
        query = [("sources", sources), ("tag", tag)]
        query.extend(("tags", value) for value in selected_tags)
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get("/api/people", query_string=query)
        self.assertEqual(response.status_code, 200)
        return response.get_json()["people"]

    def test_union_deduplicates_by_tmdb_id_and_adds_source_tags(self):
        people = self.request_people()
        self.assertEqual([person["tmdb_id"] for person in people], [1, 3, 2])
        self.assertEqual(people[0]["sources"], ["missing", "trending"])
        self.assertEqual(people[1]["sources"], ["missing"])
        self.assertEqual(people[2]["sources"], ["trending"])

    def test_legacy_source_parameter_is_ignored_for_the_unified_page(self):
        self.assertEqual([person["tmdb_id"] for person in self.request_people("missing")], [1, 3, 2])
        self.assertEqual([person["tmdb_id"] for person in self.request_people("trending")], [1, 3, 2])

    def test_trending_and_missing_kometa_tags_find_the_intersection(self):
        people = self.request_people(selected_tags=("Trending", "Missing Kometa"))
        self.assertEqual([person["tmdb_id"] for person in people], [1])

    def test_known_requester_is_returned_with_missing_person(self):
        person = next(person for person in self.request_people() if person["tmdb_id"] == 1)
        self.assertEqual(person["requested_by"], [{"name": "Request User", "id": "123"}])
        self.assertEqual(person["provenance_tags"], ["Log Upload"])

    def test_log_upload_tag_is_searchable_for_historical_records(self):
        people = self.request_people(tag="log upload")
        self.assertEqual([person["tmdb_id"] for person in people], [1, 3])
        self.assertTrue(all(person["provenance_tags"] == ["Log Upload"] for person in people))

    def test_historical_log_record_uses_searchable_unknown_requester(self):
        people = self.request_people(tag="unknown")
        self.assertEqual([person["tmdb_id"] for person in people], [3])
        self.assertEqual(people[0]["requested_by"], [{"name": "Unknown", "id": None}])

    def test_requesters_accumulate_without_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            store = PeopleStore(directory)
            store.upsert({"key": "tmdb-9", "name": "Person", "requested_by": [{"name": "First Name", "id": "1"}]})
            store.upsert({"key": "tmdb-9", "name": "Person", "requested_by": [{"name": "Updated Name", "id": "1"}]})
            person = store.upsert({"key": "tmdb-9", "name": "Person", "requested_by": [{"name": "Second User", "id": "2"}]})
        self.assertEqual(person["requested_by"], [
            {"name": "Updated Name", "id": "1"},
            {"name": "Second User", "id": "2"},
        ])

    def test_api_supports_smaller_mobile_page_size(self):
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get("/api/people", query_string={"sources": "missing,trending", "per_page": 1})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.get_json()["people"]), 1)
        self.assertEqual(response.get_json()["per_page"], 1)
        self.assertEqual(response.get_json()["total"], 3)
        self.assertEqual(response.get_json()["total_pages"], 3)

    def test_tag_filter_supports_contains_and_wildcards(self):
        self.assertEqual([person["tmdb_id"] for person in self.request_people(tag="user")], [1])
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get("/api/people", query_string={"sources": "missing,trending", "tag": "user"})
        self.assertEqual(response.get_json()["total"], 1)
        self.assertEqual([person["tmdb_id"] for person in self.request_people(tag="Request*User")], [1])
        self.assertEqual([person["tmdb_id"] for person in self.request_people(tag="trend?ng")], [1, 2])

    def test_dynamic_tags_include_counts_and_group_requesters_with_or_semantics(self):
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get("/api/people", query_string=[
                ("sources", "missing,trending"),
                ("tags", "Requested by Request User"),
                ("tags", "Requested by Unknown"),
            ])
        payload = response.get_json()
        self.assertEqual([person["tmdb_id"] for person in payload["people"]], [1, 3])
        facets = {(item["category"], item["tag"]): item["count"] for item in payload["available_tags"]}
        self.assertEqual(facets[("discovery", "Log Upload")], 2)
        self.assertEqual(facets[("requester", "Requested by Unknown")], 1)
        self.assertEqual(facets[("requester", "Requested by Request User")], 1)

    def test_dynamic_tags_combine_different_categories_with_and_semantics(self):
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get("/api/people", query_string=[
                ("sources", "missing,trending"),
                ("tags", "Log Upload"),
                ("tags", "Requested by Unknown"),
            ])
        self.assertEqual([person["tmdb_id"] for person in response.get_json()["people"]], [3])

    def test_missing_filter_includes_trending_gaps_without_uploaded_logs(self):
        Path(STORE.name, "people.json").write_text("[]", encoding="utf-8")
        people = self.request_people(selected_tags=("Missing Kometa",))
        self.assertEqual([person["tmdb_id"] for person in people], [1])
        self.assertEqual(people[0]["sources"], ["missing", "trending"])

    def test_missing_tmdb_is_searchable_and_excluded_from_processing_export(self):
        Path(STORE.name, "people.json").write_text(json.dumps([
            {"key": "tmdb-5", "tmdb_id": 5, "name": "Blocked Person", "log_url": "/scan/blocked"},
        ]), encoding="utf-8")
        people = self.request_people("missing", "Missing TMDb")
        blocked = next(person for person in people if person["tmdb_id"] == 5)
        self.assertEqual(blocked["metadata_tags"], ["Missing TMDb"])
        self.assertEqual(blocked["tmdb_images_url"], "https://www.themoviedb.org/person/5/images/profiles")
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get(
                "/api/people/export",
                query_string={"sources": "missing", "tag": "Missing TMDb"},
            )
        self.assertEqual(response.get_data(as_text=True), "")

    def test_missing_people_with_tmdb_images_are_ready(self):
        person = next(person for person in self.request_people("missing") if person["tmdb_id"] == 3)
        self.assertEqual(person["metadata_tags"], ["TMDb Ready"])
        self.assertEqual(person["tmdb_images_url"], "https://www.themoviedb.org/person/3/images/profiles")

    def test_verified_tmdb_image_survives_transient_profile_lookup_gap(self):
        Path(STORE.name, "people.json").write_text(json.dumps([
            {"key": "tmdb-5", "tmdb_id": 5, "name": "Blocked Person", "tmdb_image_found": True},
        ]), encoding="utf-8")
        person = next(person for person in self.request_people("missing") if person["tmdb_id"] == 5)
        self.assertEqual(person["metadata_tags"], ["TMDb Ready"])
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get("/api/people/export", query_string={"sources": "missing"})
        self.assertEqual(response.get_data(as_text=True).splitlines(), ["1|Alice Person", "5|Blocked Person", "2|Completed Person"])

    def test_repository_image_reconciliation_only_removes_missing_source(self):
        completed = next(person for person in self.request_people() if person["name"] == "Completed Person")
        self.assertEqual(completed["sources"], ["trending"])
        self.assertEqual(completed["kometa_image"], "https://example.test/completed.jpg")

    def test_repository_image_reconciliation_ignores_accents_but_not_partial_names(self):
        Path(STORE.name, "people.json").write_text(json.dumps([
            {"key": "tmdb-6", "tmdb_id": 6, "name": "Hikaru Kondo", "log_url": "/scan/hikaru"},
            {"key": "tmdb-7", "tmdb_id": 7, "name": "Hikaru", "log_url": "/scan/other-hikaru"},
        ]), encoding="utf-8")

        def accented_urlopen(request, timeout=0):
            if "People-Images/refs" in request.full_url:
                return Response("* [Hikaru Kondô](https://example.test/hikaru.jpg)\n", "text/plain")
            return fake_urlopen(request, timeout)

        with patch("logscan_web.app.urlopen", side_effect=accented_urlopen):
            response = create_app().test_client().get("/api/people", query_string={"sources": "missing,trending"})
        self.assertEqual(response.status_code, 200)
        people = response.get_json()["people"]
        self.assertNotIn(6, [person["tmdb_id"] for person in people])
        partial = next(person for person in people if person["tmdb_id"] == 7)
        self.assertIn("missing", partial["sources"])

    def test_export_uses_the_same_filtered_union(self):
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get("/api/people/export", query_string={"sources": "missing,trending"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True).splitlines(), ["1|Alice Person", "3|Bob Person", "2|Completed Person"])

    def test_export_preserves_original_accented_log_name(self):
        Path(STORE.name, "people.json").write_text(json.dumps([
            {
                "key": "tmdb-1", "tmdb_id": 1, "name": "Hikaru Kondo",
                "original_name": "Hikaru Kondô", "log_url": "/scan/hikaru",
            },
        ]), encoding="utf-8")
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get(
                "/api/people/export",
                query_string=[("tags", "Log Upload")],
            )
        self.assertEqual(response.get_data(as_text=True).splitlines(), ["1|Hikaru Kondô"])

    def test_export_respects_requester_tag_filter(self):
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get(
                "/api/people/export",
                query_string={"sources": "missing,trending", "tag": "request*user"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True).splitlines(), ["1|Alice Person"])

    def authorize_support(self):
        with self.client.session_transaction() as support_session:
            support_session["support_authorized_at"] = 9999999999
            support_session["support_user"] = {"id": "42", "username": "Support Person", "avatar": "https://cdn.example/avatar.png"}

    def test_support_identity_is_visible_in_shared_menu_on_every_public_page(self):
        self.authorize_support()
        for path in ("/", "/people", "/analytics"):
            body = self.client.get(path).get_data(as_text=True)
            self.assertIn("Signed in as", body)
            self.assertIn("Support Person", body)
            self.assertIn("Sign out", body)
            self.assertIn('class="header-my-uploads"', body)
            self.assertIn('src="https://cdn.example/avatar.png"', body)
            self.assertIn('view=mine', body)
            if path == "/":
                self.assertIn("Uploading as Support Person", body)
                self.assertIn("New scans will appear in My uploads for 48 hours.", body)

    def test_people_actions_are_hidden_and_rejected_without_support_session(self):
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            payload = self.client.get("/api/people", query_string={"sources": "trending"}).get_json()
        self.assertFalse(payload["actions_enabled"])
        for action in ("check", "flag", "exclude"):
            self.assertEqual(self.client.post(f"/api/people/tmdb-1/{action}").status_code, 404)

    def test_people_actions_are_enabled_for_support_session(self):
        self.authorize_support()
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            payload = self.client.get("/api/people", query_string={"sources": "trending"}).get_json()
        self.assertTrue(payload["actions_enabled"])

    def test_complete_removes_missing_and_temporarily_checks_trending(self):
        self.authorize_support()
        response = self.client.post("/api/people/tmdb-1/check")
        self.assertEqual(response.status_code, 204)
        self.assertEqual([person["tmdb_id"] for person in self.request_people()], [3, 2])

    def test_people_page_uses_card_level_tmdb_guidance(self):
        response = self.client.get("/people")
        html = response.get_data(as_text=True)
        self.assertNotIn("people-status-note", html)
        self.assertNotIn("Image status", html)

    def test_service_activity_is_visible_on_scanner_and_people_pages(self):
        for path in ("/", "/people"):
            html = self.client.get(path).get_data(as_text=True)
            self.assertIn('class="usage-stats"', html)
            self.assertIn("Logs processed", html)
            self.assertIn("Lines processed", html)
            self.assertIn("People submitted", html)
            self.assertIn("People addressed", html)
            self.assertIn("Tracking since", html)

    def test_anonymous_scanner_makes_upload_identity_and_sign_in_visible(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn('class="upload-identity"', html)
        self.assertIn("Keep your scans together", html)
        self.assertIn("find, search, reopen, and delete retained web and Discord uploads", html)
        self.assertIn("helps support identify your scans faster", html)
        self.assertIn("Optional. Anonymous scans still work and expire after 48 hours.", html)
        self.assertIn('class="header-my-uploads"', html)
        self.assertIn("Sign in with Discord", html)

    def test_log_scanner_header_links_to_people(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn('href="/people">People</a>', html)
        self.assertIn('aria-label="All utilities"', html)
        self.assertIn('>Kometa Logscan</span>', html)
        self.assertIn('aria-label="Kometa Logscan home"', html)

    def test_shared_navigation_uses_one_menu_on_desktop_and_mobile(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertNotIn('class="header-primary-links"', html)
        self.assertIn('class="site-nav"', html)
        self.assertIn('class="site-nav-icon"', html)
        self.assertNotIn('>Account</span>', html)
        self.assertIn('aria-current="page">Log Scanner</a>', html)
        self.assertIn("site_nav.js", html)
        self.assertIn('href="https://utilities.kometa.wiki/"', html)
        self.assertIn("Kometa Utilities Home", html)

    def test_people_header_uses_official_kometa_icon(self):
        response = self.client.get("/people")
        self.assertEqual(response.status_code, 200)
        self.assertIn('class="brand-mark" src="/static/logscan.png"', response.get_data(as_text=True))
        self.assertNotIn('<span class="brand-mark">K</span>', response.get_data(as_text=True))

    def test_favicon_is_available_at_browser_default_path(self):
        response = self.client.get("/favicon.ico")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "image/png")
        self.assertGreater(len(response.data), 100)

    def test_analytics_page_is_linked_and_loads_dashboard(self):
        scanner = self.client.get("/").get_data(as_text=True)
        response = self.client.get("/analytics")
        self.assertEqual(response.status_code, 200)
        self.assertIn('href="/analytics">Analytics</a>', scanner)
        self.assertIn('id="analytics-summary"', response.get_data(as_text=True))

    def test_anonymous_analytics_endpoint_contains_only_aggregates(self):
        payload = self.client.get("/api/analytics").get_json()
        self.assertIn("totals", payload)
        self.assertIn("days", payload)
        self.assertNotIn("users", payload)
        self.assertNotIn("filenames", payload)

    def test_api_internal_errors_are_returned_as_json(self):
        app.config["PROPAGATE_EXCEPTIONS"] = False
        try:
            with patch("logscan_web.storage.AnonymousAnalyticsStore.snapshot", side_effect=RuntimeError("private failure detail")):
                response = self.client.get("/api/analytics")
        finally:
            app.config.pop("PROPAGATE_EXCEPTIONS", None)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.mimetype, "application/json")
        self.assertNotIn("private failure detail", response.get_data(as_text=True))

    def test_unconfigured_support_console_uses_themed_503_page(self):
        keys = (
            "DISCORD_CLIENT_ID",
            "DISCORD_CLIENT_SECRET",
            "DISCORD_GUILD_ID",
            "DISCORD_SUPPORT_ROLE_IDS",
            "LOGSCAN_SECRET_KEY",
        )
        previous = {key: app.config.get(key) for key in keys}
        try:
            app.config.update({
                "DISCORD_CLIENT_ID": "",
                "DISCORD_CLIENT_SECRET": "",
                "DISCORD_GUILD_ID": "",
                "DISCORD_SUPPORT_ROLE_IDS": set(),
                "LOGSCAN_SECRET_KEY": "",
            })
            response = self.client.get("/support/logs")
        finally:
            app.config.update(previous)
        html = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 503)
        self.assertIn("Kometa Logscan", html)
        self.assertIn("Discord access needs to be configured", html)
        self.assertNotIn("<h1>Service Unavailable</h1>", html)

    def test_old_beta_routes_are_removed(self):
        self.assertEqual(self.client.get("/people/popular").status_code, 404)
        self.assertEqual(self.client.get("/people/tmdb-1").status_code, 404)
        self.assertEqual(self.client.get("/api/people/popular").status_code, 404)

    def test_legacy_source_filter_does_not_limit_the_unified_page(self):
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get("/api/people?sources=unknown")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["total"], 3)

    def test_people_page_uses_dynamic_tags_and_discreet_examples(self):
        html = self.client.get("/people").get_data(as_text=True)
        self.assertNotIn('class="source-filter"', html)
        self.assertIn('class="tag-filter-examples"', html)
        self.assertIn("Missing Kometa", html)
        script = Path("logscan_web/static/people.js").read_text(encoding="utf-8")
        css = Path("logscan_web/static/styles.css").read_text(encoding="utf-8")
        self.assertIn('person.sources?.includes("missing")', script)
        self.assertIn(".person-card.missing-kometa-person", css)


if __name__ == "__main__":
    unittest.main()
