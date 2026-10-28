import bz2
import gzip
import lzma
import tarfile
import time
import zipfile
from io import BytesIO
from pathlib import Path

import pytest
import zstandard as zstd

from logscan_web import scanner

KOMETA = b"[kometa.py:1] [INFO] | Version: 2.5.3 |\n[kometa.py:2] [INFO] | Finished: today Run Time: 0:00:01 |\n"
IMAGEMAID = b"[imagemaid.py:1] [INFO] | Version: 1.0.0 |\n"
LOG_FILENAMES = [
    "meta.log.1",
    "meta.log.2",
    "meta.log.9",
    "META.LOG.1",
    "Meta.Log.2",
    "report.pdf.1",
    "report.txt.2",
    "config.yaml.9",
    "report.1",
    "meta.log.1.2",
    "meta.log",
    "META.LOG",
    "report.txt",
    "config.yml",
    "config.yaml",
]
INVALID_FILENAMES = ["report.pdf", "report.0", "report.pdf.10", "meta.log.10", "meta.log.old", "meta.log.1.pdf", "meta.log.-1"]


@pytest.mark.parametrize("number", range(1, 10))
def test_numeric_suffixes_match_discord_cog(number):
    assert scanner.is_supported_filename(f"report.{number}")
    assert scanner.is_supported_filename(f".{number}")


@pytest.mark.parametrize("filename", LOG_FILENAMES)
def test_supported_log_filenames_across_validation_and_scanning(filename, tmp_path):
    path = tmp_path / "upload"
    path.write_bytes(KOMETA)
    assert scanner.is_supported_filename(filename)
    assert scanner.is_supported_filename(filename, include_archives=False)
    assert scanner.prepare_scan_input(filename, KOMETA) == (filename, KOMETA)
    assert scanner.find_scannable_upload_path(filename, path) == [(filename, len(KOMETA))]
    assert scanner.find_scannable_archive_logs(filename, KOMETA) == [(filename, len(KOMETA))]
    assert scanner.scan_log(filename, KOMETA).filename == filename


@pytest.mark.parametrize("filename", INVALID_FILENAMES)
def test_invalid_numeric_extensions_are_rejected_even_with_valid_content(filename, tmp_path, monkeypatch):
    path = tmp_path / "upload"
    path.write_bytes(KOMETA)
    monkeypatch.setattr(scanner, "STREAM_SCAN_THRESHOLD", 1)
    assert not scanner.is_supported_filename(filename)
    for operation in (
        lambda: scanner.prepare_scan_input(filename, KOMETA),
        lambda: scanner.find_scannable_upload_path(filename, path),
        lambda: scanner.find_scannable_archive_logs(filename, KOMETA),
        lambda: scanner.scan_archive_path(filename, path),
    ):
        with pytest.raises(scanner.ScanError):
            operation()


@pytest.mark.parametrize("suffix", sorted(scanner.ARCHIVE_SUFFIXES))
def test_supported_archive_filenames(suffix):
    filename = f"logs{suffix.upper()}"
    assert scanner.is_supported_filename(filename)
    assert not scanner.is_supported_filename(filename, include_archives=False)


@pytest.mark.parametrize("content", [b"An unrelated text file", b"[kometa.py:abc] invalid source marker"])
@pytest.mark.parametrize("streaming", [False, True])
def test_rotated_filename_does_not_bypass_content_validation(content, streaming, tmp_path, monkeypatch):
    path = tmp_path / "upload"
    path.write_bytes(content)
    if streaming:
        monkeypatch.setattr(scanner, "STREAM_SCAN_THRESHOLD", 1)
    for operation in (
        lambda: scanner.scan_log("meta.log.1", content),
        lambda: scanner.find_scannable_upload_path("meta.log.1", path),
        lambda: scanner.find_scannable_archive_logs("meta.log.1", content),
        lambda: scanner.scan_archive_path("meta.log.1", path),
    ):
        with pytest.raises(scanner.ScanError):
            operation()


@pytest.mark.parametrize("filename", ["meta.log.1", "meta.log.2", "meta.log.9", "META.LOG.1", "meta.log"])
@pytest.mark.parametrize("content,tool", [(KOMETA, "kometa"), (IMAGEMAID, "imagemaid")])
def test_rotated_logs_use_streaming_scan(filename, content, tool, tmp_path, monkeypatch):
    path = tmp_path / "upload"
    path.write_bytes(content)
    monkeypatch.setattr(scanner, "STREAM_SCAN_THRESHOLD", 1)
    [(name, scanned_content, result)] = scanner.scan_archive_path(filename, path)
    assert name == result.filename == filename
    assert scanned_content == path
    assert result.metadata["tool_name"] == tool


def archive_bytes(kind, members):
    output = BytesIO()
    if kind == "zip":
        with zipfile.ZipFile(output, "w") as archive:
            for name, content in members:
                archive.writestr(name, content)
    else:
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name, content in members:
                entry = tarfile.TarInfo(name)
                entry.size = len(content)
                archive.addfile(entry, BytesIO(content))
    return output.getvalue()


@pytest.mark.parametrize("kind", ["zip", "tar"])
@pytest.mark.parametrize("streaming", [False, True])
def test_archive_discovery_and_scanning_include_rotated_logs(kind, streaming, tmp_path, monkeypatch):
    members = [(f"logs/{name}", KOMETA) for name in ["meta.log.1", "meta.log.2", "meta.log.9", "META.LOG.1", "normal.log"]]
    members.append(("logs/report.pdf.1", KOMETA))
    content = archive_bytes(kind, members + [("report.pdf.10", KOMETA), ("readme.pdf", b"ignored")])
    filename = f"logs.{kind}"
    path = tmp_path / filename
    path.write_bytes(content)
    if streaming:
        monkeypatch.setattr(scanner, "STREAM_SCAN_THRESHOLD", 1)
    expected = [(name, len(data)) for name, data in members]
    assert scanner.find_scannable_upload_path(filename, path) == expected
    _, prepared = scanner.prepare_scan_input(filename, content)
    assert prepared == b"\n\n".join(data for _, data in members)
    if kind == "zip":
        assert scanner.find_scannable_archive_logs(filename, content) == expected
    scans = scanner.scan_archive_path(filename, path)
    try:
        assert [name for name, _, _ in scans] == [name for name, _ in members]
        assert all(result.metadata["tool_name"] == "kometa" for _, _, result in scans)
        assert all(isinstance(data, Path) == streaming for _, data, _ in scans)
    finally:
        for _, data, _ in scans:
            if isinstance(data, Path):
                data.unlink()


@pytest.mark.parametrize("kind", ["zip", "tar"])
def test_archive_with_only_invalid_numeric_extension_is_rejected(kind, tmp_path):
    content = archive_bytes(kind, [("report.pdf.10", KOMETA)])
    filename = f"logs.{kind}"
    path = tmp_path / filename
    path.write_bytes(content)
    for operation in (
        lambda: scanner.prepare_scan_input(filename, content),
        lambda: scanner.find_scannable_upload_path(filename, path),
        lambda: scanner.find_scannable_archive_logs(filename, content),
        lambda: scanner.scan_archive_path(filename, path),
    ):
        with pytest.raises(scanner.ScanError):
            operation()


def test_nested_archive_discovers_rotated_logs():
    nested = archive_bytes("zip", [("logs/meta.log.1", KOMETA)])
    content = archive_bytes("zip", [("nested.zip", nested)])
    assert scanner.prepare_scan_input("logs.zip", content)[1] == KOMETA
    assert [name for name, _, _ in scanner.scan_archive_logs("logs.zip", content)] == ["logs/meta.log.1"]


@pytest.mark.parametrize("suffix,compress", [("gz", gzip.compress), ("bz2", bz2.compress), ("xz", lzma.compress), ("zst", zstd.ZstdCompressor().compress)])
def test_compressed_rotated_logs(suffix, compress, tmp_path):
    filename = f"meta.log.1.{suffix}"
    content = compress(KOMETA)
    path = tmp_path / filename
    path.write_bytes(content)
    assert scanner.prepare_scan_input(filename, content)[1] == KOMETA
    assert scanner.find_scannable_upload_path(filename, path) == [("meta.log.1", len(KOMETA))]
    assert scanner.scan_archive_path(filename, path)[0][2].metadata["tool_name"] == "kometa"


@pytest.fixture
def bot_client(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_STORE", str(tmp_path))
    monkeypatch.setenv("LOGSCAN_API_KEY", "test-secret")
    from logscan_web.app import create_app

    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def validation_result(client, filename, content, background):
    headers = {"Authorization": "Bearer test-secret"}
    job_id = "rotated-log-validation-123456789"
    if background:
        headers["X-Scan-Job-ID"] = job_id
    response = client.post("/api/bot/validate", data={"log": (BytesIO(content), filename)}, headers=headers)
    if not background:
        assert response.status_code == 200
        return response.json
    assert response.status_code == 202
    deadline = time.monotonic() + 5
    while True:
        job = client.get(f"/api/scan-jobs/{job_id}").json
        assert job["phase"] != "failed", job
        if job["phase"] == "complete":
            return job["result"]
        assert time.monotonic() < deadline, job
        time.sleep(0.01)


@pytest.mark.parametrize("filename", ["meta.log.1", "meta.log.2", "meta.log.9", "META.LOG.1", "report.pdf.1", "meta.log"])
@pytest.mark.parametrize("background", [False, True])
def test_bot_validation_returns_usable_result_for_scan_prompt(bot_client, filename, background):
    result = validation_result(bot_client, filename, KOMETA, background)
    assert result == {"files": [{"filename": filename, "content_size": len(KOMETA)}]}
    # The existing cog uses this size and count to accept an attachment and offer its scan prompt.
    assert sum(int(file["content_size"]) for file in result["files"]) == len(KOMETA)
    assert len(result["files"]) == 1
    response = bot_client.post("/api/bot/scan", data={"log": (BytesIO(KOMETA), filename)}, headers={"Authorization": "Bearer test-secret"})
    assert response.status_code == 200
    scan = response.json["scans"][0]
    assert scan["filename"] == filename
    assert scan["metadata"]["tool_name"] == "kometa"
    assert bot_client.get(f'/scan/{scan["id"]}').status_code == 200


@pytest.mark.parametrize("filename,content", [("report.pdf.10", KOMETA), ("meta.log.1", b"Unrelated text"), ("report.pdf.1", b"Unrelated text")])
def test_bot_validation_rejects_invalid_filename_or_content(bot_client, filename, content):
    response = bot_client.post("/api/bot/validate", data={"log": (BytesIO(content), filename)}, headers={"Authorization": "Bearer test-secret"})
    assert response.status_code == 400
    assert response.json["error"]


def test_zip_response_reports_invalid_numeric_extension(bot_client):
    content = archive_bytes("zip", [("meta.log.1", KOMETA), ("normal.log", KOMETA), ("report.pdf.10", KOMETA)])
    response = bot_client.post("/api/bot/scan", data={"log": (BytesIO(content), "logs.zip")}, headers={"Authorization": "Bearer test-secret"})
    assert response.status_code == 200
    assert response.json["unscanned_files"] == [{"filename": "report.pdf.10", "reason": "Bad file extension"}]
