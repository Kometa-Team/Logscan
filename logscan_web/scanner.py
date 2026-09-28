import bz2
import gzip
import lzma
import mmap
import shutil
import tempfile
import re
import tarfile
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path, PurePosixPath
from urllib.parse import unquote

import py7zr
import zstandard as zstd

from .models import ScanContext
from .rules import RuleRegistry, migrated_rules
from .rules.base import TextRule, evaluate_text_rules_bytes
from .categories import category_configuration


MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 3
STREAM_SCAN_THRESHOLD = 64 * 1024 * 1024
ALLOWED_SUFFIXES = {".txt", ".log", ".yml", ".yaml"}
ARCHIVE_SUFFIXES = {
    ".zip", ".7z", ".tar", ".tgz", ".gz", ".bz2", ".tbz2", ".xz", ".txz", ".zst",
}


class ScanError(ValueError):
    pass


def extract_missing_people(content: str) -> list[dict[str, str | bool]]:
    """Return unique People Posters missing from a Kometa log.

    This mirrors the live cog's two signals: a TMDb poster update followed by
    its collection name, and the later "No Poster Found" warning.  The latter
    has no TMDb source image.
    """
    people: dict[str, bool] = {}
    for match in re.finditer(
        r"Detail: tmdb_person updated poster to \[URL\] https?://[^\s|]+"
        r"(?:\s*\|)?\s*\n.*?\n.*?\n.*?Finished (?P<name>.+?) Collection",
        content,
        re.IGNORECASE,
    ):
        name = re.sub(r" \((?:Director|Producer|Writer)\)$", "", match.group("name").strip())
        if name:
            people[name] = True
    for match in re.finditer(
        r"Collection Warning: No Poster Found at https://raw\.githubusercontent\.com/"
        r"Kometa-Team/People-Images[^\s]*?/(?P<name>[^/\s]+?)(?:\.[A-Za-z0-9]+)?(?=\s|$)",
        content,
        re.IGNORECASE,
    ):
        name = unquote(re.sub(r"\.[A-Za-z0-9]+$", "", match.group("name"))).strip()
        if name and name not in people:
            people[name] = False
    return [
        {"name": name, "tmdb_image_found": has_image}
        for name, has_image in people.items()
    ]


def _validate_archive_names(names: list[str]) -> list[str]:
    """Return safe, scannable archive members and ignore everything else."""
    files = []
    for name in names:
        path = PurePosixPath(name.replace("\\", "/"))
        if not name.endswith(("/", "\\")):
            if not path.is_absolute() and ".." not in path.parts and path.suffix.lower() in ALLOWED_SUFFIXES | ARCHIVE_SUFFIXES:
                files.append(name)
    if not files:
        raise ScanError("The archive does not contain any files to scan.")
    return files


def _combine_nested_files(files: list[tuple[str, bytes]], archive_depth: int) -> bytes:
    prepared_files = []
    extracted_size = 0
    for filename, content in files:
        try:
            _filename, prepared = prepare_scan_input(filename, content, archive_depth)
        except ScanError as exc:
            is_nested_archive = Path(filename).suffix.lower() in ARCHIVE_SUFFIXES or filename.lower().endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar.zst"))
            if is_nested_archive and str(exc) == "The archive does not contain any files to scan.":
                continue
            raise
        extracted_size += len(prepared)
        if extracted_size > MAX_FILE_BYTES:
            raise ScanError("The extracted archive contents are larger than the 1 GB limit.")
        prepared_files.append(prepared)
    return b"\n\n".join(prepared_files)


def _extract_zip(filename: str, content_bytes: bytes, archive_depth: int) -> tuple[str, bytes]:
    try:
        with zipfile.ZipFile(BytesIO(content_bytes)) as archive:
            files = _validate_archive_names([entry.filename for entry in archive.infolist()])
            entries = [archive.getinfo(name) for name in files]
            if any(entry.flag_bits & 0x1 for entry in entries):
                raise ScanError("The ZIP contains encrypted files and cannot be scanned.")
            if sum(entry.file_size for entry in entries) > MAX_FILE_BYTES:
                raise ScanError("The extracted ZIP contents are larger than the 1 GB limit.")
            extracted_files = []
            extracted_size = 0
            for entry in entries:
                with archive.open(entry) as member:
                    extracted_file = member.read(MAX_FILE_BYTES - extracted_size + 1)
                extracted_size += len(extracted_file)
                if extracted_size > MAX_FILE_BYTES:
                    raise ScanError("The extracted ZIP contents are larger than the 1 GB limit.")
                extracted_files.append(extracted_file)
            extracted = _combine_nested_files(list(zip(files, extracted_files)), archive_depth)
    except zipfile.BadZipFile as exc:
        raise ScanError("The selected ZIP file is invalid.") from exc

    if not extracted:
        raise ScanError("The ZIP does not contain any text to scan.")
    return f"{Path(filename).stem}.log", extracted


def _extract_tar(filename: str, content_bytes: bytes, archive_depth: int) -> tuple[str, bytes]:
    try:
        with tarfile.open(fileobj=BytesIO(content_bytes), mode="r:*") as archive:
            members = archive.getmembers()
            files = [member for member in members if member.isfile()]
            names = _validate_archive_names([member.name for member in files])
            members_by_name = {member.name: member for member in files}
            scannable_members = [members_by_name[name] for name in names]
            if sum(member.size for member in scannable_members) > MAX_FILE_BYTES:
                raise ScanError("The extracted TAR contents are larger than the 1 GB limit.")
            extracted_files = []
            extracted_size = 0
            for name in names:
                member = members_by_name[name]
                source = archive.extractfile(member)
                if source is None:
                    raise ScanError("The TAR archive could not be extracted.")
                with source:
                    extracted_file = source.read(MAX_FILE_BYTES - extracted_size + 1)
                extracted_size += len(extracted_file)
                if extracted_size > MAX_FILE_BYTES:
                    raise ScanError("The extracted TAR contents are larger than the 1 GB limit.")
                extracted_files.append(extracted_file)
            extracted = _combine_nested_files(list(zip(names, extracted_files)), archive_depth)
    except tarfile.TarError as exc:
        raise ScanError("The selected TAR file is invalid.") from exc
    if not extracted:
        raise ScanError("The archive does not contain any text to scan.")
    return f"{Path(filename).stem}.log", extracted


def _extract_gzip(filename: str, content_bytes: bytes, archive_depth: int) -> tuple[str, bytes]:
    try:
        with gzip.GzipFile(fileobj=BytesIO(content_bytes), mode="rb") as archive:
            extracted = archive.read(MAX_FILE_BYTES + 1)
    except (gzip.BadGzipFile, EOFError, OSError) as exc:
        raise ScanError("The selected GZIP file is invalid.") from exc
    if not extracted:
        raise ScanError("The GZIP file does not contain any text to scan.")
    if len(extracted) > MAX_FILE_BYTES:
        raise ScanError("The extracted GZIP contents are larger than the 1 GB limit.")
    _inner_filename, extracted = prepare_scan_input(Path(filename).stem, extracted, archive_depth)
    return f"{Path(filename).stem}.log", extracted


def _extract_bzip2(
    filename: str, content_bytes: bytes, archive_depth: int,
) -> tuple[str, bytes]:
    try:
        with bz2.BZ2File(BytesIO(content_bytes), mode="rb") as archive:
            extracted = archive.read(MAX_FILE_BYTES + 1)
    except (EOFError, OSError) as exc:
        raise ScanError("The selected BZIP2 file is invalid.") from exc
    return _prepare_decompressed_log(filename, extracted, archive_depth, "BZIP2")


def _extract_xz(
    filename: str, content_bytes: bytes, archive_depth: int,
) -> tuple[str, bytes]:
    try:
        with lzma.LZMAFile(BytesIO(content_bytes), mode="rb") as archive:
            extracted = archive.read(MAX_FILE_BYTES + 1)
    except (EOFError, lzma.LZMAError, OSError) as exc:
        raise ScanError("The selected XZ file is invalid.") from exc
    return _prepare_decompressed_log(filename, extracted, archive_depth, "XZ")


def _decompress_zstandard(content_bytes: bytes) -> bytes:
    try:
        with zstd.ZstdDecompressor().stream_reader(BytesIO(content_bytes)) as archive:
            extracted = archive.read(MAX_FILE_BYTES + 1)
        if len(extracted) > MAX_FILE_BYTES:
            raise ScanError("The extracted Zstandard contents are larger than the 1 GB limit.")
        return extracted
    except zstd.ZstdError as exc:
        raise ScanError("The selected Zstandard file is invalid.") from exc


def _extract_zstandard(
    filename: str, content_bytes: bytes, archive_depth: int,
) -> tuple[str, bytes]:
    return _prepare_decompressed_log(
        filename,
        _decompress_zstandard(content_bytes),
        archive_depth,
        "Zstandard",
    )


def _prepare_decompressed_log(
    filename: str,
    extracted: bytes,
    archive_depth: int,
    format_name: str,
) -> tuple[str, bytes]:
    if not extracted:
        raise ScanError(f"The {format_name} file does not contain any text to scan.")
    if len(extracted) > MAX_FILE_BYTES:
        raise ScanError(f"The extracted {format_name} contents are larger than the 1 GB limit.")
    inner_filename = Path(filename).stem
    _inner_filename, extracted = prepare_scan_input(inner_filename, extracted, archive_depth)
    return f"{inner_filename}.log", extracted

def _extract_7z(filename: str, content_bytes: bytes, archive_depth: int) -> tuple[str, bytes]:
    try:
        with tempfile.TemporaryDirectory(prefix="logscan-7z-") as directory:
            archive_path = Path(directory, "upload.7z")
            archive_path.write_bytes(content_bytes)
            with py7zr.SevenZipFile(archive_path, mode="r") as archive:
                entries = archive.list()
                names = _validate_archive_names([entry.filename for entry in entries])
                selected = [entry for entry in entries if entry.filename in names]
                if sum(entry.uncompressed or 0 for entry in selected) > MAX_FILE_BYTES:
                    raise ScanError("The extracted 7-Zip contents are larger than the 1 GB limit.")
                archive.extract(path=directory, targets=names)
            extracted_files = []
            extracted_size = 0
            for name in names:
                extracted_path = Path(directory, *PurePosixPath(name.replace("\\", "/")).parts)
                content = extracted_path.read_bytes()
                extracted_size += len(content)
                if extracted_size > MAX_FILE_BYTES:
                    raise ScanError("The extracted 7-Zip contents are larger than the 1 GB limit.")
                extracted_files.append(content)
            extracted = _combine_nested_files(list(zip(names, extracted_files)), archive_depth)
    except py7zr.Bad7zFile as exc:
        raise ScanError("The selected 7-Zip file is invalid.") from exc
    if not extracted:
        raise ScanError("The 7-Zip archive does not contain any text to scan.")
    return f"{Path(filename).stem}.log", extracted

def prepare_scan_input(filename: str, content_bytes: bytes, archive_depth: int = 0) -> tuple[str, bytes]:
    """Validate an upload and return the text that should be stored and scanned."""
    suffix = Path(filename).suffix.lower()
    if suffix in ARCHIVE_SUFFIXES or filename.lower().endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar.zst")):
        if archive_depth >= MAX_ARCHIVE_DEPTH:
            raise ScanError("Archives may be nested no more than three levels deep.")
    if suffix == ".zip":
        return _extract_zip(filename, content_bytes, archive_depth + 1)
    if suffix == ".7z":
        return _extract_7z(filename, content_bytes, archive_depth + 1)
    if filename.lower().endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar")):
        return _extract_tar(filename, content_bytes, archive_depth + 1)
    if filename.lower().endswith(".tar.zst"):
        tar_content = _decompress_zstandard(content_bytes)
        return _extract_tar(Path(filename).stem, tar_content, archive_depth + 1)
    if suffix == ".gz":
        return _extract_gzip(filename, content_bytes, archive_depth + 1)
    if suffix == ".bz2":
        return _extract_bzip2(filename, content_bytes, archive_depth + 1)
    if suffix == ".xz":
        return _extract_xz(filename, content_bytes, archive_depth + 1)
    if suffix == ".zst":
        return _extract_zstandard(filename, content_bytes, archive_depth + 1)
    if suffix not in ALLOWED_SUFFIXES and not suffix.lstrip(".").isdigit():
        raise ScanError("Choose a Kometa log, text, YAML, ZIP, 7-Zip, TAR, GZIP, BZIP2, XZ, or Zstandard file.")
    return filename, content_bytes


@dataclass(frozen=True)
class ScanResult:
    filename: str
    recommendations: list[dict]
    metadata: dict
    overview: dict
    categories: list[dict]
    missing_people: list[dict[str, str | bool]]


def _plain_title(value: str) -> str:
    value = re.sub(r"[*_`]+", "", value or "")
    value = re.sub(
        r"^[^\w]+",
        "",
        value,
        flags=re.UNICODE,
    )
    value = re.sub(r"\]+$", "", value.strip()).strip()
    return value or "Recommendation"


def _strip_emojis(value: str) -> str:
    """Remove emoji glyphs and selectors while preserving ordinary punctuation."""
    value = re.sub(
        "["
        "\U0001F1E6-\U0001F1FF"
        "\U0001F300-\U0001FAFF"
        "\u2300-\u23FF"
        "\u2600-\u27BF"
        "]+",
        "",
        value or "",
    )
    return value.replace("\uFE0F", "").replace("\u200D", "")


def _severity(first_line: str) -> str:
    if first_line.startswith(("🚀", "💥", "❌")):
        return "critical"
    if first_line.startswith("⚠"):
        return "warning"
    title = _plain_title(first_line).lower()
    if any(term in title for term in (
        "failed", "invalid", "error", "vulnerable", "exceeds available",
        "required api key", "required service", "unhandled", "incomplete",
        "unreadable", "subscription", "prerequisite", "api limit",
        "request limit", "could not be parsed", "already contains",
        "image file is missing", "font file is missing", "unknown plex library",
        "plex library was not found", "connection timed out",
    )):
        return "critical"
    if any(term in title for term in (
        "warning", "legacy", "detected", "matched no items", "no matching",
        "low memory", "memory below", "insufficient memory", "run order",
        "maintenance", "run exceeds", "rounding issue",
    )):
        return "warning"
    return "advice"


def _first_value(content: str, label: str) -> str | None:
    match = re.search(rf"\b{re.escape(label)}:\s*(.+?)(?:\s*\|)?\s*$", content, re.MULTILINE)
    return match.group(1).strip() if match else None


def _date_first(value: str | None) -> str | None:
    if not value:
        return None
    match = re.fullmatch(r"(\d{1,2}:\d{2}:\d{2})\s+(\d{4}-\d{2}-\d{2})", value)
    return f"{match.group(2)} {match.group(1)}" if match else value


def normalized_platform(value: str | None) -> str:
    """Reduce a detailed runtime platform string to a non-identifying family."""
    lowered = (value or "").casefold()
    if "wsl" in lowered or "microsoft-standard" in lowered:
        return "WSL"
    if "windows" in lowered:
        return "Windows"
    if "linux" in lowered:
        return "Linux"
    if "darwin" in lowered or "macos" in lowered or "mac os" in lowered:
        return "macOS"
    if "freebsd" in lowered:
        return "FreeBSD"
    return "Unknown"


def normalized_installation(version: str | None) -> str:
    """Return an anonymous install family only when the log states it explicitly."""
    lowered = (version or "").casefold()
    if "linuxserver" in lowered:
        return "Docker (LinuxServer)"
    if "docker" in lowered:
        return "Docker"
    if re.search(r"\(python(?:\s|\d)", lowered):
        return "Native Python"
    return "Unknown"

def apply_documentation_branch(recommendations: list[dict], branch: str) -> None:
    """Point Kometa Wiki links at the scanned release channel's documentation."""
    documentation_branch = "develop" if branch in {"develop", "nightly"} else "latest"
    target = f"https://www.kometa.wiki/en/{documentation_branch}/"
    pattern = re.compile(r"https://(?:www\.)?kometa\.wiki/en/(?:latest|develop)/", re.I)
    for recommendation in recommendations:
        for field in ("solution", "message"):
            value = recommendation.get(field)
            if isinstance(value, str):
                recommendation[field] = pattern.sub(target, value)


def _log_message(line: str) -> str:
    """Return the readable message from a Kometa log line."""
    match = re.match(
        r"^(?:\[[^\]]+\]\s+)*\[[^\]]+\.py:\d+\]\s+\[[A-Z]+\]\s*\|\s?(.*?)\s*\|?\s*$",
        line,
    )
    return match.group(1).strip() if match else line.strip().strip("|").strip()


def _plex_configuration_section(lines: list[str], number: int) -> dict[str, object]:
    """Build a Plex configuration section with a useful library label."""
    name = next(
        (match.group(1).strip() for line in lines if (match := re.fullmatch(r"Connected to library\s+(.+)", line, re.I))),
        None,
    )
    library_type = next(
        (match.group(1).title() for line in lines if (match := re.fullmatch(r"Type:\s*(Movie|Show|Music)", line, re.I))),
        None,
    )
    if library_type and name:
        label = f"{library_type}: {name}"
    else:
        label = library_type or name or f"Section {number}"
    return {"title": f"Plex Configuration - {label}", "lines": lines}


def extract_plex_configurations(content: str) -> list[dict[str, object]]:
    """Extract the informational Plex configuration blocks shown by Kometa."""
    sections: list[dict[str, object]] = []
    current: list[str] | None = None
    for raw_line in content.splitlines():
        message = _log_message(raw_line)
        if "Plex Configuration" in message:
            if current:
                sections.append(_plex_configuration_section(current, len(sections) + 1))
            current = []
            continue
        if current is None:
            continue
        if re.search(r"\bScanning\b", message) or "Library Connection Failed" in message:
            if current:
                sections.append(_plex_configuration_section(current, len(sections) + 1))
            current = None
            continue
        if message and not re.fullmatch(r"[-=]+", message):
            current.append(message)
    if current:
        sections.append(_plex_configuration_section(current, len(sections) + 1))
    return sections


def plex_analytics(sections: list[dict[str, object]]) -> dict[str, list[str]]:
    """Return bounded Plex categories that are safe to persist as aggregates."""
    values = {
        "versions": [], "platforms": [], "update_channels": [],
        "library_types": [], "agents": [], "scanners": [],
    }
    for section in sections:
        lines = [str(line) for line in section.get("lines", [])]
        for line in lines:
            version = re.search(r"\bversion\s+(\d+\.\d+\.\d+\.\d+(?:-[A-Za-z0-9]+)?)\b", line, re.I)
            if version:
                values["versions"].append(version.group(1))
            platform = re.search(r"\bRunning on\s+(Windows|Linux|macOS|Darwin|FreeBSD)\b", line, re.I)
            if platform:
                family = platform.group(1).casefold()
                values["platforms"].append("macOS" if family in {"macos", "darwin"} else family.title())
            channel = re.search(r"\bon\s+(Public|Beta)\s+update channel\b", line, re.I)
            if channel:
                values["update_channels"].append(channel.group(1).title())
            library_type = re.fullmatch(r"Type:\s*(Movie|Show|Music)", line, re.I)
            if library_type:
                values["library_types"].append(library_type.group(1).title())
            agent = re.fullmatch(r"Agent:\s*([A-Za-z0-9._-]{1,80})", line)
            if agent:
                values["agents"].append(agent.group(1))
            scanner = re.fullmatch(
                r"Scanner:\s*(Plex Movie|Plex TV Series|Plex Music|Plex Video Files|Plex Photo Scanner)",
                line,
                re.I,
            )
            if scanner:
                values["scanners"].append(scanner.group(1).title())
    return values


def _runtime_seconds(value: str) -> int | None:
    """Convert a Kometa duration to seconds."""
    match = re.fullmatch(
        r"(?:(?P<days>\d+)\s+days?,\s*)?(?P<hours>\d+):(?P<minutes>\d{2}):(?P<seconds>\d{2})(?:\.\d+)?",
        value.strip(),
        re.I,
    )
    if not match:
        return None
    return (
        int(match.group("days") or 0) * 86400
        + int(match.group("hours")) * 3600
        + int(match.group("minutes")) * 60
        + int(match.group("seconds"))
    )


def extract_section_run_times(content: str) -> list[dict[str, object]]:
    """Return the longest non-zero Kometa section runtimes."""
    messages = [(_log_message(line), number) for number, line in enumerate(content.splitlines(), 1)]
    runtimes: list[dict[str, object]] = []
    for index, (message, line_number) in enumerate(messages):
        finished_with_runtime = re.match(r"^Finished\s+(?!:)(.+?)\s+Run Time:\s*(.+)$", message, re.I)
        finished = finished_with_runtime or re.match(r"^Finished\s+(?!:)(.+)$", message, re.I)
        if not finished:
            continue
        name = finished.group(1).strip().rstrip("|").strip()
        duration = finished_with_runtime.group(2) if finished_with_runtime else None
        if not duration and index + 1 < len(messages):
            runtime_match = re.search(r"\bRun Time:\s*([^|]+)", messages[index + 1][0], re.I)
            duration = runtime_match.group(1).strip() if runtime_match else None
        seconds = _runtime_seconds(duration or "")
        if not name or not seconds:
            continue
        runtimes.append({
            "name": name,
            "duration": duration,
            "seconds": seconds,
            "line": line_number,
        })
    return sorted(runtimes, key=lambda item: int(item["seconds"]), reverse=True)


def _log_overview(
    filename: str,
    content: str,
    kometa_version: str | None,
    run_time: str | None,
    recommendations: list[dict],
) -> dict:
    yaml_findings = [item for item in recommendations if item["severity"] == "schema"]
    yaml_status = (
        f"{len(yaml_findings)} configuration validation issue"
        f"{'' if len(yaml_findings) == 1 else 's'} detected in log"
        if yaml_findings
        else "Live schema validation pending"
    )
    completed_run = re.search(
        r"Start Time:\s*(?P<start>.*?)\s+Finished:\s*(?P<end>.*?)\s+Run Time:\s*(?P<runtime>[^|\r\n]+)",
        content,
    )
    plex_configurations = extract_plex_configurations(content)
    return {
        "log_name": filename,
        "recommendation_count": len(recommendations),
        "kometa_version": kometa_version,
        "newest_version_at_run": _first_value(content, "Newest Version"),
        "platform": _first_value(content, "Platform"),
        "total_memory": _first_value(content, "Memory"),
        "available_memory": _first_value(content, "Available Memory"),
        "run_command": _first_value(content, "Run Command"),
        "start_time": _date_first(completed_run.group("start").strip()) if completed_run else _first_value(content, "Started"),
        "finished": _date_first(completed_run.group("end").strip()) if completed_run else _first_value(content, "Finished"),
        "run_time": (
            completed_run.group("runtime").strip()
            if completed_run else run_time
        ),
        "yaml_validation": yaml_status,
        "yaml_issue_count": len(yaml_findings),
        "section_run_times": extract_section_run_times(content),
        "plex_configurations": plex_configurations,
        "plex_analytics": plex_analytics(plex_configurations),
    }


def _scan_large_log(filename: str, content_bytes) -> ScanResult:
    """Scan a large log while decoding only lines needed by structural rules."""
    rules = migrated_rules()
    text_rules = [rule for rule in rules if isinstance(rule, TextRule)]
    custom_rules = [rule for rule in rules if not isinstance(rule, TextRule)]
    findings = evaluate_text_rules_bytes(text_rules, content_bytes)

    sample_terms = (
        b"[kometa.py:", b"[plex_meta_manager.py:", b"version:", b"branch:",
        b"[quickstart]", b"finished:", b"finished ", b"run time:", b"start time:", b"started:",
        b"platform:", b"memory:", b"available memory:", b"run command:",
        b"plex db cache setting:", b"overlay_path:", b"overlay_files:", b"--time",
        b"plex configuration", b"using asset directory", b"scheduled maintenance",
        b"connected to server", b"running on", b"plexpass:", b"connected to library",
        b"type:", b"agent:", b"scanner:", b"ratings source:",
        b"library connection successful", b"library connection failed",
        b"scanning metadata", b"run_order:",
        b"- operations", b"mass_user_rating_update", b"mass_episode_user_ratings_update",
    )
    missing_terms = (b"tmdb_person updated poster", b"collection warning: no poster found")
    sparse_pattern = re.compile(b"|".join(re.escape(term) for term in sample_terms + missing_terms), re.I)
    sampled_lines: dict[int, str] = {}
    missing_lines: list[str] = []
    marker_found = False
    complete_log = False
    content_length = len(content_bytes)
    chunk_size = 4 * 1024 * 1024
    overlap = 64 * 1024
    chunk_start = 0
    lines_before_chunk = 0

    def decoded_line(start: int) -> tuple[str, int]:
        end = content_bytes.find(b"\n", start)
        if end < 0:
            end = content_length
        return content_bytes[start:end].decode("utf-8", errors="replace").rstrip("\r"), end

    while chunk_start < content_length:
        chunk_end = min(content_length, chunk_start + chunk_size)
        scan_end = min(content_length, chunk_end + overlap)
        chunk = content_bytes[chunk_start:scan_end]
        core_length = chunk_end - chunk_start
        newline_cursor = 0
        current_line = lines_before_chunk + 1
        for match in sparse_pattern.finditer(chunk):
            if match.start() >= core_length:
                break
            current_line += chunk.count(b"\n", newline_cursor, match.start())
            newline_cursor = match.start()
            global_match = chunk_start + match.start()
            line_start = content_bytes.rfind(b"\n", 0, global_match) + 1
            line, line_end = decoded_line(line_start)
            lowered_term = match.group(0).lower()
            if lowered_term in (b"[kometa.py:", b"[plex_meta_manager.py:"):
                marker_found = True
            if lowered_term in sample_terms:
                sampled_lines.setdefault(current_line, line)
                if lowered_term == b"run_order:" and line_end < content_length:
                    next_line, _next_end = decoded_line(line_end + 1)
                    sampled_lines.setdefault(current_line + 1, next_line)
                complete_log |= b"finished:" in line.lower().encode() and b"run time:" in line.lower().encode()
            if lowered_term in missing_terms:
                block_end = line_end
                for _ in range(4 if lowered_term == b"tmdb_person updated poster" else 0):
                    if block_end >= content_length:
                        break
                    _next_line, block_end = decoded_line(block_end + 1)
                missing_lines.append(content_bytes[line_start:block_end].decode("utf-8", errors="replace"))
        core = chunk[:core_length]
        lines_before_chunk += core.count(b"\n")
        chunk_start = chunk_end

    line_count = lines_before_chunk + int(bool(content_length) and content_bytes[content_length - 1] != 10)
    sampled = [
        "\n" * max(0, number - previous - 1) + sampled_lines[number]
        for previous, number in zip([0, *sorted(sampled_lines)[:-1]], sorted(sampled_lines))
    ]
    if not marker_found:
        raise ScanError("This does not appear to be a complete Kometa log file.")

    sample_content = "\n".join(sampled)
    version_match = re.search(r"\bVersion:\s*([^|\r\n]+)", sample_content)
    kometa_version = version_match.group(1).strip() if version_match else None
    branch_match = re.search(r"\(Branch:\s*(master|develop|nightly)\)", sample_content, re.I)
    kometa_branch = branch_match.group(1).casefold() if branch_match else "unknown"
    quickstart_metadata = extract_quickstart_metadata(sample_content)
    run_match = re.search(r"\bFinished:.*?\bRun Time:\s*([^|\r\n]+)", sample_content)
    detected_run_time = run_match.group(1).strip() if run_match else None
    context = ScanContext.from_content(
        filename, sample_content, kometa_version=kometa_version,
        run_time=detected_run_time, complete=complete_log,
    )
    findings.extend(finding for rule in custom_rules for finding in rule.evaluate(context))
    normalized = [finding.as_dict() for finding in findings]
    apply_documentation_branch(normalized, kometa_branch)
    normalized.sort(key=lambda item: {"critical": 0, "error": 1, "warning": 2, "schema": 3, "advice": 4}[item["severity"]])
    runtime_platform = _first_value(sample_content, "Platform")
    metadata = {
        "kometa_version": kometa_version,
        "newest_version_at_run": _first_value(sample_content, "Newest Version"),
        "kometa_branch": kometa_branch,
        **quickstart_metadata,
        "runtime_platform": normalized_platform(runtime_platform),
        "installation_method": normalized_installation(kometa_version),
        "run_time": str(detected_run_time) if detected_run_time else None,
        "complete": complete_log,
        "header_found": kometa_version is not None,
        "line_count": line_count,
        "size_bytes": len(content_bytes),
        "counts": {
            level: sum(item["severity"] == level for item in normalized)
            for level in ("critical", "warning", "schema", "advice")
        },
    }
    return ScanResult(
        filename=filename,
        recommendations=normalized,
        metadata=metadata,
        overview=_log_overview(filename, sample_content, kometa_version, detected_run_time, normalized),
        categories=category_configuration(),
        missing_people=extract_missing_people("\n".join(missing_lines)),
    )

def extract_quickstart_metadata(content: str) -> dict:
    """Extract non-sensitive Quickstart launcher metadata from a Kometa log."""
    marker = re.search(r"\[Quickstart\]\s+Run marker:[^\r\n]*", content, re.IGNORECASE)
    fields = {
        key.casefold(): value
        for key, value in re.findall(r"\b(quickstart|branch)=([^\s|]+)", marker.group(0), re.IGNORECASE)
    } if marker else {}
    branch = fields.get("branch", "unknown").casefold()
    if branch not in {"master", "develop"}:
        branch = "unknown"
    return {
        "quickstart_run": bool(marker),
        "quickstart_version": fields.get("quickstart"),
        "quickstart_branch": branch,
    }


def scan_log(filename: str, content_bytes: bytes) -> ScanResult:
    filename, content_bytes = prepare_scan_input(filename, content_bytes)
    if not content_bytes:
        raise ScanError("The selected file is empty.")
    if len(content_bytes) > MAX_FILE_BYTES:
        raise ScanError("The selected file is larger than the 1 GB limit.")

    content = content_bytes.decode("utf-8", errors="replace")
    if not re.search(r"\[(?:kometa|plex_meta_manager)\.py:", content, re.IGNORECASE):
        raise ScanError("This does not appear to be a complete Kometa log file.")

    version_match = re.search(r"\bVersion:\s*([^|\r\n]+)", content)
    kometa_version = version_match.group(1).strip() if version_match else None
    kometa_branch_match = re.search(r"\(Branch:\s*(master|develop|nightly)\)", content, re.IGNORECASE)
    kometa_branch = kometa_branch_match.group(1).casefold() if kometa_branch_match else "unknown"
    quickstart_metadata = extract_quickstart_metadata(content)
    run_match = re.search(r"\bFinished:.*?\bRun Time:\s*([^|\r\n]+)", content)
    detected_run_time = run_match.group(1).strip() if run_match else None
    context = ScanContext.from_content(
        filename,
        content,
        kometa_version=kometa_version,
        run_time=detected_run_time,
        complete=detected_run_time is not None,
    )
    registry = RuleRegistry()
    for rule in migrated_rules():
        registry.register(rule)
    normalized = [finding.as_dict() for finding in registry.evaluate(context)]
    apply_documentation_branch(normalized, kometa_branch)
    normalized.sort(key=lambda item: {"critical": 0, "error": 1, "warning": 2, "schema": 3, "advice": 4}[item["severity"]])

    runtime_platform = _first_value(content, "Platform")
    metadata = {
        "kometa_version": kometa_version,
        "newest_version_at_run": _first_value(content, "Newest Version"),
        "kometa_branch": kometa_branch,
        **quickstart_metadata,
        "runtime_platform": normalized_platform(runtime_platform),
        "installation_method": normalized_installation(kometa_version),
        "run_time": str(detected_run_time) if detected_run_time else None,
        "complete": detected_run_time is not None,
        "header_found": kometa_version is not None,
        "line_count": content.count("\n") + int(bool(content) and not content.endswith("\n")),
        "size_bytes": len(content_bytes),
        "counts": {
            level: sum(item["severity"] == level for item in normalized)
            for level in ("critical", "warning", "schema", "advice")
        },
    }
    return ScanResult(
        filename=filename,
        recommendations=normalized,
        metadata=metadata,
        overview=_log_overview(filename, content, kometa_version, detected_run_time, normalized),
        categories=category_configuration(),
        missing_people=extract_missing_people(content),
    )


def _scan_large_path(filename: str, path: Path) -> ScanResult:
    with path.open("rb") as source:
        with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as content:
            return _scan_large_log(filename, content)


def scan_content_size(content: bytes | Path) -> int:
    return content.stat().st_size if isinstance(content, Path) else len(content)


def scan_archive_logs(filename: str, content_bytes: bytes) -> list[tuple[str, bytes | Path, ScanResult]]:
    """Return one scan input and result for every valid Kometa log in a ZIP."""
    def collect(name: str, content: bytes, depth: int) -> list[tuple[str, bytes, ScanResult]]:
        if Path(name).suffix.lower() == ".zip":
            if depth >= MAX_ARCHIVE_DEPTH:
                raise ScanError("Archives may be nested no more than three levels deep.")
            try:
                with zipfile.ZipFile(BytesIO(content)) as archive:
                    files = _validate_archive_names([entry.filename for entry in archive.infolist()])
                    entries = [archive.getinfo(member) for member in files]
                    if any(entry.flag_bits & 0x1 for entry in entries):
                        raise ScanError("The ZIP contains encrypted files and cannot be scanned.")
                    if sum(entry.file_size for entry in entries) > MAX_FILE_BYTES:
                        raise ScanError("The extracted ZIP contents are larger than the 1 GB limit.")
                    results = []
                    for entry in entries:
                        with archive.open(entry) as member:
                            if entry.file_size >= STREAM_SCAN_THRESHOLD and Path(entry.filename).suffix.lower() in ALLOWED_SUFFIXES:
                                temporary = tempfile.NamedTemporaryFile(prefix="logscan-", suffix=".log", delete=False)
                                temporary_path = Path(temporary.name)
                                try:
                                    with temporary:
                                        shutil.copyfileobj(member, temporary, length=1024 * 1024)
                                    result = _scan_large_path(entry.filename, temporary_path)
                                    results.append((entry.filename, temporary_path, result))
                                except Exception:
                                    temporary_path.unlink(missing_ok=True)
                                    raise
                            else:
                                results.extend(collect(entry.filename, member.read(), depth + 1))
                    return results
            except zipfile.BadZipFile as exc:
                raise ScanError("The selected ZIP file is invalid.") from exc
            except ScanError as exc:
                if depth > 0 and str(exc) == "The archive does not contain any files to scan.":
                    return []
                raise
        try:
            prepared_name, prepared_content = prepare_scan_input(name, content, depth)
            return [(prepared_name, prepared_content, scan_log(prepared_name, prepared_content))]
        except ScanError:
            return []

    scans = collect(filename, content_bytes, 0)
    total_size = sum(scan_content_size(content) for _name, content, _result in scans)
    if total_size > MAX_FILE_BYTES:
        raise ScanError("The extracted archive contents are larger than the 1 GB limit.")
    if not scans:
        raise ScanError("The archive does not contain a complete Kometa log file.")
    return scans


def _stream_kometa_marker_and_size(source) -> tuple[bool, int]:
    carry = b""
    size = 0
    marker_found = False
    while chunk := source.read(1024 * 1024):
        size += len(chunk)
        if size > MAX_FILE_BYTES:
            raise ScanError("The extracted archive contents are larger than the 1 GB limit.")
        lowered = (carry + chunk).lower()
        marker_found = marker_found or b"[kometa.py:" in lowered or b"[plex_meta_manager.py:" in lowered
        carry = chunk[-32:]
    return marker_found, size


def _stream_contains_kometa_marker(source) -> bool:
    return _stream_kometa_marker_and_size(source)[0]


def _find_scannable_tar_path(path: Path) -> list[tuple[str, int]]:
    try:
        with tarfile.open(path, mode="r:*") as archive:
            found = []
            for entry in archive.getmembers():
                if not entry.isfile() or Path(entry.name).suffix.lower() not in ALLOWED_SUFFIXES:
                    continue
                member = archive.extractfile(entry)
                if member is not None:
                    with member:
                        if _stream_contains_kometa_marker(member):
                            found.append((entry.name, entry.size))
            if found:
                return found
    except (tarfile.TarError, OSError) as exc:
        raise ScanError("The selected TAR file is invalid.") from exc
    raise ScanError("The archive does not contain a complete Kometa log file.")


def _find_scannable_zstandard_tar(path: Path) -> list[tuple[str, int]]:
    temporary = tempfile.NamedTemporaryFile(prefix="logscan-zstd-", suffix=".tar", delete=False)
    temporary_path = Path(temporary.name)
    try:
        extracted_size = 0
        with path.open("rb") as compressed, zstd.ZstdDecompressor().stream_reader(compressed) as source, temporary:
            while chunk := source.read(1024 * 1024):
                extracted_size += len(chunk)
                if extracted_size > MAX_FILE_BYTES:
                    raise ScanError("The extracted Zstandard contents are larger than the 1 GB limit.")
                temporary.write(chunk)
        return _find_scannable_tar_path(temporary_path)
    except zstd.ZstdError as exc:
        raise ScanError("The selected Zstandard file is invalid.") from exc
    finally:
        temporary_path.unlink(missing_ok=True)


def _find_scannable_compressed_log(
    filename: str, path: Path, suffix: str,
) -> list[tuple[str, int]]:
    compressed = None
    try:
        if suffix == ".gz":
            source = gzip.GzipFile(filename=path, mode="rb")
        elif suffix == ".bz2":
            source = bz2.BZ2File(path, mode="rb")
        elif suffix == ".xz":
            source = lzma.LZMAFile(path, mode="rb")
        else:
            compressed = path.open("rb")
            source = zstd.ZstdDecompressor().stream_reader(compressed)
        with source:
            found, extracted_size = _stream_kometa_marker_and_size(source)
    except (gzip.BadGzipFile, EOFError, lzma.LZMAError, OSError, zstd.ZstdError) as exc:
        names = {".gz": "GZIP", ".bz2": "BZIP2", ".xz": "XZ", ".zst": "Zstandard"}
        raise ScanError(f"The selected {names[suffix]} file is invalid.") from exc
    finally:
        if compressed is not None:
            compressed.close()
    if found:
        return [(Path(filename).stem, extracted_size)]
    raise ScanError("The archive does not contain a complete Kometa log file.")

def find_scannable_upload_path(filename: str, path: Path) -> list[tuple[str, int]]:
    """Identify logs in a spooled upload without retaining the upload in memory."""
    size = path.stat().st_size
    if not size:
        raise ScanError("The selected file is empty.")
    if size > MAX_FILE_BYTES:
        raise ScanError("The selected file is larger than the 1 GB limit.")
    lowered_filename = filename.lower()
    suffix = Path(filename).suffix.lower()
    tar_suffixes = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
    if lowered_filename.endswith(tar_suffixes):
        return _find_scannable_tar_path(path)
    if lowered_filename.endswith(".tar.zst"):
        return _find_scannable_zstandard_tar(path)
    if suffix in {".gz", ".bz2", ".xz", ".zst"}:
        return _find_scannable_compressed_log(filename, path, suffix)
    if suffix == ".7z":
        prepared_name, prepared_content = _extract_7z(filename, path.read_bytes(), 1)
        if _stream_contains_kometa_marker(BytesIO(prepared_content)):
            return [(prepared_name, len(prepared_content))]
        raise ScanError("The archive does not contain a complete Kometa log file.")
    if suffix != ".zip":
        if suffix not in ALLOWED_SUFFIXES:
            raise ScanError("Choose a Kometa log, text, YAML, ZIP, 7-Zip, TAR, GZIP, BZIP2, XZ, or Zstandard file.")
        with path.open("rb") as source:
            if _stream_contains_kometa_marker(source):
                return [(filename, size)]
        raise ScanError("This does not appear to be a complete Kometa log file.")
    try:
        with zipfile.ZipFile(path) as archive:
            found = []
            for entry in archive.infolist():
                if entry.is_dir() or Path(entry.filename).suffix.lower() not in ALLOWED_SUFFIXES:
                    continue
                with archive.open(entry) as member:
                    if _stream_contains_kometa_marker(member):
                        found.append((entry.filename, entry.file_size))
            if found:
                return found
    except zipfile.BadZipFile as exc:
        raise ScanError("The selected ZIP file is invalid.") from exc
    raise ScanError("The archive does not contain a complete Kometa log file.")

def find_scannable_archive_logs(filename: str, content_bytes: bytes) -> list[tuple[str, int]]:
    """Permissively identify Kometa logs before the strict scan validates every entry."""
    if Path(filename).suffix.lower() != ".zip":
        result = scan_log(filename, content_bytes)
        return [(result.filename, len(content_bytes))]
    try:
        with zipfile.ZipFile(BytesIO(content_bytes)) as archive:
            found = []
            for entry in archive.infolist():
                if entry.is_dir() or Path(entry.filename).suffix.lower() not in ALLOWED_SUFFIXES:
                    continue
                if entry.file_size >= STREAM_SCAN_THRESHOLD:
                    marker_found = False
                    carry = b""
                    with archive.open(entry) as member:
                        while chunk := member.read(1024 * 1024):
                            lowered = (carry + chunk).lower()
                            if b"[kometa.py:" in lowered or b"[plex_meta_manager.py:" in lowered:
                                marker_found = True
                                break
                            carry = chunk[-32:]
                    if marker_found:
                        found.append((entry.filename, entry.file_size))
                    continue
                with archive.open(entry) as member:
                    content = member.read()
                try:
                    result = scan_log(entry.filename, content)
                except ScanError:
                    continue
                found.append((result.filename, len(content)))
            if found:
                return found
    except zipfile.BadZipFile as exc:
        raise ScanError("The selected ZIP file is invalid.") from exc
    raise ScanError("The archive does not contain a complete Kometa log file.")
