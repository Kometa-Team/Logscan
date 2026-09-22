import gzip
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

from .models import ScanContext
from .rules import RuleRegistry, migrated_rules
from .rules.base import TextRule, evaluate_text_rules_bytes
from .categories import category_configuration


MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 3
STREAM_SCAN_THRESHOLD = 64 * 1024 * 1024
ALLOWED_SUFFIXES = {".txt", ".log", ".yml", ".yaml"}
ARCHIVE_SUFFIXES = {".zip", ".tar", ".tgz", ".gz"}


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
            is_nested_archive = Path(filename).suffix.lower() in ARCHIVE_SUFFIXES or filename.lower().endswith((".tar.gz", ".tgz"))
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


def prepare_scan_input(filename: str, content_bytes: bytes, archive_depth: int = 0) -> tuple[str, bytes]:
    """Validate an upload and return the text that should be stored and scanned."""
    suffix = Path(filename).suffix.lower()
    if suffix in ARCHIVE_SUFFIXES or filename.lower().endswith((".tar.gz", ".tgz")):
        if archive_depth >= MAX_ARCHIVE_DEPTH:
            raise ScanError("Archives may be nested no more than three levels deep.")
    if suffix == ".zip":
        return _extract_zip(filename, content_bytes, archive_depth + 1)
    if filename.lower().endswith((".tar.gz", ".tgz", ".tar")):
        return _extract_tar(filename, content_bytes, archive_depth + 1)
    if suffix == ".gz":
        return _extract_gzip(filename, content_bytes, archive_depth + 1)
    if suffix not in ALLOWED_SUFFIXES and not suffix.lstrip(".").isdigit():
        raise ScanError("Choose a Kometa log, text, YAML, ZIP, TAR, or GZIP file.")
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


def apply_documentation_branch(recommendations: list[dict], branch: str) -> None:
    """Point Kometa Wiki links at the scanned release channel's documentation."""
    documentation_branch = "develop" if branch == "develop" else "latest"
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


def extract_plex_configurations(content: str) -> list[dict[str, object]]:
    """Extract the informational Plex configuration blocks shown by Kometa."""
    sections: list[dict[str, object]] = []
    current: list[str] | None = None
    for raw_line in content.splitlines():
        message = _log_message(raw_line)
        if "Plex Configuration" in message:
            if current:
                sections.append({"title": f"Plex Configuration - Section {len(sections) + 1}", "lines": current})
            current = []
            continue
        if current is None:
            continue
        if re.search(r"\bScanning\b", message) or "Library Connection Failed" in message:
            if current:
                sections.append({"title": f"Plex Configuration - Section {len(sections) + 1}", "lines": current})
            current = None
            continue
        if message and not re.fullmatch(r"[-=]+", message):
            current.append(message)
    if current:
        sections.append({"title": f"Plex Configuration - Section {len(sections) + 1}", "lines": current})
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


def _log_overview(
    filename: str,
    content: str,
    kometa_version: str | None,
    run_time: str | None,
    recommendations: list[dict],
) -> dict:
    yaml_findings = [item for item in recommendations if item["severity"] == "schema"]
    yaml_status = "Schema issues detected" if yaml_findings else "No YAML or schema issues detected"
    completed_run = re.search(
        r"Start Time:\s*(?P<start>.*?)\s+Finished:\s*(?P<end>.*?)\s+Run Time:\s*(?P<runtime>[^|\r\n]+)",
        content,
    )
    plex_configurations = extract_plex_configurations(content)
    return {
        "log_name": filename,
        "recommendation_count": len(recommendations),
        "kometa_version": kometa_version,
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
        b"[quickstart]", b"finished:", b"run time:", b"start time:", b"started:",
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
    quickstart_marker = re.search(r"\[Quickstart\]\s+Run marker:[^\r\n]*", sample_content, re.I)
    quickstart_fields = {
        key.casefold(): value
        for key, value in re.findall(r"\b(quickstart|branch)=([^\s|]+)", quickstart_marker.group(0), re.I)
    } if quickstart_marker else {}
    quickstart_branch = quickstart_fields.get("branch", "unknown").casefold()
    if quickstart_branch not in {"master", "develop"}:
        quickstart_branch = "unknown"
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
        "kometa_branch": kometa_branch,
        "quickstart_run": bool(quickstart_marker),
        "quickstart_version": quickstart_fields.get("quickstart"),
        "quickstart_branch": quickstart_branch,
        "runtime_platform": normalized_platform(runtime_platform),
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
    quickstart_marker = re.search(r"\[Quickstart\]\s+Run marker:[^\r\n]*", content, re.IGNORECASE)
    quickstart_fields = {
        key.casefold(): value
        for key, value in re.findall(r"\b(quickstart|branch)=([^\s|]+)", quickstart_marker.group(0), re.IGNORECASE)
    } if quickstart_marker else {}
    quickstart_branch = quickstart_fields.get("branch", "unknown").casefold()
    if quickstart_branch not in {"master", "develop"}:
        quickstart_branch = "unknown"
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
        "kometa_branch": kometa_branch,
        "quickstart_run": bool(quickstart_marker),
        "quickstart_version": quickstart_fields.get("quickstart"),
        "quickstart_branch": quickstart_branch,
        "runtime_platform": normalized_platform(runtime_platform),
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
