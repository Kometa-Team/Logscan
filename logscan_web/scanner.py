import gzip
import re
import tarfile
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path, PurePosixPath

from .models import ScanContext
from .rules import RuleRegistry, migrated_rules
from .categories import category_configuration


MAX_FILE_BYTES = 500 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 3
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
        name = re.sub(r"\.[A-Za-z0-9]+$", "", match.group("name")).replace("%20", " ").strip()
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
            raise ScanError("The extracted archive contents are larger than the 500 MB limit.")
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
                raise ScanError("The extracted ZIP contents are larger than the 500 MB limit.")
            extracted_files = []
            extracted_size = 0
            for entry in entries:
                with archive.open(entry) as member:
                    extracted_file = member.read(MAX_FILE_BYTES - extracted_size + 1)
                extracted_size += len(extracted_file)
                if extracted_size > MAX_FILE_BYTES:
                    raise ScanError("The extracted ZIP contents are larger than the 500 MB limit.")
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
                raise ScanError("The extracted TAR contents are larger than the 500 MB limit.")
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
                    raise ScanError("The extracted TAR contents are larger than the 500 MB limit.")
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
        raise ScanError("The extracted GZIP contents are larger than the 500 MB limit.")
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
    }


def scan_log(filename: str, content_bytes: bytes) -> ScanResult:
    filename, content_bytes = prepare_scan_input(filename, content_bytes)
    if not content_bytes:
        raise ScanError("The selected file is empty.")
    if len(content_bytes) > MAX_FILE_BYTES:
        raise ScanError("The selected file is larger than the 500 MB limit.")

    content = content_bytes.decode("utf-8", errors="replace")
    lowered = content.lower()
    if "[kometa.py:" not in lowered and "[plex_meta_manager.py:" not in lowered:
        raise ScanError("This does not appear to be a complete Kometa log file.")

    version_match = re.search(r"\bVersion:\s*([^|\r\n]+)", content)
    kometa_version = version_match.group(1).strip() if version_match else None
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
    normalized.sort(key=lambda item: {"critical": 0, "error": 1, "warning": 2, "schema": 3, "advice": 4}[item["severity"]])

    metadata = {
        "kometa_version": kometa_version,
        "run_time": str(detected_run_time) if detected_run_time else None,
        "complete": detected_run_time is not None,
        "header_found": kometa_version is not None,
        "line_count": len(content.splitlines()),
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
    )


def scan_archive_logs(filename: str, content_bytes: bytes) -> list[tuple[str, bytes, ScanResult]]:
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
                        raise ScanError("The extracted ZIP contents are larger than the 500 MB limit.")
                    results = []
                    for entry in entries:
                        with archive.open(entry) as member:
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
    total_size = sum(len(content) for _name, content, _result in scans)
    if total_size > MAX_FILE_BYTES:
        raise ScanError("The extracted archive contents are larger than the 500 MB limit.")
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
