"""ImageMaid analysis without Quickstart's local database or runtime dependencies."""

from __future__ import annotations

import re


def runtime_seconds(value: str) -> int | None:
    match = re.fullmatch(r"(?:(\d+) days?,?\s*)?(\d+):(\d{2}):(\d{2})(?:\.\d+)?", value.strip(), re.IGNORECASE)
    if not match:
        return None
    days, hours, minutes, seconds = match.groups()
    return int(days or 0) * 86400 + int(hours) * 3600 + int(minutes) * 60 + int(seconds)


def recovered_bytes(value: str) -> int | None:
    match = re.fullmatch(r"([\d.]+)\s*(bytes?|[kmgt]?i?bs?)", value.strip(), re.IGNORECASE)
    if not match:
        return None
    unit = match[2].lower().replace("i", "").rstrip("s")
    power = {"b": 0, "byte": 0, "bytes": 0, "kb": 1, "mb": 2, "gb": 3, "tb": 4}[unit]
    try:
        return int(float(match[1]) * 1024**power)
    except (ValueError, OverflowError):
        return None


def analyze_imagemaid(content) -> dict:
    # Iterate bytes one line at a time, including mmap-backed large uploads.
    values = {"version": None, "mode": None, "run_command": None, "run_time": None, "started": None, "finished": None}
    counts = {
        "restore_found_files": 0,
        "restore_removed_files": 0,
        "restore_recovered_bytes": 0,
        "photo_found_files": 0,
        "photo_removed_files": 0,
        "photo_recovered_bytes": 0,
        "bloat_found_files": 0,
        "bloat_removed_files": 0,
        "bloat_recovered_bytes": 0,
    }
    timings = {}
    timing_lines = {}
    operations = set()
    evidence = {"critical": [], "error": [], "warning": []}
    occurrences = {key: 0 for key in evidence}
    markers = []
    section = ""
    stopped = False
    blocked = False
    database_failed = False
    finished_seen = False
    cleanup_reported = False
    line_count = 0
    for number, match in enumerate(re.finditer(rb"[^\r\n]*(?:\r\n|\r|\n|$)", content), 1):
        if not match[0]:
            break
        line_count += 1
        line = match[0].decode("utf-8", errors="replace")
        message = re.sub(r"^.*?\[(?:DEBUG|INFO|WARNING|ERROR|CRITICAL|TRACE)\]\s*", "", line).strip().strip("|").strip()
        if "[Quickstart]" in line:
            if len(markers) < 500:
                markers.append(line)
            stopped |= bool(re.search(r"Run event:.*\bevent=stopped\b", line))
            blocked |= bool(re.search(r"Maintenance marker:.*\bevent=blocked_start\b", line))
            marker = re.search(r"Run marker:\s*started=(\S+).*?\btool=imagemaid\b(?:\s+mode=(\S+))?", line)
            if marker:
                values["started"] = marker[1]
                values["mode"] = marker[2] or values["mode"]
        timestamp = re.match(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
        if timestamp and not values["started"]:
            values["started"] = timestamp[1]
        for label, key in (("Version", "version"), ("Run Command", "run_command"), ("Platform", "platform"), ("Started", "started"), ("Finished", "finished")):
            found = re.search(rf"(?:^|\|)\s*{label}:\s*([^|]+)", message, re.IGNORECASE)
            if found and not values.get(key):
                values[key] = found[1].strip()
        mode = re.search(r"Running in\s+(\w+)\s+Mode", message, re.IGNORECASE)
        if mode:
            values["mode"] = mode[1].lower()
        total = re.search(r"Total Runtime\s*\|\s*([^|]+)", message, re.IGNORECASE)
        if total:
            values["run_time"] = total[1].strip()
        if "ImageMaid Finished" in message or "Finished ImageMaid" in message:
            finished_seen = True
            values["finished"] = (timestamp[1] if timestamp else None) or values["finished"]
        database_failed |= "Database File Could not Downloaded" in message
        for operation, phrase in (
            ("database", "Downloading Database"),
            ("photo_transcoder", "PhotoTranscoder set to True"),
            ("empty_trash", "Empty Trash Plex Operation Started"),
            ("clean_bundles", "Clean Bundles Plex Operation Started"),
            ("optimize_db", "Optimize DB Plex Operation Started"),
        ):
            if phrase in message:
                operations.add(operation)
        for phrase, key in (
            ("Downloading Database", "database_download"),
            ("Querying For In-Use Images", "database_query"),
            ("Scanning ImageMaid Restore", "restore_scan"),
            ("Removing ImageMaid Restore", "restore_action"),
            ("Scanning Metadata Directory", "report_scan"),
            ("Reporting Bloat Images", "report_action"),
            ("Removing Bloat Images", "bloat_remove"),
            ("Deleting Bloat Images", "bloat_remove"),
            ("Scanning for PhotoTranscoder", "photo_scan"),
            ("Removing PhotoTranscoder", "photo_remove"),
            ("Empty Trash Plex Operation Started", "empty_trash"),
            ("Clean Bundles Plex Operation Started", "clean_bundles"),
            ("Optimize DB Plex Operation Started", "optimize_db"),
        ):
            if phrase in message:
                section = key
        header = re.search(r"=+\s*(.*?)\s*=+", message)
        if header:
            section = {
                "database": "database",
                "reporting bloat images": "report",
                "remove phototranscoder images": "photo",
                "remove imagemaid restore bloat images": "restore",
                "empty trash plex operation": "empty_trash",
                "remove bloat images": "bloat",
                "delete bloat images": "bloat",
                "clean bundles plex operation": "clean_bundles",
                "optimize db plex operation": "optimize_db",
            }.get(header[1].lower(), section)
        row = re.search(r"(?:^|\|)\s*(Downloaded|Query|Scan Time|Report Time|Remove Time|Runtime)\s*(?:\||:)\s*([^|]+)", message, re.IGNORECASE)
        if row:
            duration = runtime_seconds(row[2])
            if duration is not None:
                suffix = {"downloaded": "download", "query": "query", "scan time": "scan", "report time": "action", "remove time": "action"}.get(row[1].lower())
                key = f"{section}_{suffix}" if suffix else section
                timings[key] = duration
                timing_lines[key] = number
        for pattern, key in (
            (r"Found\s+(\d+)\s+Bloat Images in the ImageMaid Directory", "restore_found_files"),
            (r"Removed\s+(\d+)\s+ImageMaid Restore Bloat Images", "restore_removed_files"),
            (r"Found\s+(\d+)\s+PhotoTranscoder Images", "photo_found_files"),
            (r"Removed\s+(\d+)\s+PhotoTranscoder Images", "photo_removed_files"),
        ):
            found = re.search(pattern, message, re.IGNORECASE)
            if found:
                counts[key] = int(found[1])
                cleanup_reported = True
        removed = re.search(r"(?:Removed|Deleted)\s+(\d+)\s+Bloat Images", message, re.IGNORECASE)
        if removed:
            counts["bloat_removed_files"] = int(removed[1])
            cleanup_reported = True
            section = "bloat_remove"
        recovered = re.search(r"Space Recovered:\s*([^|]+)", message, re.IGNORECASE)
        if recovered:
            amount = recovered_bytes(recovered[1])
            if amount is not None and section.startswith(("restore", "photo", "bloat")):
                counts[f"{section.split('_')[0]}_recovered_bytes"] = amount
                cleanup_reported = True
        level = re.search(r"\[(CRITICAL|ERROR|WARNING)\]", line, re.IGNORECASE)
        if level or re.search(r"\bError:", message):
            severity = level[1].lower() if level else "error"
            occurrences[severity] += 1
            if len(evidence[severity]) < 80:
                evidence[severity].append((number, message))
    complete = finished_seen and runtime_seconds(values["run_time"] or "") is not None
    recommendations = []

    def finding(key, severity, title, description, solution, lines=(), total=None):
        recommendations.append(
            {
                "id": key,
                "severity": severity,
                "title": title,
                "description": description,
                "solution": solution,
                "message": f"**{title}**\nIssue: {description}\n\nProposed solution: {solution}",
                "evidence_lines": list(lines),
                "occurrence_count": total,
                "evidence_truncated": total is not None and total > len(lines),
            }
        )

    if not complete:
        title = "ImageMaid run stopped by user" if stopped else "ImageMaid start blocked by Plex maintenance" if blocked else "ImageMaid run appears incomplete"
        finding(
            "imagemaid_incomplete",
            "advice" if stopped or blocked else "warning",
            title,
            "The log does not record a completed ImageMaid run with a total runtime.",
            "Review the end of the log before starting another run.",
        )
    if database_failed:
        finding(
            "imagemaid_database_failed",
            "error",
            "ImageMaid database download failed",
            "ImageMaid could not download the Plex database.",
            "Check the Plex connection and token, and that the server permits database downloads.",
        )
    for severity, entries in evidence.items():
        if entries:
            finding(
                f"imagemaid_{severity}",
                severity,
                f"ImageMaid reported {severity} entries",
                "\n".join(text for _, text in entries[:8]),
                "Review the referenced entries and resolve the reported connection, path, or permission issue before repeating a destructive mode.",
                [number for number, _ in entries],
                occurrences[severity],
            )
    recommendations.sort(key=lambda item: {"critical": 0, "error": 1, "warning": 2, "advice": 4}[item["severity"]])
    return {
        "values": values,
        "counts": counts,
        "timings": timings,
        "operations": sorted(operations),
        "complete": complete,
        "recommendations": recommendations,
        "quickstart_content": "\n".join(markers),
        "line_count": line_count,
        "timing_lines": timing_lines,
        "cleanup_reported": cleanup_reported,
    }
