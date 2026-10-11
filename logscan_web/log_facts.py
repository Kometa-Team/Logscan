"""Log measurements independent of recommendation grouping and severity."""

import re


_LEVELS = ("critical", "error", "warning", "info", "debug", "trace")
_LEVEL_PATTERN = re.compile(rb"\[(CRITICAL|ERROR|WARNING|INFO|DEBUG|TRACE)\]", re.I)
_LINE_BREAK_PATTERN = re.compile(rb"\r\n|\r|\n")
_VALIDATION_PATTERN = re.compile(
    r"(?P<report>\bValidation\s+Report)(?:\s*\((?P<level>[^)\r\n]*)\))?"
    r"|\[validator\.py:\d+\][^\r\n]*?\bResult:\s*(?P<result>[^|\r\n]+)",
    re.I,
)
_VALIDATION_BYTES_PATTERN = re.compile(_VALIDATION_PATTERN.pattern.encode("ascii"), re.I)


def count_log_occurrences(content) -> dict[str, int]:
    """Count tagged lines per level in bytes or mmap, without copying the log.

    A repeated tag on the same line counts once. Findings are deliberately
    excluded: multiple recommendation rules may refer to the same log entry.
    """
    counts = dict.fromkeys(_LEVELS, 0)
    previous_lines = dict.fromkeys(_LEVELS, -1)
    line_number = 1
    cursor = 0
    for match in _LEVEL_PATTERN.finditer(content):
        line_number += sum(1 for _ in _LINE_BREAK_PATTERN.finditer(content, cursor, match.start()))
        cursor = match.end()
        level = match.group(1).decode("ascii").lower()
        if previous_lines[level] != line_number:
            counts[level] += 1
            previous_lines[level] = line_number
    return counts


def extract_validation_summary(content) -> dict:
    """Recognize terminal validator results, including failed/skipped runs.

    A generic 'Result:' message is insufficient: the terminal line must come
    from validator.py, matching Quickstart's completion contract.
    """
    level = None
    result = None
    validation_run = False
    pattern = _VALIDATION_PATTERN if isinstance(content, str) else _VALIDATION_BYTES_PATTERN

    def value(match, group):
        text = match.group(group)
        if isinstance(text, bytes):
            text = text.decode("utf-8", errors="replace")
        return text.strip().lower() if text else None

    for match in pattern.finditer(content):
        if match.group("report"):
            validation_run = True
            level = value(match, "level")
            result = None
        else:
            validation_run = True
            result = value(match, "result")
    if not validation_run:
        return {}
    return {
        "validation_run": True,
        "validation_level": level,
        "validation_result": result,
    }
