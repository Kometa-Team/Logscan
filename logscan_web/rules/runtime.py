"""Runtime and host-environment recommendation rules."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .base import TextRule
from ..models import Finding, ScanContext
from ..recommendations import RULES


def _rule(rule_id: str, *needles: str) -> TextRule:
    definition = next(rule for rule in RULES.values() if rule.id == rule_id)
    return TextRule(definition, any_of=needles)


RULES = (
    _rule("plexapi_update", "requires an update to:"),
    _rule("kometa_update", "Newest Version:"),
    TextRule(next(rule for rule in RULES.values() if rule.id == "linuxserver"), all_on_same_line=("(Linuxserver", "Version:")),
    _rule("checkfiles", "checkFiles=1"),
)


def _definition(rule_id: str):
    return next(rule for rule in RULES_BY_TITLE.values() if rule.id == rule_id)


def _clock_minutes(value: str) -> int:
    hours, minutes = (int(part) for part in value.split(":"))
    return (hours * 60) + minutes


def _duration_minutes(value: str | None) -> float | None:
    if not value:
        return None
    match = re.fullmatch(r"(?:(\d+)\s+days?,?\s+)?(\d+):(\d{1,2}):(\d{1,2})", value.strip())
    if not match:
        return None
    days, hours, minutes, seconds = (int(part or 0) for part in match.groups())
    return (days * 1440) + (hours * 60) + minutes + (seconds / 60)


# Preserve the catalogue lookup after this module's RULES constant is assigned.
RULES_BY_TITLE = __import__("logscan_web.recommendations", fromlist=["RULES"]).RULES


def _memory_gb(context: ScanContext, label: str) -> float | None:
    match = re.search(rf"(?<!Available ){re.escape(label)}:\s*([\d.]+)\s*(GB|MB|TB)", context.content, re.I)
    if not match:
        return None
    value = float(match.group(1))
    return value / 1024 if match.group(2).upper() == "MB" else value * 1024 if match.group(2).upper() == "TB" else value


@dataclass(frozen=True)
class RuntimeAnalysisRule:
    """Handles checks that require values parsed from more than one log line."""

    id: str = "runtime-analysis"
    detectors: tuple[str, ...] = ("SCHEDULE_ANALYSIS", "LOG_INCOMPLETE")

    def evaluate(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        def add(rule_id: str, evidence: tuple[int, ...] = ()) -> None:
            rule = _definition(rule_id)
            findings.append(Finding(
                rule.id,
                rule.category,
                rule.title,
                rule.description,
                rule.solution,
                evidence,
            ))

        memory = _memory_gb(context, "Memory")
        cache = _memory_gb(context, "Plex DB cache setting")
        overlay = bool(re.search(r"\boverlay_(?:path|files):", context.content, re.I))
        if memory is None:
            add("memory_unavailable")
        elif memory < 4:
            add("memory_overlay_insufficient" if overlay else "memory_low")
        elif memory < 8 and overlay:
            add("memory_overlay_low")
        if cache is not None and memory is not None:
            add("db_cache_exceeds_memory" if cache >= memory else "db_cache_undersized" if cache < 1 else "memory_low") if cache >= memory or cache < 1 else None

        if re.search(r"Platform:.*-WSL", context.content, re.I):
            add("wsl_memory")
        if not re.search(r"--times? \((?:KOMETA|PMM)_TIMES?\)", context.content, re.I):
            add("schedule_unavailable")
        else:
            schedule = re.search(r"--times? \((?:KOMETA|PMM)_TIMES?\): ?[\"']?(\d{1,2}:\d{2})", context.content, re.I)
            maintenance = re.search(r"Scheduled maintenance running between (\d{1,2}:\d{2}) and (\d{1,2}:\d{2})", context.content, re.I)
            run_minutes = _duration_minutes(context.run_time)
            if schedule and maintenance and run_minutes is not None:
                scheduled = _clock_minutes(schedule.group(1))
                maintenance_start = _clock_minutes(maintenance.group(1))
                maintenance_end = _clock_minutes(maintenance.group(2))
                before_maintenance = (maintenance_start - scheduled) % 1440
                maintenance_buffer = (maintenance_start - maintenance_end) % 1440
                in_maintenance = (
                    maintenance_start <= scheduled < maintenance_end
                    if maintenance_start <= maintenance_end
                    else scheduled >= maintenance_start or scheduled < maintenance_end
                )
                if run_minutes > 1440:
                    add("schedule_over_24_hours")
                elif run_minutes > maintenance_buffer:
                    add("schedule_maintenance_buffer")
                elif in_maintenance:
                    add("schedule_conflict")
                elif run_minutes > before_maintenance:
                    add("schedule_overlap")
        if not context.complete:
            add("incomplete_log")
        return findings


# Compatibility names retained for callers that used the earlier split-rule API.
MemoryAnalysisRule = RuntimeAnalysisRule
ScheduleAnalysisRule = RuntimeAnalysisRule
