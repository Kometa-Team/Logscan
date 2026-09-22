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

        def add(rule_id: str, evidence: tuple[int, ...] = (), details: str = "") -> None:
            rule = _definition(rule_id)
            findings.append(Finding(
                rule.id,
                rule.category,
                rule.title,
                rule.description,
                rule.solution,
                evidence,
                details,
            ))

        memory = _memory_gb(context, "Memory")
        cache = _memory_gb(context, "Plex DB cache setting")
        overlay = bool(re.search(r"\boverlay_(?:path|files):", context.content, re.I))
        if memory is None:
            add("memory_unavailable")
        elif memory < 4:
            target = 8 if overlay else 4
            add(
                "memory_overlay_insufficient" if overlay else "memory_low",
                details=(
                    "**Memory recommendation**\n"
                    f"Detected memory: **{memory:.2f} GB**. "
                    f"At least **{target} GB** is recommended when running Kometa "
                    f"{'with' if overlay else 'without'} overlays to reduce out-of-memory failures.\n\n"
                    "These values are estimates and vary with library size, file count, operations, and overlays."
                ),
            )
        elif memory < 8 and overlay:
            add(
                "memory_overlay_low",
                details=(
                    "**Memory recommendation**\n"
                    f"Detected memory: **{memory:.2f} GB**. At least **8 GB** is recommended for "
                    "better performance because overlays were detected.\n\n"
                    "This estimate varies with library size, file count, operations, and overlays."
                ),
            )
        if cache is not None and memory is not None:
            cache_url = "https://www.kometa.wiki/en/latest/config/plex#plex-attributes"
            disclaimer = "The best value varies with library size, file count, operations, and overlays."
            if cache >= memory:
                add(
                    "db_cache_exceeds_memory",
                    details=(
                        "**Plex DB cache issue**\n"
                        f"The Plex DB cache is **{cache:.2f} GB**, equal to or greater than the detected "
                        f"system memory of **{memory:.2f} GB**. Set it safely below total memory.\n"
                        f"See {cache_url}\n\n{disclaimer}"
                    ),
                )
            elif cache < 1:
                add(
                    "db_cache_undersized",
                    details=(
                        "**Plex DB cache advice**\n"
                        f"The Plex DB cache is **{cache:.2f} GB** and detected system memory is "
                        f"**{memory:.2f} GB**. Consider a value above 1 GB; `db_cache: 1024` is 1 GB.\n"
                        f"See {cache_url}\n\n{disclaimer}"
                    ),
                )

        if re.search(r"Platform:.*-WSL", context.content, re.I):
            add(
                "wsl_memory",
                details=(
                    "**WSL memory recommendation**\n"
                    "WSL 2 uses a virtual machine and, by default, can use up to 50% of Windows memory. "
                    "A lower limit may leave Kometa without enough RAM for larger workloads.\n\n"
                    "Configure the WSL 2 VM in `%UserProfile%\\.wslconfig`, for example:\n"
                    "`[wsl2]`\n`memory=8GB`\n\n"
                    "Run `wsl --shutdown` after changing the file, then restart the distribution. "
                    "See https://learn.microsoft.com/windows/wsl/wsl-config"
                ),
            )
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
                    schedule_id = "schedule_over_24_hours"
                elif run_minutes > maintenance_buffer:
                    schedule_id = "schedule_maintenance_buffer"
                elif in_maintenance:
                    schedule_id = "schedule_conflict"
                elif run_minutes > before_maintenance:
                    schedule_id = "schedule_overlap"
                else:
                    schedule_id = None
                if schedule_id:
                    rule = _definition(schedule_id)
                    add(
                        schedule_id,
                        details=(
                            f"**{rule.title}**\n"
                            f"Run time: **{context.run_time}**\n"
                            f"Kometa scheduled start: **{schedule.group(1)}**\n"
                            f"Plex maintenance window: **{maintenance.group(1)}-{maintenance.group(2)}**\n\n"
                            f"{rule.description}\n\nProposed solution: {rule.solution} "
                            "See https://support.plex.tv/articles/202197488-scheduled-server-maintenance/"
                        ),
                    )
        if not context.complete:
            add("incomplete_log")
        return findings


# Compatibility names retained for callers that used the earlier split-rule API.
MemoryAnalysisRule = RuntimeAnalysisRule
ScheduleAnalysisRule = RuntimeAnalysisRule
