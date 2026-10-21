"""Kometa, Plex, image, overlay, and generic log-level rules."""

import re
from dataclasses import dataclass
from typing import ClassVar

from .base import EVIDENCE_LIMIT, TextRule, findings_from_lines, matching_line_spans, text_pattern
from ..plex_security import LEGACY_HIGH, LEGACY_LOW, assess_log, assessment_message, parse_pms_version, server_observation
from ..models import Finding, ScanContext
from ..recommendations import RULES, RULES as RECOMMENDATION_RULES


def _rule(rule_id: str, *needles: str) -> TextRule:
    definition = next(rule for rule in RULES.values() if rule.id == rule_id)
    return TextRule(definition, any_of=needles)


def _same_line_rule(rule_id: str, *needles: str) -> TextRule:
    definition = next(rule for rule in RULES.values() if rule.id == rule_id)
    return TextRule(definition, all_on_same_line=needles)


@dataclass(frozen=True)
class PlexSecurityRule:
    """Assess logged PMS versions using the shared offline advisory core."""

    definition: object
    detector: ClassVar[str] = "PMS_VULNERABLE"
    vulnerable_low: ClassVar[tuple[int, int, int, int]] = LEGACY_LOW
    vulnerable_high: ClassVar[tuple[int, int, int, int]] = LEGACY_HIGH

    @property
    def id(self) -> str:
        return self.definition.id

    @staticmethod
    def _version_tuple(version: str) -> tuple[int, int, int, int]:
        """Normalize a four-part PMS version, dropping any build suffix."""
        parsed = parse_pms_version(version)
        if parsed is None:
            raise ValueError(f"Invalid Plex Media Server version: {version}")
        return parsed

    def evaluate(self, context: ScanContext) -> list[Finding]:
        return self.evaluate_bytes(context.content)

    def evaluate_bytes(self, content) -> list[Finding]:
        findings = []
        for assessment in assess_log(_connection_lines(content), EVIDENCE_LIMIT):
            if assessment["status"] == "patched":
                continue
            affected = assessment["status"] == "affected"
            message = assessment_message(assessment)
            findings.append(
                Finding(
                    self.id if affected else f"{self.id}_{assessment['status']}",
                    "critical" if affected else "advice",
                    message.split("\n", 1)[0],
                    "Plex version observed in the uploaded log; current server status is unknown.",
                    assessment["remediation"],
                    tuple(assessment["evidence_lines"]),
                    details=message,
                    occurrence_count=assessment["occurrence_count"],
                    evidence_truncated=assessment["evidence_truncated"],
                    security_assessment=assessment,
                )
            )
        return findings


def _connection_lines(content):
    for number, start, end in matching_line_spans(text_pattern(("Connected to server",), content), content):
        line = content[start:end]
        yield number, line if isinstance(line, str) else line.decode("utf-8", errors="replace")


def _server_versions(content):
    for number, line in _connection_lines(content):
        observation = server_observation(line)
        if observation and parse_pms_version(observation[1]) is not None:
            yield number, observation[1]


@dataclass(frozen=True)
class RunOrderRule:
    definition: object
    detector: ClassVar[str] = "RUN_ORDER"

    @property
    def id(self) -> str:
        return self.definition.id

    def evaluate(self, context: ScanContext) -> list[Finding]:
        return self.evaluate_bytes(context.content)

    def evaluate_bytes(self, content) -> list[Finding]:
        breaks = re.compile(r"\r\n|\r|\n" if isinstance(content, str) else rb"\r\n|\r|\n")
        operations = text_pattern(("- operations",), content)

        def matching_numbers():
            for number, _start, end in matching_line_spans(text_pattern(("run_order:",), content), content):
                line_break = breaks.match(content, end)
                if line_break is None or line_break.end() == len(content):
                    continue
                next_start = line_break.end()
                next_break = breaks.search(content, next_start)
                next_end = next_break.start() if next_break else len(content)
                if operations.search(content, next_start, next_end) is None:
                    yield number

        return findings_from_lines(self.definition, matching_numbers())


@dataclass(frozen=True)
class RatingRoundingRule:
    definition: object
    detector: ClassVar[str] = "RATING_ROUNDING"
    affected_low: ClassVar[tuple[int, int, int, int]] = (1, 40, 0, 7998)
    affected_high: ClassVar[tuple[int, int, int, int]] = (1, 40, 3, 8555)

    @property
    def id(self) -> str:
        return self.definition.id

    def evaluate(self, context: ScanContext) -> list[Finding]:
        return self.evaluate_bytes(context.content)

    def evaluate_bytes(self, content) -> list[Finding]:
        if not any(self.affected_low < PlexSecurityRule._version_tuple(version) < self.affected_high for _number, version in _server_versions(content)):
            return []
        pattern = text_pattern(("mass_user_rating_update", "mass_episode_user_ratings_update"), content)
        return findings_from_lines(self.definition, (number for number, _start, _end in matching_line_spans(pattern, content)))


CUSTOM_DETECTORS = {
    PlexSecurityRule.detector: PlexSecurityRule,
    RunOrderRule.detector: RunOrderRule,
    RatingRoundingRule.detector: RatingRoundingRule,
}


def _custom_rule(rule_id: str):
    definition = next(rule for rule in RECOMMENDATION_RULES.values() if rule.id == rule_id)
    if definition.detector not in CUSTOM_DETECTORS:
        raise ValueError(f"Unknown custom detector: {definition.detector}")
    return CUSTOM_DETECTORS[definition.detector](definition)


RULES = (
    _rule("api_key_missing", "apikey is blank"),
    TextRule(
        next(rule for rule in RULES.values() if rule.id == "plex_version"),
        all_on_same_line=("1.32.7", "Connected to server"),
    ),
    _rule("kometa_critical", "[CRITICAL]"),
    _rule("kometa_error", "[ERROR]"),
    _rule("kometa_warning", "[WARNING]"),
    _rule(
        "retired_nightly_branch",
        "(Branch: nightly)",
        "(Git: nightly)",
        "(Docker: nightly)",
    ),
    _same_line_rule("id_conversion", "Convert Warning: No ", "ID Found for"),
    _rule("image_unreadable", "PIL.UnidentifiedImageError: cannot"),
    _same_line_rule("flixpatrol_parse", "FlixPatrol Error:", "failed to parse"),
    _rule("image_size", "in _upload_image"),
    _rule("internal_server", "internal_server_error"),
    _same_line_rule("mass_update", "Config Error: Operation mass_", "without a successful"),
    _rule("metadata_load", "Metadata File Failed To Load"),
    _rule("overlay_load", "Overlay File Failed To Load"),
    _rule("playlist_load", "Playlist File Failed To Load"),
    _rule("plex_no_items", "Plex Error: No Items found in Plex"),
    _rule("overlay_font", "Overlay Error: font:"),
    _rule("overlay_reset", "Reapply Overlays: True", "Reset Overlays: ["),
    _rule("overlay_existing", "Poster already has an Overlay"),
    _rule("overlay_image", "Overlay Image not found"),
    _same_line_rule("playlist_library", "Playlist Error: Library:", "not defined"),
    _same_line_rule("plex_regex", "Plex Error: ", "No matches found with regex pattern"),
    _same_line_rule("plex_library", "Plex Error: Plex Library", "not found"),
    _custom_rule("rating_rounding"),
    _rule("plex_url", "Plex Error: Plex url is invalid"),
    _custom_rule("plex_security"),
    _custom_rule("run_order"),
    _rule("traceback", "Traceback (most recent call last):"),
)
