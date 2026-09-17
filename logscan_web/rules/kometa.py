"""Kometa, Plex, image, overlay, and generic log-level rules."""

import re
from dataclasses import dataclass
from typing import ClassVar

from .base import TextRule
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
    """Detect PMS versions in the live cog's vulnerable version range."""

    definition: object
    detector: ClassVar[str] = "PMS_VULNERABLE"
    vulnerable_low: ClassVar[tuple[int, int, int, int]] = (1, 41, 7, 0)
    vulnerable_high: ClassVar[tuple[int, int, int, int]] = (1, 42, 0, 99999)
    version_pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"Connected to server\s+.+?\s+(?:\(?\s*(?:version|Version:)\s+)(\d+\.\d+\.\d+\.\d+(?:-[A-Za-z0-9]+)?)",
        re.IGNORECASE,
    )

    @property
    def id(self) -> str:
        return self.definition.id

    @staticmethod
    def _version_tuple(version: str) -> tuple[int, int, int, int]:
        """Normalize a four-part PMS version, dropping any build suffix."""
        major, minor, patch, build = version.split("-", 1)[0].split(".")
        return int(major), int(minor), int(patch), int(build)

    def evaluate(self, context: ScanContext) -> list[Finding]:
        evidence = tuple(
            number
            for number, line in enumerate(context.lines, start=1)
            if (match := self.version_pattern.search(line))
            and self.vulnerable_low <= self._version_tuple(match.group(1)) <= self.vulnerable_high
        )
        if not evidence:
            return []
        return [Finding(
            self.id,
            self.definition.category,
            self.definition.title,
            self.definition.description,
            self.definition.solution,
            evidence,
        )]


@dataclass(frozen=True)
class RunOrderRule:
    definition: object
    detector: ClassVar[str] = "RUN_ORDER"

    @property
    def id(self) -> str:
        return self.definition.id

    def evaluate(self, context: ScanContext) -> list[Finding]:
        evidence = tuple(number for number, line in enumerate(context.lines, 1)
                         if "run_order:" in line.lower()
                         and number < len(context.lines)
                         and "- operations" not in context.lines[number].lower())
        return [Finding(self.id, self.definition.category, self.definition.title,
                        self.definition.description, self.definition.solution, evidence)] if evidence else []


@dataclass(frozen=True)
class RatingRoundingRule:
    definition: object
    detector: ClassVar[str] = "RATING_ROUNDING"

    @property
    def id(self) -> str:
        return self.definition.id

    def evaluate(self, context: ScanContext) -> list[Finding]:
        if not any(
            (match := PlexSecurityRule.version_pattern.search(line))
            and PlexSecurityRule.vulnerable_low <= PlexSecurityRule._version_tuple(match.group(1))
            <= PlexSecurityRule.vulnerable_high
            for line in context.lines
        ):
            return []
        evidence = tuple(number for number, line in enumerate(context.lines, 1)
                         if "mass_user_rating_update" in line.lower()
                         or "mass_episode_user_ratings_update" in line.lower())
        return [Finding(self.id, self.definition.category, self.definition.title,
                        self.definition.description, self.definition.solution, evidence)] if evidence else []


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
