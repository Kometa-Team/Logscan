"""Configuration, YAML, and deprecated-schema recommendation rules."""

import hashlib
import re

from .base import EVIDENCE_LIMIT, TextRule, matching_line_spans, text_pattern
from ..models import Finding, ScanContext
from ..recommendations import RULES as RULE_DEFINITIONS
from ..service_names import SERVICE_NAMES, configuration_documentation, service_key


def _rule(rule_id: str, *needles: str) -> TextRule:
    definition = next(rule for rule in RULE_DEFINITIONS.values() if rule.id == rule_id)
    return TextRule(definition, any_of=needles)


def _same_line_rule(rule_id: str, *needles: str) -> TextRule:
    definition = next(rule for rule in RULE_DEFINITIONS.values() if rule.id == rule_id)
    return TextRule(definition, all_on_same_line=needles)


def _word_bounded_rule(rule_id: str, *needles: str) -> TextRule:
    definition = next(rule for rule in RULE_DEFINITIONS.values() if rule.id == rule_id)
    return TextRule(definition, word_bounded_any_of=needles)


def _record_evidence(groups: dict, key, number: int) -> None:
    """Cap distinct config issues and retain overflow in the generic finding."""
    if key not in groups and len(groups) >= 100:
        key = None
    evidence, count = groups.setdefault(key, ([], 0))
    if len(evidence) < EVIDENCE_LIMIT:
        evidence.append(number)
    groups[key] = (evidence, count + 1)


class ConfigurationDefaultRule:
    """Separate each omitted setting and logged default with bounded evidence."""

    id = "config_subattribute_default"

    def evaluate(self, context: ScanContext) -> list[Finding]:
        return self._evaluate(context.content)

    def evaluate_bytes(self, content) -> list[Finding]:
        return self._evaluate(content)

    def _evaluate(self, content) -> list[Finding]:
        anchor = r"Config Warning:"
        pattern = re.compile(anchor if isinstance(content, str) else anchor.encode(), re.I)
        required = [text_pattern((term,), content) for term in ("sub-attribute", "not found using")]
        grammar = re.compile(
            r"Config Warning:[ \t]+(?P<section>[a-z][a-z0-9_-]{0,63})[ \t]+sub-attribute[ \t]+"
            r"(?P<field>[a-z][a-z0-9_-]{0,79})[ \t]+not found using[ \t]+(?P<value>[^\r\n|]{1,256}?)[ \t]+as default\b",
            re.I,
        )
        groups = {}
        for number, start, end in matching_line_spans(pattern, content):
            if any(check.search(content, start, end) is None for check in required):
                continue
            position = pattern.search(content, start, end).start()
            line = content[position : min(end, position + 1024)]
            if not isinstance(line, str):
                line = line.decode("utf-8", errors="replace")
            parsed = grammar.search(line)
            key = None
            if parsed:
                section, field = parsed["section"].casefold(), parsed["field"].casefold()
                value = parsed["value"].strip().replace("`", "'")
                if re.search(r"api_?key|token|password|secret|authorization|cookie|url", field, re.I) and value.casefold() not in {"none", "null", "true", "false", "''", '""'}:
                    value = "[redacted]"
                key = (section, field, value)
            _record_evidence(groups, key, number)
        findings = []
        for key, (evidence, count) in groups.items():
            service = None
            if key:
                section, field, value = key
                label = "Kometa settings" if section == "settings" else SERVICE_NAMES.get(section, section)
                service = "kometa" if section == "settings" else section if section in SERVICE_NAMES else None
                path = f"{section}.{field}"
                title = f"{label}: {field} defaults to {value}"
                description = f"`{path}` was not configured. Kometa used the logged default `{value}`."
                guidance = f"To override it, set `{field}` under the affected `{section}` section in config.yml."
                if section == "tracearr" and field == "server_id" and value.casefold() in {"none", "null"}:
                    description += " Kometa attempts to identify the Plex server automatically."
                    guidance = "Leave `tracearr.server_id` unset if automatic server matching works. If Tracearr reports no unique match, set it to the appropriate server UUID listed in that error."
                elif section == "settings" and field == "playlist_sync_to_users" and value.casefold() in {"none", "null"}:
                    description += " Playlists are not synced to other users by default; individual playlists can override this."
                    guidance = "Keep this default for owner-only playlists. To share playlists, set `settings.playlist_sync_to_users` to `all` or a list of users."
                elif section == "settings" and field == "overlay_artwork_quality":
                    description += " This setting controls the quality of generated overlay artwork."
                solution = f"No change is required if this default is intended. {guidance} See {configuration_documentation(section)}"
                digest = hashlib.sha256(value.encode()).hexdigest()[:12]
                identifier = f"{self.id}_{section}_{field}_{digest}"
            else:
                definition = next(rule for rule in RULE_DEFINITIONS.values() if rule.id == self.id)
                identifier, title, description, solution = definition.id, definition.title, definition.description, definition.solution
            findings.append(
                Finding(identifier, "warning", title, description, solution, tuple(evidence), occurrence_count=count, evidence_truncated=count > len(evidence), service=service)
            )
        return findings


class ServiceConfigurationRule:
    """Explain which builder needs which missing service connection."""

    id = "service_config"

    def evaluate(self, context: ScanContext) -> list[Finding]:
        return self._evaluate(context.content)

    def evaluate_bytes(self, content) -> list[Finding]:
        return self._evaluate(content)

    def _evaluate(self, content) -> list[Finding]:
        anchor = r"requires[ \t]+"
        pattern = re.compile(anchor if isinstance(content, str) else anchor.encode(), re.I)
        required = [text_pattern((term,), content) for term in ("Error:", "to be configured")]
        grammar = re.compile(r"Error:[ \t]+['\"]?(?P<feature>[a-z][a-z0-9_.-]{0,99})['\"]?[ \t]*requires[ \t]+(?P<service>[a-z][a-z0-9_-]{0,63})[ \t]+to be configured\b", re.I)
        groups = {}
        for number, start, end in matching_line_spans(pattern, content):
            if any(check.search(content, start, end) is None for check in required):
                continue
            position = pattern.search(content, start, end).start()
            line = content[max(start, position - 512) : min(end, position + 512)]
            if not isinstance(line, str):
                line = line.decode("utf-8", errors="replace")
            parsed = grammar.search(line)
            key = None
            if parsed and (service := service_key(parsed["service"])):
                key = (service, parsed["feature"].casefold())
            _record_evidence(groups, key, number)
        findings = []
        for key, (evidence, count) in groups.items():
            service = None
            if key:
                service, feature = key
                name = SERVICE_NAMES[service]
                identifier = f"{self.id}_{service}_{feature}"
                title = f"{name} is required by {feature}"
                description = f"`{feature}` cannot run because the {name} connection was not successfully configured."
                solution = (
                    f"Complete the `{service}` connection in config.yml, confirm Kometa connects successfully, then rerun `{feature}`. See {configuration_documentation(service)}"
                )
            else:
                definition = next(rule for rule in RULE_DEFINITIONS.values() if rule.id == self.id)
                identifier, title, description, solution = definition.id, definition.title, definition.description, definition.solution
            findings.append(
                Finding(identifier, "error", title, description, solution, tuple(evidence), occurrence_count=count, evidence_truncated=count > len(evidence), service=service)
            )
        return findings


RULES = (
    _word_bounded_rule("cache_disabled", "cache: false"),
    _rule("legacy_other_award", "other_award"),
    _rule("legacy_delete_unmanaged", "delete_unmanaged_collections"),
    _rule("legacy_git", "- git: PMM"),
    _rule("legacy_pmm", "- pmm:"),
    _rule("mdblist_attribute", "mdblist_list attribute not allowed"),
    _rule("metadata_attribute", "metadata attribute is required"),
    ConfigurationDefaultRule(),
    _rule(
        "legacy_mass_metadata_update",
        "mass_genre_update:",
        "mass_content_rating_update:",
        "mass_original_title_update:",
        "mass_studio_update:",
        "mass_originally_available_update:",
        "mass_added_at_update:",
        "mass_audience_rating_update:",
        "mass_critic_rating_update:",
        "mass_user_rating_update:",
        "mass_episode_audience_rating_update:",
        "mass_episode_critic_rating_update:",
        "mass_episode_user_rating_update:",
        "mass_poster_update:",
        "mass_background_update:",
        "mass_logo_update:",
        "mass_square_art_update:",
    ),
    _rule("legacy_missing", "missing_path", "save_missing"),
    _rule("legacy_overlay_level", "overlay_level:"),
    _rule("yaml", "ruamel.yaml."),
    _same_line_rule("flixpatrol_subscription", "flixpatrol", "- pmm:"),
    ServiceConfigurationRule(),
)
