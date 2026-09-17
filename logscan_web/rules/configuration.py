"""Configuration, YAML, and deprecated-schema recommendation rules."""

from .base import TextRule
from ..recommendations import RULES


def _rule(rule_id: str, *needles: str) -> TextRule:
    definition = next(rule for rule in RULES.values() if rule.id == rule_id)
    return TextRule(definition, any_of=needles)


def _same_line_rule(rule_id: str, *needles: str) -> TextRule:
    definition = next(rule for rule in RULES.values() if rule.id == rule_id)
    return TextRule(definition, all_on_same_line=needles)


def _word_bounded_rule(rule_id: str, *needles: str) -> TextRule:
    definition = next(rule for rule in RULES.values() if rule.id == rule_id)
    return TextRule(definition, word_bounded_any_of=needles)


RULES = (
    _word_bounded_rule("cache_disabled", "cache: false"),
    _rule("legacy_other_award", "other_award"),
    _rule("legacy_delete_unmanaged", "delete_unmanaged_collections"),
    _rule("legacy_git", "- git: PMM"),
    _rule("legacy_pmm", "- pmm:"),
    _rule("mdblist_attribute", "mdblist_list attribute not allowed"),
    _rule("metadata_attribute", "metadata attribute is required"),
    _rule("legacy_missing", "missing_path", "save_missing"),
    _rule("legacy_overlay_level", "overlay_level:"),
    _rule("yaml", "ruamel.yaml."),
    _same_line_rule("flixpatrol_subscription", "flixpatrol", "- pmm:"),
    _same_line_rule("service_config", "Error: ", " requires ", " to be configured"),
)
