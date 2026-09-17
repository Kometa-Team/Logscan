"""Rule interfaces and registry for the modular recommendation engine."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol

from ..models import Finding, ScanContext


class RecommendationRule(Protocol):
    """A single independently testable recommendation detector."""

    id: str

    def evaluate(self, context: ScanContext) -> Iterable[Finding]:
        """Return zero or more findings for the supplied parsed log."""


@dataclass
class RuleRegistry:
    """Owns rule ordering and rejects duplicate stable rule IDs."""

    _rules: list[RecommendationRule] = field(default_factory=list)

    def register(self, rule: RecommendationRule) -> RecommendationRule:
        if any(existing.id == rule.id for existing in self._rules):
            raise ValueError(f"Duplicate recommendation rule ID: {rule.id}")
        self._rules.append(rule)
        return rule

    def evaluate(self, context: ScanContext) -> list[Finding]:
        return [finding for rule in self._rules for finding in rule.evaluate(context)]

    @property
    def rules(self) -> tuple[RecommendationRule, ...]:
        return tuple(self._rules)


def migrated_rules() -> tuple[RecommendationRule, ...]:
    """Return the rules moved out of the legacy engine during step 2."""
    from .configuration import RULES as configuration_rules
    from .kometa import RULES as kometa_rules
    from .runtime import RULES as runtime_rules, RuntimeAnalysisRule
    from .services import RULES as service_rules

    return (*configuration_rules, *service_rules, *kometa_rules, *runtime_rules, RuntimeAnalysisRule())
