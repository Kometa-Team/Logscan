"""Reusable primitives for line-oriented recommendation rules."""

from __future__ import annotations

from dataclasses import dataclass
import re

from ..models import Finding, ScanContext
from ..recommendations import RecommendationRule as RuleDefinition


@dataclass(frozen=True)
class TextRule:
    """Emit one finding when required text appears in the log."""

    definition: RuleDefinition
    any_of: tuple[str, ...] = ()
    word_bounded_any_of: tuple[str, ...] = ()
    all_of: tuple[str, ...] = ()
    all_on_same_line: tuple[str, ...] = ()

    @property
    def id(self) -> str:
        return self.definition.id

    def evaluate(self, context: ScanContext) -> list[Finding]:
        lines = tuple(line.lower() for line in context.lines)
        any_of = tuple(value.lower() for value in self.any_of)
        word_bounded_any_of = tuple(value.lower() for value in self.word_bounded_any_of)
        all_of = tuple(value.lower() for value in self.all_of)
        all_on_same_line = tuple(value.lower() for value in self.all_on_same_line)
        if any_of and not any(any(value in line for value in any_of) for line in lines):
            return []
        if word_bounded_any_of and not any(
            any(re.search(rf"(?<![\w]){re.escape(value)}(?![\w])", line) for value in word_bounded_any_of)
            for line in lines
        ):
            return []
        if all_of and not all(any(value in line for line in lines) for value in all_of):
            return []
        if all_on_same_line and not any(all(value in line for value in all_on_same_line) for line in lines):
            return []
        evidence = tuple(
            number
            for number, line in enumerate(lines, start=1)
            if (
                any(value in line for value in any_of + all_of + all_on_same_line)
                or any(re.search(rf"(?<![\w]){re.escape(value)}(?![\w])", line) for value in word_bounded_any_of)
            )
        )
        return [Finding(
            self.id,
            self.definition.category,
            self.definition.title,
            self.definition.description,
            self.definition.solution,
            evidence,
        )]
