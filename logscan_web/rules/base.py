"""Reusable primitives for line-oriented recommendation rules."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
import re

from ..models import Finding, ScanContext
from ..recommendations import RecommendationRule as RuleDefinition

EVIDENCE_LIMIT = 10_000
_LINE_BREAKS = re.compile(r"\r\n|\r|\n")
_BYTE_LINE_BREAKS = re.compile(rb"\r\n|\r|\n")


def text_pattern(values: tuple[str, ...], content):
    expression = "|".join(re.escape(value) for value in sorted(values, key=len, reverse=True))
    return re.compile(expression if isinstance(content, str) else expression.encode("utf-8"), re.I)


def matching_line_spans(pattern, content) -> Iterator[tuple[int, int, int]]:
    """Yield each candidate line once without copying lines or storing offsets."""
    breaks = _LINE_BREAKS if isinstance(content, str) else _BYTE_LINE_BREAKS
    number, cursor, start, end = 1, 0, 0, -1
    for match in pattern.finditer(content):
        position = match.start()
        if position < end:
            continue
        for line_break in breaks.finditer(content, cursor, position):
            number += 1
            start = line_break.end()
        cursor = position
        next_break = breaks.search(content, position)
        end = next_break.start() if next_break else len(content)
        yield number, start, end


def _is_word_character(content, position: int) -> bool:
    if position < 0 or position >= len(content):
        return False
    if isinstance(content, str):
        value = content[position]
    else:
        # UTF-8 boundary checks need at most four bytes, even on a huge line.
        start = position
        while start > max(0, position - 3) and content[start] & 0xC0 == 0x80:
            start -= 1
        value = content[start : start + 4].decode("utf-8", errors="replace")[0]
    return value.isalnum() or value == "_"


def _has_word_match(pattern, content, start: int, end: int) -> bool:
    return any(not _is_word_character(content, match.start() - 1) and not _is_word_character(content, match.end()) for match in pattern.finditer(content, start, end))


def findings_from_lines(definition: RuleDefinition, numbers: Iterable[int]) -> list[Finding]:
    """Count ordered distinct matching lines while retaining only first evidence."""
    evidence = []
    count = 0
    previous = None
    for number in numbers:
        if number == previous:
            continue
        previous = number
        count += 1
        if len(evidence) < EVIDENCE_LIMIT:
            evidence.append(number)
    if not count:
        return []
    return [
        Finding(
            definition.id,
            definition.category,
            definition.title,
            definition.description,
            definition.solution,
            tuple(evidence),
            occurrence_count=count,
            evidence_truncated=count > len(evidence),
        )
    ]


@dataclass(frozen=True)
class TextRule:
    """Emit one finding with exact counts of lines satisfying its predicate.

    all_of retains its log-wide prerequisite semantics; the other populated
    groups must all match a candidate line before that line is counted.
    """

    definition: RuleDefinition
    any_of: tuple[str, ...] = ()
    word_bounded_any_of: tuple[str, ...] = ()
    all_of: tuple[str, ...] = ()
    all_on_same_line: tuple[str, ...] = ()

    @property
    def id(self) -> str:
        return self.definition.id

    def evaluate(self, context: ScanContext) -> list[Finding]:
        return evaluate_text_rules([self], context)


def _evaluate_text_rules(rules: list[TextRule], content) -> list[Finding]:
    findings = []
    for rule in rules:
        required = [text_pattern((value,), content) for value in rule.all_of]
        if any(pattern.search(content) is None for pattern in required):
            continue
        any_pattern = text_pattern(rule.any_of, content) if rule.any_of else None
        word_pattern = text_pattern(rule.word_bounded_any_of, content) if rule.word_bounded_any_of else None
        word_patterns = [text_pattern((value,), content) for value in rule.word_bounded_any_of]
        same_patterns = [text_pattern((value,), content) for value in rule.all_on_same_line]
        if rule.any_of:
            candidate = any_pattern
        elif rule.word_bounded_any_of:
            candidate = word_pattern
        elif rule.all_on_same_line:
            candidate = text_pattern((max(rule.all_on_same_line, key=len),), content)
        elif rule.all_of:
            candidate = text_pattern(rule.all_of, content)
        else:
            continue

        def matching_numbers():
            for number, start, end in matching_line_spans(candidate, content):
                if any_pattern and any_pattern.search(content, start, end) is None:
                    continue
                if word_patterns and not any(_has_word_match(pattern, content, start, end) for pattern in word_patterns):
                    continue
                if any(pattern.search(content, start, end) is None for pattern in same_patterns):
                    continue
                yield number

        findings.extend(findings_from_lines(rule.definition, matching_numbers()))
    return findings


def evaluate_text_rules(rules: list[TextRule], context: ScanContext) -> list[Finding]:
    return _evaluate_text_rules(rules, context.content)


def evaluate_text_rules_bytes(rules: list[TextRule], content) -> list[Finding]:
    """Search bytes/mmap directly with the same predicates and evidence cap."""
    return _evaluate_text_rules(rules, content)
