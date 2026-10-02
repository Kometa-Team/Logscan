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


def evaluate_text_rules(rules: list[TextRule], context: ScanContext) -> list[Finding]:
    """Evaluate ordinary text rules together without duplicating the log."""
    states = []
    term_uses: dict[str, list[tuple[int, str]]] = {}
    for index, rule in enumerate(rules):
        values = {
            "any": tuple(value.lower() for value in rule.any_of),
            "word": tuple(value.lower() for value in rule.word_bounded_any_of),
            "all": tuple(value.lower() for value in rule.all_of),
            "same": tuple(value.lower() for value in rule.all_on_same_line),
        }
        states.append({"rule": rule, "values": values, "found": set(), "evidence": set()})
        for kind, terms in values.items():
            for term in terms:
                term_uses.setdefault(term, []).append((index, kind))

    pattern = re.compile("|".join(re.escape(term) for term in sorted(term_uses, key=len, reverse=True)), re.I)
    line_number = 1
    previous_position = 0
    same_line_hits: dict[tuple[int, int], set[str]] = {}
    for match in pattern.finditer(context.content):
        line_number += context.content.count("\n", previous_position, match.start())
        previous_position = match.start()
        term = match.group(0).lower()
        for index, kind in term_uses[term]:
            if kind == "word":
                before = context.content[match.start() - 1] if match.start() else ""
                after = context.content[match.end()] if match.end() < len(context.content) else ""
                if (before and (before.isalnum() or before == "_")) or (after and (after.isalnum() or after == "_")):
                    continue
            states[index]["found"].add((kind, term))
            states[index]["evidence"].add(line_number)
            if kind == "same":
                same_line_hits.setdefault((index, line_number), set()).add(term)

    for (index, _line_number), hits in same_line_hits.items():
        if all(term in hits for term in states[index]["values"]["same"]):
            states[index]["found"].add(("same_line", "complete"))

    findings = []
    for state in states:
        values, found = state["values"], state["found"]
        if values["any"] and not any(("any", term) in found for term in values["any"]):
            continue
        if values["word"] and not any(("word", term) in found for term in values["word"]):
            continue
        if values["all"] and not all(("all", term) in found for term in values["all"]):
            continue
        if values["same"] and ("same_line", "complete") not in found:
            continue
        definition = state["rule"].definition
        findings.append(Finding(
            definition.id, definition.category, definition.title, definition.description,
            definition.solution, tuple(sorted(state["evidence"])),
        ))
    return findings

def evaluate_text_rules_bytes(rules: list[TextRule], content: bytes) -> list[Finding]:
    """Evaluate large logs while retaining repeated evidence with bounded storage."""
    newline = bytes((10,))
    evidence_limit = 10_000

    def variants(value: str) -> tuple[bytes, ...]:
        encoded = value.encode()
        return tuple(dict.fromkeys((encoded, encoded.lower(), encoded.upper())))

    def matching_positions(value: str, word_bounded: bool = False) -> list[int]:
        matches = set()
        for candidate in variants(value):
            position = content.find(candidate)
            while position >= 0 and len(matches) < evidence_limit:
                before = content[position - 1] if position else None
                end = position + len(candidate)
                after = content[end] if end < len(content) else None
                bounded = not (
                    (before is not None and (chr(before).isalnum() or before == 95))
                    or (after is not None and (chr(after).isalnum() or after == 95))
                )
                if not word_bounded or bounded:
                    matches.add(position)
                position = content.find(candidate, position + max(1, len(candidate)))
        return sorted(matches)

    pending = []
    for rule in rules:
        evidence_positions = []
        if rule.any_of:
            positions = [position for value in rule.any_of for position in matching_positions(value)]
            if not positions:
                continue
            evidence_positions.extend(positions)
        if rule.word_bounded_any_of:
            positions = [
                position
                for value in rule.word_bounded_any_of
                for position in matching_positions(value, True)
            ]
            if not positions:
                continue
            evidence_positions.extend(positions)
        if rule.all_of:
            positions_by_value = [matching_positions(value) for value in rule.all_of]
            if any(not positions for positions in positions_by_value):
                continue
            evidence_positions.extend(
                position for positions in positions_by_value for position in positions
            )
        if rule.all_on_same_line:
            anchor = max(rule.all_on_same_line, key=len)
            matched_lines = set()
            for position in matching_positions(anchor):
                line_start = content.rfind(newline, 0, position) + 1
                line_end = content.find(newline, position)
                if line_end < 0:
                    line_end = len(content)
                line = content[line_start:line_end].lower()
                if all(value.lower().encode() in line for value in rule.all_on_same_line):
                    matched_lines.add(line_start)
                    if len(matched_lines) >= evidence_limit:
                        break
            if not matched_lines:
                continue
            evidence_positions.extend(matched_lines)
        pending.append((rule.definition, tuple(sorted(set(evidence_positions)))))

    positions = sorted({position for _definition, evidence in pending for position in evidence})
    position_lines = {}
    line_number = 1
    cursor = 0
    for position in positions:
        while True:
            next_newline = content.find(newline, cursor, position)
            if next_newline < 0:
                break
            line_number += 1
            cursor = next_newline + 1
        position_lines[position] = line_number

    findings = []
    for definition, evidence in pending:
        evidence_lines = tuple(sorted({position_lines[position] for position in evidence}))[:evidence_limit]
        findings.append(Finding(
            definition.id,
            definition.category,
            definition.title,
            definition.description,
            definition.solution,
            evidence_lines,
        ))
    return findings
