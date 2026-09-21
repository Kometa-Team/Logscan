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
    """Evaluate text rules against bytes without decoding or copying a large log."""
    states = []
    term_uses: dict[bytes, list[tuple[int, str]]] = {}
    for index, rule in enumerate(rules):
        values = {
            "any": tuple(value.lower().encode() for value in rule.any_of),
            "word": tuple(value.lower().encode() for value in rule.word_bounded_any_of),
            "all": tuple(value.lower().encode() for value in rule.all_of),
            "same": tuple(value.lower().encode() for value in rule.all_on_same_line),
        }
        states.append({"rule": rule, "values": values, "found": set(), "evidence": set()})
        for kind, terms in values.items():
            for term in terms:
                term_uses.setdefault(term, []).append((index, kind))

    pattern = re.compile(b"|".join(re.escape(term) for term in sorted(term_uses, key=len, reverse=True)), re.I)
    same_line_hits: dict[tuple[int, int], set[bytes]] = {}
    line_number = 1
    newline_cursor = 0
    chunk_start = 0
    chunk_size = 4 * 1024 * 1024
    overlap = max(map(len, term_uses), default=1)
    content_length = len(content)
    while chunk_start < content_length:
        chunk_end = min(content_length, chunk_start + chunk_size)
        scan_end = min(content_length, chunk_end + overlap)
        for match in pattern.finditer(content, chunk_start, scan_end):
            if match.start() >= chunk_end:
                break
            while True:
                newline = content.find(b"\n", newline_cursor, match.start())
                if newline < 0:
                    break
                line_number += 1
                newline_cursor = newline + 1
            term = match.group(0).lower()
            for index, kind in term_uses[term]:
                if kind == "word":
                    before = content[match.start() - 1] if match.start() else None
                    after = content[match.end()] if match.end() < content_length else None
                    if (before is not None and (chr(before).isalnum() or before == 95)) or (after is not None and (chr(after).isalnum() or after == 95)):
                        continue
                states[index]["found"].add((kind, term))
                states[index]["evidence"].add(line_number)
                if kind == "same":
                    same_line_hits.setdefault((index, line_number), set()).add(term)
        chunk_start = chunk_end
    for (index, _line_number), hits in same_line_hits.items():
        if all(term in hits for term in states[index]["values"]["same"]):
            states[index]["found"].add(("same_line", b"complete"))
    findings = []
    for state in states:
        values, found = state["values"], state["found"]
        if values["any"] and not any(("any", term) in found for term in values["any"]):
            continue
        if values["word"] and not any(("word", term) in found for term in values["word"]):
            continue
        if values["all"] and not all(("all", term) in found for term in values["all"]):
            continue
        if values["same"] and ("same_line", b"complete") not in found:
            continue
        definition = state["rule"].definition
        findings.append(Finding(
            definition.id, definition.category, definition.title, definition.description,
            definition.solution, tuple(sorted(state["evidence"])),
        ))
    return findings