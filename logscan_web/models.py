"""Stable data types shared by the scanner and recommendation rules."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
import re
from typing import Literal


Category = Literal["critical", "error", "warning", "schema", "advice"]


@dataclass(frozen=True)
class LogLines:
    """Re-iterable line view that does not copy an entire large log."""

    content: str

    def __iter__(self) -> Iterator[str]:
        for match in re.finditer(r"[^\r\n]*(?:\r\n|\r|\n|$)", self.content):
            value = match.group(0)
            if not value:
                break
            yield value.rstrip("\r\n")


@dataclass(frozen=True)
class ScanContext:
    """Immutable, parsed input supplied to every recommendation rule."""

    filename: str
    content: str
    lines: LogLines
    kometa_version: str | None = None
    run_time: str | None = None
    complete: bool = False

    @classmethod
    def from_content(
        cls,
        filename: str,
        content: str,
        *,
        kometa_version: str | None = None,
        run_time: str | None = None,
        complete: bool = False,
    ) -> "ScanContext":
        return cls(filename, content, LogLines(content), kometa_version, run_time, complete)


@dataclass(frozen=True)
class Finding:
    """A structured recommendation emitted by one rule."""

    id: str
    category: Category
    title: str
    description: str
    solution: str = "Review the referenced log entries and update the affected configuration."
    evidence_lines: tuple[int, ...] = field(default_factory=tuple)
    details: str = ""

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.category,
            "title": self.title,
            "description": self.description,
            "solution": self.solution,
            "evidence_lines": list(self.evidence_lines),
            "message": self.details or f"**{self.title}**\nIssue: {self.description}\n\nProposed solution: {self.solution}",
        }
