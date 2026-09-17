"""Stable data types shared by the scanner and recommendation rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


Category = Literal["critical", "error", "warning", "schema", "advice"]


@dataclass(frozen=True)
class ScanContext:
    """Immutable, parsed input supplied to every recommendation rule."""

    filename: str
    content: str
    lines: tuple[str, ...]
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
        return cls(filename, content, tuple(content.splitlines()), kometa_version, run_time, complete)


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
