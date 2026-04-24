"""Response scanner — detect prompt injection patterns in MCP server responses."""

from __future__ import annotations
import re
from dataclasses import dataclass, field


# Default patterns that indicate prompt injection in tool output.
# Sourced from VIGIL (arXiv 2604) and tool-stream-injection research.
DEFAULT_PATTERNS: list[str] = [
    r"(?i)ignore\s+(all\s+)?previous\s+instructions",
    r"(?i)you\s+are\s+now\s+a",
    r"(?i)system\s*:\s*you",
    r"(?i)forget\s+(everything|all|your)\s+(above|previous|prior)",
    r"(?i)new\s+instructions?\s*:",
    r"(?i)do\s+not\s+follow\s+(the\s+)?(user|original|previous)",
    r"(?i)<\s*/?system\s*>",
    r"(?i)\[INST\]",
    r"(?i)###\s*(system|instruction)",
]


@dataclass
class ResponseScanner:
    patterns: list[re.Pattern] = field(default_factory=list)

    @classmethod
    def from_config(cls, extra_patterns: list[str] | None = None) -> ResponseScanner:
        raw = DEFAULT_PATTERNS + (extra_patterns or [])
        return cls(patterns=[re.compile(p) for p in raw])

    def scan(self, text: str) -> str | None:
        """Return the matched pattern string if injection detected, else None."""
        for pat in self.patterns:
            if pat.search(text):
                return pat.pattern
        return None
