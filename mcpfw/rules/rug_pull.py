"""Rug-pull detection: alert when MCP tool descriptions change after initial registration.

Attack pattern (postmark-mcp): A malicious MCP server publishes benign tool descriptions
to pass review, then silently changes them to include hidden instructions that manipulate
the agent. The descriptions are invisible to humans but processed by the LLM as trusted context.

This module caches tool descriptors on first tools/list response and flags any changes
on subsequent responses.
"""

from __future__ import annotations
import hashlib
import json
import time
from dataclasses import dataclass, field


@dataclass
class ToolBaseline:
    name: str
    description_hash: str
    input_schema_hash: str
    first_seen: float
    raw_description: str = ""


@dataclass
class RugPullAlert:
    tool_name: str
    field_changed: str  # "description" or "inputSchema"
    old_hash: str
    new_hash: str
    timestamp: float


class RugPullDetector:
    """Detects when MCP server tool descriptions change after initial registration."""

    def __init__(self):
        self.baselines: dict[str, ToolBaseline] = {}
        self._locked = False

    @property
    def is_locked(self) -> bool:
        """True after first tools/list response has been cached."""
        return self._locked

    @property
    def tool_count(self) -> int:
        return len(self.baselines)

    def register_tools(self, tools: list[dict]) -> list[RugPullAlert]:
        """Process a tools/list response. Returns alerts for any changed tools.
        
        First call: caches all tool descriptors as the baseline (no alerts).
        Subsequent calls: compares against baseline, alerts on any changes.
        """
        alerts = []
        now = time.time()

        for tool in tools:
            name = tool.get("name", "")
            desc_hash = _hash(tool.get("description", ""))
            schema_hash = _hash(json.dumps(tool.get("inputSchema", {}), sort_keys=True))

            if name not in self.baselines:
                # First time seeing this tool
                self.baselines[name] = ToolBaseline(
                    name=name,
                    description_hash=desc_hash,
                    input_schema_hash=schema_hash,
                    first_seen=now,
                    raw_description=tool.get("description", "")[:200],
                )
            else:
                # Compare against baseline
                baseline = self.baselines[name]

                if desc_hash != baseline.description_hash:
                    alerts.append(RugPullAlert(
                        tool_name=name,
                        field_changed="description",
                        old_hash=baseline.description_hash,
                        new_hash=desc_hash,
                        timestamp=now,
                    ))

                if schema_hash != baseline.input_schema_hash:
                    alerts.append(RugPullAlert(
                        tool_name=name,
                        field_changed="inputSchema",
                        old_hash=baseline.input_schema_hash,
                        new_hash=schema_hash,
                        timestamp=now,
                    ))

        if not self._locked and self.baselines:
            self._locked = True

        return alerts


def _hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()[:16]
