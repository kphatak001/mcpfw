"""Session tracker — records tool call history for cross-call context."""

from __future__ import annotations
from dataclasses import dataclass, field
import time


@dataclass
class CallRecord:
    tool: str
    arguments: dict
    action: str
    timestamp: float


class Session:
    def __init__(self, max_history: int = 1000):
        self.history: list[CallRecord] = []
        self.max_history = max_history

    def record_call(self, params: dict, decision) -> None:
        self.history.append(CallRecord(
            tool=params.get("name", ""),
            arguments=params.get("arguments", {}),
            action=decision.action,
            timestamp=time.time(),
        ))
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history:]

    def recent_tools(self, window_seconds: float = 60.0) -> list[str]:
        cutoff = time.time() - window_seconds
        return [r.tool for r in self.history if r.timestamp > cutoff]
