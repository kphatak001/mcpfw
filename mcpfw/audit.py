"""Audit logger — JSON-lines append log of all tool call decisions."""

from __future__ import annotations
import json
import sys
import time
from pathlib import Path


class AuditLog:
    def __init__(self, path: str | None = None):
        self._file = open(path, "a") if path else None

    def log_call(self, request: dict, decision) -> None:
        params = request.get("params", {})
        self._write({
            "event": "tool_call",
            "tool": params.get("name", ""),
            "arguments": params.get("arguments", {}),
            "decision": decision.action,
            "rule": decision.rule_name,
            "message": decision.message,
        })

    def log_human_decision(self, request: dict, approved: bool) -> None:
        params = request.get("params", {})
        self._write({
            "event": "human_decision",
            "tool": params.get("name", ""),
            "approved": approved,
        })

    def log_passthrough(self, message: dict) -> None:
        method = message.get("method", "")
        if method:  # only log methods, not responses
            self._write({"event": "passthrough", "method": method})

    def _write(self, entry: dict) -> None:
        entry["timestamp"] = time.time()
        entry["iso_time"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line = json.dumps(entry, default=str)
        if self._file:
            self._file.write(line + "\n")
            self._file.flush()
        # Also write summary to stderr for visibility
        if entry.get("event") == "tool_call" and entry.get("decision") != "allow":
            sys.stderr.write(f"mcpfw [{entry['decision'].upper()}] {entry['tool']}: {entry.get('message', '')}\n")

    def close(self) -> None:
        if self._file:
            self._file.close()
