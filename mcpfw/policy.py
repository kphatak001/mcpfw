"""Policy engine — parse YAML policies, evaluate rules against tool calls."""

from __future__ import annotations
import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from .rules.rate_limit import RateLimiter


@dataclass
class Decision:
    action: str  # allow, deny, ask
    rule_name: str = ""
    message: str = ""


@dataclass
class Rule:
    action: str  # allow, deny, ask, rate_limit, budget, sequence
    tools: list[str] = field(default_factory=lambda: ["*"])
    when: dict = field(default_factory=dict)
    message: str = ""
    rate: str = ""  # e.g. "10/minute"
    name: str = ""
    # budget fields
    max_calls: int = 0
    max_per_tool: int = 0
    # sequence fields
    pattern: list[str] = field(default_factory=list)


@dataclass
class Policy:
    name: str
    rules: list[Rule]
    scan_responses: dict = field(default_factory=dict)
    _rate_limiters: dict[str, RateLimiter] = field(default_factory=dict, repr=False)

    def evaluate(self, params: dict, session: Any = None) -> Decision:
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        for rule in self.rules:
            if rule.action == "budget":
                result = _check_budget(rule, session, tool_name)
                if result:
                    return result
                continue

            if rule.action == "sequence":
                result = _check_sequence(rule, tool_name, arguments, session)
                if result:
                    return result
                continue

            if not _tool_matches(tool_name, rule.tools):
                continue
            if rule.when and not _when_matches(arguments, rule.when):
                continue

            if rule.action == "rate_limit":
                key = f"{rule.name}:{','.join(rule.tools)}"
                if key not in self._rate_limiters:
                    self._rate_limiters[key] = RateLimiter.from_spec(rule.rate)
                if not self._rate_limiters[key].allow():
                    return Decision("deny", rule.name, rule.message or f"Rate limit exceeded: {rule.rate}")
                continue  # rate_limit rules don't terminate — fall through to next

            return Decision(rule.action, rule.name, rule.message)

        return Decision("allow", "_default", "No matching rule — default allow")


def _check_budget(rule: Rule, session, current_tool: str = "") -> Decision | None:
    """Enforce session-wide call budgets."""
    if session is None:
        return None
    if rule.max_calls and len(session.history) >= rule.max_calls:
        return Decision("deny", rule.name, rule.message or f"Session budget exceeded: {rule.max_calls} calls")
    if rule.max_per_tool and current_tool:
        count = sum(1 for r in session.history if r.tool == current_tool)
        if count >= rule.max_per_tool:
            return Decision("deny", rule.name, rule.message or f"Per-tool budget exceeded for {current_tool}: {rule.max_per_tool}")
    return None


def _check_sequence(rule: Rule, current_tool: str, current_args: dict, session) -> Decision | None:
    """Detect suspicious multi-call sequences."""
    if session is None or not rule.pattern:
        return None
    steps = rule.pattern
    if len(steps) < 2:
        return None

    # Current call must match the last step
    if not _step_matches(current_tool, _first_arg_value(current_args), steps[-1]):
        return None

    # Walk backwards through history to find preceding steps
    needed = list(reversed(steps[:-1]))
    idx = 0
    for rec in reversed(session.history):
        if idx >= len(needed):
            break
        if _step_matches(rec.tool, _first_arg_value(rec.arguments), needed[idx]):
            idx += 1

    if idx >= len(needed):
        return Decision("deny", rule.name, rule.message or f"Suspicious call sequence detected")
    return None


def _step_matches(tool: str, arg_hint: str, step: str) -> bool:
    """Match a sequence step like 'read_file:*.env*' or just 'run_command'."""
    if ":" in step:
        tool_pat, arg_pat = step.split(":", 1)
        return fnmatch.fnmatch(tool, tool_pat) and fnmatch.fnmatch(arg_hint, arg_pat)
    return fnmatch.fnmatch(tool, step)


def _first_arg_value(arguments: dict) -> str:
    """Return the first argument value as string (for sequence matching)."""
    if not arguments:
        return ""
    return str(next(iter(arguments.values()), ""))


def load_policy(path: str) -> Policy:
    with open(path) as f:
        data = yaml.safe_load(f)

    rules = []
    for i, rd in enumerate(data.get("rules", [])):
        rules.append(Rule(
            action=rd["action"],
            tools=rd.get("tools", ["*"]),
            when=rd.get("when", {}),
            message=rd.get("message", ""),
            rate=rd.get("rate", ""),
            name=rd.get("name", f"rule_{i}"),
            max_calls=rd.get("max_calls", 0),
            max_per_tool=rd.get("max_per_tool", 0),
            pattern=rd.get("pattern", []),
        ))

    return Policy(
        name=data.get("name", "unnamed"),
        rules=rules,
        scan_responses=data.get("scan_responses", {}),
    )


def _tool_matches(tool_name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(tool_name, p) for p in patterns)


def _when_matches(arguments: dict, when: dict) -> bool:
    arg_matches = when.get("arg_matches", {})
    for arg_name, patterns in arg_matches.items():
        value = _deep_get(arguments, arg_name)
        if value is None:
            continue
        value_str = str(value)
        if any(fnmatch.fnmatch(value_str, p) for p in patterns):
            return True

    arg_regex = when.get("arg_regex", {})
    for arg_name, pattern in arg_regex.items():
        value = _deep_get(arguments, arg_name)
        if value and re.search(pattern, str(value)):
            return True

    arg_contains = when.get("arg_contains", {})
    for arg_name, substrings in arg_contains.items():
        value = _deep_get(arguments, arg_name)
        if value and any(s in str(value) for s in substrings):
            return True

    return False


def _deep_get(d: dict, key: str) -> Any:
    """Get nested dict value via dot notation: 'a.b.c'."""
    parts = key.split(".")
    for p in parts:
        if isinstance(d, dict):
            d = d.get(p)
        else:
            return None
    return d
