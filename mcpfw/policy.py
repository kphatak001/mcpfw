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
    action: str  # allow, deny, ask, rate_limit
    tools: list[str] = field(default_factory=lambda: ["*"])
    when: dict = field(default_factory=dict)
    message: str = ""
    rate: str = ""  # e.g. "10/minute"
    name: str = ""


@dataclass
class Policy:
    name: str
    rules: list[Rule]
    _rate_limiters: dict[str, RateLimiter] = field(default_factory=dict, repr=False)

    def evaluate(self, params: dict, session: Any = None) -> Decision:
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        for rule in self.rules:
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
        ))

    return Policy(name=data.get("name", "unnamed"), rules=rules)


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
