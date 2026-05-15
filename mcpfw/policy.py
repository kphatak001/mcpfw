"""Policy engine — parse YAML policies, evaluate rules against tool calls."""

from __future__ import annotations
import fnmatch
import re
import time
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
    action: str  # allow, deny, ask, rate_limit, budget, sequence, requires
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
    # temporal precondition fields
    requires_event: str = ""  # tool pattern that must have occurred
    within_seconds: float = 0  # time window for the required event
    cooldown_seconds: float = 0  # min time since a specific event before this is allowed


@dataclass
class Policy:
    name: str
    rules: list[Rule]
    scan_responses: dict = field(default_factory=dict)
    default_action: str = "allow"  # "allow", "deny", or "ask"
    _rate_limiters: dict[str, RateLimiter] = field(default_factory=dict, repr=False)

    def filter_tools(self, tools: list[dict]) -> tuple[list[dict], list[str]]:
        """Filter a tools/list response, removing tools the agent should never see.

        Returns (visible_tools, hidden_names).  A tool is hidden when
        ``evaluate`` with empty arguments yields ``deny``.
        """
        visible, hidden = [], []
        for tool in tools:
            name = tool.get("name", "")
            decision = self.evaluate({"name": name, "arguments": {}})
            if decision.action == "deny":
                hidden.append(name)
            else:
                visible.append(tool)
        return visible, hidden

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

            if rule.action == "requires":
                result = _check_requires(rule, tool_name, arguments, session)
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

        return Decision(self.default_action, "_default", "No matching rule — default " + self.default_action)


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


def _check_requires(rule: Rule, current_tool: str, current_args: dict, session) -> Decision | None:
    """Enforce temporal preconditions: tool X requires event Y within Z seconds."""
    if session is None:
        return None
    if not _tool_matches(current_tool, rule.tools):
        return None
    if rule.when and not _when_matches(current_args, rule.when):
        return None

    now = time.time()

    # requires_event: block unless a matching event occurred within the time window
    if rule.requires_event and rule.within_seconds:
        cutoff = now - rule.within_seconds
        found = any(
            fnmatch.fnmatch(r.tool, rule.requires_event) and r.timestamp > cutoff
            for r in session.history
        )
        if not found:
            window_desc = _format_duration(rule.within_seconds)
            return Decision(
                "deny", rule.name,
                rule.message or f"Requires '{rule.requires_event}' within last {window_desc}"
            )

    # cooldown_seconds: block if a matching event occurred too recently
    if rule.cooldown_seconds and rule.requires_event:
        cutoff = now - rule.cooldown_seconds
        too_recent = any(
            fnmatch.fnmatch(r.tool, rule.requires_event) and r.timestamp > cutoff
            for r in session.history
        )
        if too_recent:
            window_desc = _format_duration(rule.cooldown_seconds)
            return Decision(
                "deny", rule.name,
                rule.message or f"Cooldown: must wait {window_desc} after '{rule.requires_event}'"
            )

    return None


def _format_duration(seconds: float) -> str:
    if seconds >= 3600:
        return f"{seconds / 3600:.0f}h"
    if seconds >= 60:
        return f"{seconds / 60:.0f}m"
    return f"{seconds:.0f}s"


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


def _parse_duration(spec: str) -> float:
    """Parse duration strings like '30m', '2h', '300s', '1h30m' into seconds."""
    if not spec:
        return 0
    if isinstance(spec, (int, float)):
        return float(spec)
    total = 0
    import re as _re
    for match in _re.finditer(r'(\d+(?:\.\d+)?)\s*([smh]?)', str(spec)):
        val, unit = float(match.group(1)), match.group(2)
        if unit == 'h':
            total += val * 3600
        elif unit == 'm':
            total += val * 60
        else:
            total += val
    return total or float(spec) if spec.replace('.', '').isdigit() else total


def load_composed_policy(paths: list[str]) -> Policy:
    """Load and compose multiple policy files with precedence.

    First path = highest priority. Deny rules from higher-priority policies
    cannot be overridden by allow rules in lower-priority policies.

    Composition rules:
    - Rules are concatenated in order (highest priority first)
    - scan_responses is merged (any layer enabling it wins)
    - default_action uses the highest-priority policy's setting
    - Name is joined with " + "
    """
    if len(paths) == 1:
        return load_policy(paths[0])

    policies = [load_policy(p) for p in paths]

    merged_rules = []
    for p in policies:
        merged_rules.extend(p.rules)

    merged_scan = {}
    for p in policies:
        if p.scan_responses.get("enabled"):
            merged_scan = p.scan_responses
            break

    return Policy(
        name=" + ".join(p.name for p in policies),
        rules=merged_rules,
        scan_responses=merged_scan,
        default_action=policies[0].default_action,
    )


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
            requires_event=rd.get("requires_event", ""),
            within_seconds=_parse_duration(rd.get("within", "")),
            cooldown_seconds=_parse_duration(rd.get("cooldown", "")),
        ))

    return Policy(
        name=data.get("name", "unnamed"),
        rules=rules,
        scan_responses=data.get("scan_responses", {}),
        default_action=data.get("default_action", "allow"),
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
