"""Tests for temporal precondition rules (requires, cooldown)."""
import time
import pytest
from mcpfw.policy import Policy, Rule, Decision, _parse_duration
from mcpfw.session import Session


def make_policy(rules):
    return Policy(name="test", rules=rules)


def make_session_with_history(calls):
    """Create session with pre-populated history. calls = [(tool, seconds_ago)]"""
    s = Session()
    now = time.time()
    for tool, ago in calls:
        from mcpfw.session import CallRecord
        s.history.append(CallRecord(tool=tool, arguments={}, action="allow", timestamp=now - ago))
    return s


class TestRequiresEvent:
    def test_blocks_when_no_prior_event(self):
        policy = make_policy([Rule(
            action="requires", name="payment_needs_approval",
            tools=["payment_api"],
            requires_event="human_approval",
            within_seconds=1800,
            message="Payment requires human approval within last 30m"
        )])
        session = Session()
        result = policy.evaluate({"name": "payment_api", "arguments": {}}, session)
        assert result.action == "deny"
        assert "human approval" in result.message.lower() or "human_approval" in result.message

    def test_allows_when_prior_event_within_window(self):
        policy = make_policy([Rule(
            action="requires", name="payment_needs_approval",
            tools=["payment_api"],
            requires_event="human_approval",
            within_seconds=1800,
        )])
        session = make_session_with_history([("human_approval", 600)])  # 10 min ago
        result = policy.evaluate({"name": "payment_api", "arguments": {}}, session)
        assert result.action == "allow"

    def test_blocks_when_prior_event_outside_window(self):
        policy = make_policy([Rule(
            action="requires", name="payment_needs_approval",
            tools=["payment_api"],
            requires_event="human_approval",
            within_seconds=1800,
        )])
        session = make_session_with_history([("human_approval", 3600)])  # 60 min ago
        result = policy.evaluate({"name": "payment_api", "arguments": {}}, session)
        assert result.action == "deny"

    def test_glob_matching_on_requires_event(self):
        policy = make_policy([Rule(
            action="requires", name="admin_needs_auth",
            tools=["admin_*"],
            requires_event="auth_*",
            within_seconds=300,
        )])
        session = make_session_with_history([("auth_mfa", 120)])  # 2 min ago
        result = policy.evaluate({"name": "admin_delete", "arguments": {}}, session)
        assert result.action == "allow"

    def test_non_matching_tool_passes_through(self):
        policy = make_policy([Rule(
            action="requires", name="payment_needs_approval",
            tools=["payment_api"],
            requires_event="human_approval",
            within_seconds=1800,
        )])
        session = Session()
        result = policy.evaluate({"name": "read_file", "arguments": {}}, session)
        assert result.action == "allow"


class TestCooldown:
    def test_blocks_during_cooldown(self):
        policy = make_policy([Rule(
            action="requires", name="no_rapid_delete",
            tools=["delete_account"],
            requires_event="create_account",
            cooldown_seconds=300,
            within_seconds=0,
            message="Cannot delete within 5m of creation"
        )])
        session = make_session_with_history([("create_account", 60)])  # 1 min ago
        result = policy.evaluate({"name": "delete_account", "arguments": {}}, session)
        assert result.action == "deny"
        assert "5m" in result.message or "cooldown" in result.message.lower()

    def test_allows_after_cooldown_expires(self):
        policy = make_policy([Rule(
            action="requires", name="no_rapid_delete",
            tools=["delete_account"],
            requires_event="create_account",
            cooldown_seconds=300,
            within_seconds=0,
        )])
        session = make_session_with_history([("create_account", 600)])  # 10 min ago
        result = policy.evaluate({"name": "delete_account", "arguments": {}}, session)
        assert result.action == "allow"


class TestParseDuration:
    def test_seconds(self):
        assert _parse_duration("300s") == 300
        assert _parse_duration("300") == 300

    def test_minutes(self):
        assert _parse_duration("30m") == 1800

    def test_hours(self):
        assert _parse_duration("2h") == 7200

    def test_combined(self):
        assert _parse_duration("1h30m") == 5400

    def test_empty(self):
        assert _parse_duration("") == 0

    def test_numeric(self):
        assert _parse_duration(600) == 600


class TestYAMLIntegration:
    def test_load_requires_rule(self, tmp_path):
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("""
name: temporal-test
rules:
  - name: payment_gate
    action: requires
    tools: ["payment_*"]
    requires_event: "human_approval"
    within: "30m"
    message: "Payment requires human approval within 30 minutes"
  - name: delete_cooldown
    action: requires
    tools: ["delete_*"]
    requires_event: "create_*"
    cooldown: "5m"
    message: "Cannot delete within 5 minutes of creation"
  - action: allow
    tools: ["*"]
""")
        from mcpfw.policy import load_policy
        policy = load_policy(str(policy_file))
        assert len(policy.rules) == 3
        assert policy.rules[0].requires_event == "human_approval"
        assert policy.rules[0].within_seconds == 1800
        assert policy.rules[1].cooldown_seconds == 300

        # Test enforcement
        session = Session()
        result = policy.evaluate({"name": "payment_submit", "arguments": {}}, session)
        assert result.action == "deny"
