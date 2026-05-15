"""Tests for policy composition (multiple --policy files with precedence)."""
import os
import pytest
from mcpfw.policy import load_composed_policy, load_policy
from mcpfw.session import Session


POLICIES_DIR = os.path.join(os.path.dirname(__file__), "..", "policies")


class TestComposition:
    def test_single_policy_unchanged(self, tmp_path):
        p = tmp_path / "simple.yaml"
        p.write_text("name: simple\nrules:\n  - action: allow\n    tools: ['*']\n")
        policy = load_composed_policy([str(p)])
        assert policy.name == "simple"
        assert len(policy.rules) == 1

    def test_two_policies_merged(self, tmp_path):
        org = tmp_path / "org.yaml"
        org.write_text("name: org\nrules:\n  - action: deny\n    name: org_deny\n    tools: ['dangerous']\n    message: blocked\n")
        team = tmp_path / "team.yaml"
        team.write_text("name: team\nrules:\n  - action: allow\n    name: team_allow\n    tools: ['safe']\n")
        policy = load_composed_policy([str(org), str(team)])
        assert policy.name == "org + team"
        assert len(policy.rules) == 2
        assert policy.rules[0].name == "org_deny"
        assert policy.rules[1].name == "team_allow"

    def test_higher_priority_deny_wins(self, tmp_path):
        """Org denies write_file to .ssh. Team can't override."""
        org = tmp_path / "org.yaml"
        org.write_text("""
name: org
rules:
  - action: deny
    name: org_block_ssh
    tools: ["write_file"]
    when:
      arg_matches:
        path: ["~/.ssh/**"]
    message: "ORG blocked"
""")
        team = tmp_path / "team.yaml"
        team.write_text("""
name: team
rules:
  - action: allow
    name: team_allow_all
    tools: ["*"]
""")
        policy = load_composed_policy([str(org), str(team)])
        # Org deny comes first, so write to .ssh is blocked
        result = policy.evaluate({"name": "write_file", "arguments": {"path": "~/.ssh/id_rsa"}})
        assert result.action == "deny"
        assert result.rule_name == "org_block_ssh"

    def test_lower_priority_allows_non_denied(self, tmp_path):
        """Team allows tools that org doesn't explicitly deny."""
        org = tmp_path / "org.yaml"
        org.write_text("""
name: org
rules:
  - action: deny
    name: org_block_ssh
    tools: ["write_file"]
    when:
      arg_matches:
        path: ["~/.ssh/**"]
    message: "ORG blocked"
""")
        team = tmp_path / "team.yaml"
        team.write_text("""
name: team
rules:
  - action: allow
    name: team_allow_all
    tools: ["*"]
""")
        policy = load_composed_policy([str(org), str(team)])
        # write_file to a safe path is allowed by team
        result = policy.evaluate({"name": "write_file", "arguments": {"path": "./src/main.py"}})
        assert result.action == "allow"

    def test_default_action_from_highest_priority(self, tmp_path):
        org = tmp_path / "org.yaml"
        org.write_text("name: org\ndefault_action: deny\nrules: []\n")
        team = tmp_path / "team.yaml"
        team.write_text("name: team\ndefault_action: allow\nrules: []\n")
        policy = load_composed_policy([str(org), str(team)])
        assert policy.default_action == "deny"

    def test_scan_responses_any_layer_wins(self, tmp_path):
        org = tmp_path / "org.yaml"
        org.write_text("name: org\nscan_responses:\n  enabled: true\nrules: []\n")
        team = tmp_path / "team.yaml"
        team.write_text("name: team\nrules: []\n")
        policy = load_composed_policy([str(org), str(team)])
        assert policy.scan_responses.get("enabled") is True

    def test_bundled_policies_compose(self):
        """Verify the bundled org + team policies compose correctly."""
        org_path = os.path.join(POLICIES_DIR, "org-baseline.yaml")
        team_path = os.path.join(POLICIES_DIR, "team-support.yaml")
        if not os.path.exists(org_path):
            pytest.skip("bundled policies not found")
        policy = load_composed_policy([org_path, team_path])
        assert "org-baseline" in policy.name
        assert "team-support" in policy.name
        # Org deny on .ssh should still work
        result = policy.evaluate({"name": "write_file", "arguments": {"path": "~/.ssh/key"}})
        assert result.action == "deny"
        # Team allows search_kb
        result = policy.evaluate({"name": "search_kb", "arguments": {}})
        assert result.action == "allow"
