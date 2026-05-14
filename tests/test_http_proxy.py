"""Test HTTP proxy mode."""

import asyncio
import json
import pytest

from mcpfw.http_proxy import HttpProxy, run_http_proxy
from mcpfw.policy import load_policy
from mcpfw.audit import AuditLog


POLICY_PATH = "policies/standard.yaml"


@pytest.fixture
def policy():
    return load_policy(POLICY_PATH)


@pytest.fixture
def audit(tmp_path):
    return AuditLog(str(tmp_path / "audit.jsonl"))


@pytest.fixture
def proxy(policy, audit):
    return HttpProxy(
        target="http://localhost:9999",  # won't actually connect in unit tests
        policy=policy,
        audit=audit,
    )


def test_proxy_blocks_denied_tool(proxy):
    """Tool call to sensitive path should be blocked without forwarding."""
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "~/.ssh/id_rsa"}}
    }
    body = json.dumps(msg).encode()

    result = asyncio.run(proxy._process_request(body, proxy._get_session("test"), "test"))
    resp = json.loads(result)

    assert "error" in resp
    assert "BLOCKED" in resp["error"]["message"]


def test_proxy_session_tracks_calls(proxy):
    """Multiple calls should accumulate in session state."""
    session = proxy._get_session("agent-1")

    for i in range(3):
        msg = {"jsonrpc": "2.0", "id": i, "method": "tools/call",
               "params": {"name": "read_file", "arguments": {"path": f"/tmp/file{i}"}}}
        asyncio.run(proxy._process_request(json.dumps(msg).encode(), session, "agent-1"))

    assert len(session.history) == 3


def test_proxy_separate_sessions_per_agent(proxy):
    """Different agent IDs get independent sessions."""
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "read_file", "arguments": {"path": "/tmp/x"}}}
    body = json.dumps(msg).encode()

    asyncio.run(proxy._process_request(body, proxy._get_session("agent-a"), "agent-a"))
    asyncio.run(proxy._process_request(body, proxy._get_session("agent-b"), "agent-b"))

    assert len(proxy._get_session("agent-a").history) == 1
    assert len(proxy._get_session("agent-b").history) == 1


def test_parse_listen():
    from mcpfw.cli import _parse_listen

    assert _parse_listen(":8443") == ("0.0.0.0", 8443)
    assert _parse_listen("127.0.0.1:8443") == ("127.0.0.1", 8443)
    assert _parse_listen("8443") == ("0.0.0.0", 8443)
