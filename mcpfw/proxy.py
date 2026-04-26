"""JSON-RPC stdio proxy — spawn child MCP server, intercept tool calls."""

from __future__ import annotations
import asyncio
import json
import sys
from typing import Any

from .policy import Policy, Decision
from .audit import AuditLog
from .session import Session
from .rules.response_scanner import ResponseScanner


async def run_proxy(
    command: list[str],
    policy: Policy,
    audit: AuditLog,
    scanner: ResponseScanner | None = None,
) -> int:
    session = Session()

    proc = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=sys.stderr,
    )

    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)

    writer_transport, _ = await asyncio.get_event_loop().connect_write_pipe(
        asyncio.BaseProtocol, sys.stdout.buffer
    )
    stdout_writer = writer_transport

    # Track pending request IDs for response interception
    pending_tool_calls: set[Any] = set()
    pending_tools_list: set[Any] = set()

    async def agent_to_server():
        """Read from agent (stdin), evaluate policy, forward or block."""
        buf = b""
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                if proc.stdin:
                    proc.stdin.close()
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    proc.stdin.write(line + b"\n")
                    await proc.stdin.drain()
                    continue

                if msg.get("method") == "tools/call":
                    decision = policy.evaluate(msg.get("params", {}), session)
                    session.record_call(msg.get("params", {}), decision)
                    audit.log_call(msg, decision)

                    if decision.action == "deny":
                        resp = _error_response(msg, decision.message)
                        stdout_writer.write(json.dumps(resp).encode() + b"\n")
                        continue
                    elif decision.action == "ask":
                        approved = await _prompt_human(msg.get("params", {}))
                        if not approved:
                            resp = _error_response(msg, "Denied by user")
                            audit.log_human_decision(msg, False)
                            stdout_writer.write(json.dumps(resp).encode() + b"\n")
                            continue
                        audit.log_human_decision(msg, True)

                    # Track this request ID so we can scan the response
                    if scanner and msg.get("id") is not None:
                        pending_tool_calls.add(msg["id"])
                else:
                    # Track tools/list requests for discovery filtering
                    if msg.get("method") == "tools/list" and msg.get("id") is not None:
                        pending_tools_list.add(msg["id"])
                    audit.log_passthrough(msg)

                proc.stdin.write(json.dumps(msg).encode() + b"\n")
                await proc.stdin.drain()

    async def server_to_agent():
        """Read from MCP server (child stdout), filter discovery, scan responses, forward to agent."""
        while True:
            line = await proc.stdout.readline()
            if not line:
                return

            # Filter tools/list responses — strip tools the policy would deny
            line = _maybe_filter_tools_list(line, policy, pending_tools_list, audit)

            if scanner:
                line = _maybe_scan_response(line, scanner, pending_tool_calls, audit, stdout_writer)
                if line is None:
                    continue  # response was blocked

            stdout_writer.write(line)

    try:
        await asyncio.gather(agent_to_server(), server_to_agent())
    except (asyncio.CancelledError, BrokenPipeError):
        pass
    finally:
        if proc.returncode is None:
            proc.terminate()
            await proc.wait()

    return proc.returncode or 0


def _maybe_filter_tools_list(
    line: bytes,
    policy: Policy,
    pending: set,
    audit: AuditLog,
) -> bytes:
    """Strip denied tools from tools/list responses so the agent never sees them."""
    try:
        msg = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return line

    msg_id = msg.get("id")
    if msg_id not in pending:
        return line

    pending.discard(msg_id)

    tools = msg.get("result", {}).get("tools") if isinstance(msg.get("result"), dict) else None
    if not isinstance(tools, list):
        return line

    visible, hidden = policy.filter_tools(tools)
    if hidden:
        msg["result"]["tools"] = visible
        audit.log_discovery_filtered(hidden)
        return json.dumps(msg).encode() + b"\n"

    return line


def _maybe_scan_response(
    line: bytes,
    scanner: ResponseScanner,
    pending: set,
    audit: AuditLog,
    stdout_writer,
) -> bytes | None:
    """Scan a server response for injection. Returns line to forward, or None if blocked."""
    try:
        msg = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return line  # not JSON, pass through

    msg_id = msg.get("id")
    if msg_id not in pending:
        return line  # not a tool call response

    pending.discard(msg_id)

    # Extract text content from the result
    text = _extract_response_text(msg)
    if not text:
        return line

    matched = scanner.scan(text)
    if matched:
        audit.log_response_blocked(msg_id, matched)
        # Replace with a sanitized error so the agent knows something was wrong
        sanitized = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": -32600,
                "message": "BLOCKED by mcpfw: server response contained suspected prompt injection",
            },
        }
        stdout_writer.write(json.dumps(sanitized).encode() + b"\n")
        return None

    return line


def _extract_response_text(msg: dict) -> str:
    """Pull text from MCP tool result (handles content array and plain text)."""
    result = msg.get("result")
    if not result:
        return ""
    # MCP tool results have content: [{type: "text", text: "..."}]
    content = result.get("content") if isinstance(result, dict) else None
    if isinstance(content, list):
        parts = [c.get("text", "") for c in content if isinstance(c, dict)]
        return " ".join(parts)
    if isinstance(result, dict) and "text" in result:
        return str(result["text"])
    # Fallback: stringify the whole result
    return json.dumps(result) if result else ""


def _error_response(request: dict, message: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "error": {
            "code": -32600,
            "message": f"BLOCKED by mcpfw: {message}",
        },
    }


async def _prompt_human(params: dict) -> bool:
    tool = params.get("name", "unknown")
    args = params.get("arguments", {})
    args_str = json.dumps(args, indent=2) if args else "{}"

    sys.stderr.write(f"\n{'='*60}\n")
    sys.stderr.write(f"🔒 mcpfw: Tool call requires approval\n")
    sys.stderr.write(f"   Tool: {tool}\n")
    sys.stderr.write(f"   Args: {args_str}\n")
    sys.stderr.write(f"{'='*60}\n")
    sys.stderr.write("   Allow? [y/N]: ")
    sys.stderr.flush()

    loop = asyncio.get_event_loop()
    try:
        response = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: input()),
            timeout=120.0,
        )
        return response.strip().lower() in ("y", "yes")
    except (asyncio.TimeoutError, EOFError):
        sys.stderr.write("   Timed out / no input — denying.\n")
        return False
