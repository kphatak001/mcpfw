"""JSON-RPC stdio proxy — spawn child MCP server, intercept tool calls."""

from __future__ import annotations
import asyncio
import json
import sys
from typing import Any

from .policy import Policy, Decision
from .audit import AuditLog
from .session import Session


async def run_proxy(command: list[str], policy: Policy, audit: AuditLog) -> int:
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
                else:
                    audit.log_passthrough(msg)

                proc.stdin.write(json.dumps(msg).encode() + b"\n")
                await proc.stdin.drain()

    async def server_to_agent():
        """Read from MCP server (child stdout), forward to agent."""
        while True:
            line = await proc.stdout.readline()
            if not line:
                return
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

    # Write prompt to stderr so it doesn't interfere with JSON-RPC on stdout
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
