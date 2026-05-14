"""MCP Streamable HTTP transport support.

The MCP spec (2025-03-26) defines Streamable HTTP as the standard remote transport:
- Client sends JSON-RPC via HTTP POST to the server endpoint
- Server responds with either:
  - Content-Type: application/json (single response)
  - Content-Type: text/event-stream (SSE stream for progressive results)
- Session management via Mcp-Session-Id header
- Supports resumable streams via Last-Event-ID

This module handles both response modes, applying policy inspection to each
JSON-RPC message in the stream before forwarding to the agent.

Reference: https://modelcontextprotocol.io/docs/concepts/transports
"""

from __future__ import annotations
import asyncio
import json
import sys
from urllib.parse import urlparse

from .policy import Policy, Decision
from .audit import AuditLog
from .session import Session
from .rules.response_scanner import ResponseScanner
from .rules.rug_pull import RugPullDetector

try:
    from agent_envelope import EnvelopeSession, load_envelope
    HAS_ENVELOPE = True
except ImportError:
    HAS_ENVELOPE = False


class StreamableHttpProxy:
    """Proxy for MCP Streamable HTTP transport.
    
    Handles both single-response and SSE-streamed responses from the MCP server.
    Applies per-call policy, envelope enforcement, response scanning, and rug-pull
    detection to every message in the stream.
    """

    def __init__(self, target: str, policy: Policy, audit: AuditLog,
                 scanner: ResponseScanner | None = None,
                 envelope_path: str | None = None):
        self.target = target.rstrip("/")
        self.policy = policy
        self.audit = audit
        self.scanner = scanner
        self.envelope_path = envelope_path
        self.sessions: dict[str, Session] = {}
        self.envelope_sessions: dict[str, "EnvelopeSession"] = {}
        self.rug_pull_detector = RugPullDetector()
        self._mcp_session_id: str | None = None

    def _get_session(self, agent_id: str) -> Session:
        if agent_id not in self.sessions:
            self.sessions[agent_id] = Session()
        return self.sessions[agent_id]

    def _get_envelope_session(self, agent_id: str):
        if not self.envelope_path or not HAS_ENVELOPE:
            return None
        if agent_id not in self.envelope_sessions:
            env = load_envelope(self.envelope_path)
            session = EnvelopeSession(env)
            session.__enter__()
            self.envelope_sessions[agent_id] = session
        return self.envelope_sessions[agent_id]

    async def handle_request(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter):
        """Handle one HTTP request with Streamable HTTP support."""
        try:
            request_line = await reader.readline()
            if not request_line:
                writer.close()
                return

            method, path, _ = request_line.decode().strip().split(" ", 2)
            headers = await self._read_headers(reader)
            content_length = int(headers.get("content-length", "0"))
            body = await reader.readexactly(content_length) if content_length else b""

            agent_id = headers.get("x-agent-id", headers.get("authorization", "anonymous"))
            session = self._get_session(agent_id)

            # Track MCP session ID
            if "mcp-session-id" in headers:
                self._mcp_session_id = headers["mcp-session-id"]

            # Parse and evaluate the request
            try:
                msg = json.loads(body)
            except json.JSONDecodeError:
                await self._proxy_raw(body, headers, writer)
                return

            # Apply per-call policy for tool calls
            if msg.get("method") == "tools/call":
                params = msg.get("params", {})
                decision = self.policy.evaluate(params, session)
                session.record_call(params, decision)
                self.audit.log_call(msg, decision)

                if decision.action == "deny":
                    self._write_json_response(writer, 200, {
                        "jsonrpc": "2.0", "id": msg.get("id"),
                        "error": {"code": -32600, "message": f"BLOCKED by mcpfw: {decision.message}"}
                    })
                    return

                # Envelope check
                env_session = self._get_envelope_session(agent_id)
                if env_session:
                    args = params.get("arguments", {})
                    data_read = args.pop("__data_read", []) if isinstance(args, dict) else []
                    data_write = args.pop("__data_write", []) if isinstance(args, dict) else []
                    env_result = env_session.check(
                        params.get("name", ""), args,
                        data_read=data_read if isinstance(data_read, list) else [],
                        data_write=data_write if isinstance(data_write, list) else [],
                    )
                    if env_result.should_block:
                        violation_msg = "; ".join(v.message for v in env_result.violations[:3])
                        self._write_json_response(writer, 200, {
                            "jsonrpc": "2.0", "id": msg.get("id"),
                            "error": {"code": -32600,
                                      "message": f"BLOCKED by envelope ({env_result.decision.value}): {violation_msg}"}
                        })
                        return

            # Forward to target and handle response
            resp_headers, resp_body_or_stream = await self._forward_streamable(body, headers)
            content_type = resp_headers.get("content-type", "")

            if "text/event-stream" in content_type:
                # SSE response: stream events, inspecting each one
                await self._stream_sse_response(writer, resp_body_or_stream, msg, resp_headers)
            else:
                # Single JSON response
                resp_body = resp_body_or_stream
                # Check for rug pulls in tools/list responses
                if msg.get("method") == "tools/list":
                    resp_body = self._check_rug_pull(msg, resp_body)
                # Scan response for injection
                if msg.get("method") == "tools/call" and self.scanner:
                    resp_body = self._scan_response(msg, resp_body)
                self._write_raw_response(writer, 200, content_type or "application/json", resp_body)

        except Exception as e:
            self._write_json_response(writer, 500, {
                "jsonrpc": "2.0", "id": None,
                "error": {"code": -32603, "message": str(e)}
            })
        finally:
            await writer.drain()
            writer.close()

    async def _forward_streamable(self, body: bytes, req_headers: dict) -> tuple[dict, bytes]:
        """Forward request to target, return response headers + body."""
        parsed = urlparse(self.target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"

        reader, writer = await asyncio.open_connection(host, port, ssl=use_ssl)

        path = parsed.path or "/"
        fwd_headers = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Accept: application/json, text/event-stream\r\n"
        )
        if self._mcp_session_id:
            fwd_headers += f"Mcp-Session-Id: {self._mcp_session_id}\r\n"
        fwd_headers += "Connection: close\r\n\r\n"

        writer.write(fwd_headers.encode() + body)
        await writer.drain()

        # Read response headers
        resp_headers = {}
        status_line = await reader.readline()
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            if b":" in line:
                key, val = line.decode().split(":", 1)
                resp_headers[key.strip().lower()] = val.strip()

        # Read body
        resp_body = await reader.read(2 * 1024 * 1024)  # 2MB max
        writer.close()

        # Capture Mcp-Session-Id from response
        if "mcp-session-id" in resp_headers:
            self._mcp_session_id = resp_headers["mcp-session-id"]

        return resp_headers, resp_body

    async def _stream_sse_response(self, writer: asyncio.StreamWriter,
                                   raw_body: bytes, original_msg: dict,
                                   resp_headers: dict):
        """Parse SSE events from response, inspect each, forward to client."""
        # Write SSE response headers to client
        header = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        writer.write(header)

        # Parse SSE events from the body
        for event_data in self._parse_sse_events(raw_body):
            # Try to parse as JSON-RPC for inspection
            try:
                msg = json.loads(event_data)
                # Scan tool call results for injection
                if self.scanner and original_msg.get("method") == "tools/call":
                    text = self._extract_text(msg)
                    if text:
                        matched = self.scanner.scan(text)
                        if matched:
                            self.audit.log_response_blocked(original_msg.get("id"), matched)
                            msg = {"jsonrpc": "2.0", "id": original_msg.get("id"),
                                   "error": {"code": -32600,
                                             "message": "BLOCKED: response contained prompt injection"}}
                            event_data = json.dumps(msg)
            except json.JSONDecodeError:
                pass  # Not JSON, forward as-is

            # Forward SSE event to client
            writer.write(f"data: {event_data}\n\n".encode())

        await writer.drain()

    def _parse_sse_events(self, raw: bytes) -> list[str]:
        """Extract data fields from SSE stream."""
        events = []
        for line in raw.decode(errors="replace").split("\n"):
            if line.startswith("data: "):
                events.append(line[6:].strip())
        return events

    def _check_rug_pull(self, original_msg: dict, resp_body: bytes) -> bytes:
        try:
            resp = json.loads(resp_body)
        except json.JSONDecodeError:
            return resp_body
        tools = resp.get("result", {}).get("tools") if isinstance(resp.get("result"), dict) else None
        if not isinstance(tools, list):
            return resp_body
        alerts = self.rug_pull_detector.register_tools(tools)
        if alerts:
            for a in alerts:
                self.audit.log_event("rug_pull_detected", {"tool": a.tool_name, "field": a.field_changed})
            return json.dumps({"jsonrpc": "2.0", "id": original_msg.get("id"),
                               "error": {"code": -32600,
                                          "message": f"BLOCKED: rug-pull detected in {', '.join(a.tool_name for a in alerts)}"}}).encode()
        return resp_body

    def _scan_response(self, original_msg: dict, resp_body: bytes) -> bytes:
        try:
            resp = json.loads(resp_body)
        except json.JSONDecodeError:
            return resp_body
        text = self._extract_text(resp)
        if text:
            matched = self.scanner.scan(text)
            if matched:
                self.audit.log_response_blocked(original_msg.get("id"), matched)
                return json.dumps({"jsonrpc": "2.0", "id": original_msg.get("id"),
                                   "error": {"code": -32600,
                                             "message": "BLOCKED: response contained prompt injection"}}).encode()
        return resp_body

    def _extract_text(self, msg: dict) -> str:
        result = msg.get("result")
        if not result:
            return ""
        content = result.get("content") if isinstance(result, dict) else None
        if isinstance(content, list):
            return " ".join(c.get("text", "") for c in content if isinstance(c, dict))
        return ""

    async def _read_headers(self, reader: asyncio.StreamReader) -> dict[str, str]:
        headers = {}
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            if b":" in line:
                key, val = line.decode().split(":", 1)
                headers[key.strip().lower()] = val.strip()
        return headers

    def _write_json_response(self, writer: asyncio.StreamWriter, status: int, body: dict):
        data = json.dumps(body).encode()
        self._write_raw_response(writer, status, "application/json", data)

    def _write_raw_response(self, writer: asyncio.StreamWriter, status: int, content_type: str, body: bytes):
        header = (
            f"HTTP/1.1 {status} OK\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        writer.write(header + body)

    async def _proxy_raw(self, body: bytes, headers: dict, writer: asyncio.StreamWriter):
        resp_headers, resp_body = await self._forward_streamable(body, headers)
        ct = resp_headers.get("content-type", "application/json")
        self._write_raw_response(writer, 200, ct, resp_body)


async def run_streamable_proxy(host: str, port: int, target: str,
                               policy: Policy, audit: AuditLog,
                               scanner: ResponseScanner | None = None,
                               envelope_path: str | None = None) -> None:
    """Start the Streamable HTTP proxy server."""
    proxy = StreamableHttpProxy(target, policy, audit, scanner, envelope_path)

    server = await asyncio.start_server(proxy.handle_request, host, port)
    addr = server.sockets[0].getsockname()
    sys.stderr.write(f"mcpfw: Streamable HTTP proxy on {addr[0]}:{addr[1]}\n")
    sys.stderr.write(f"mcpfw: target {target}\n")
    sys.stderr.write(f"mcpfw: supports SSE streaming + session management\n")

    async with server:
        await server.serve_forever()
