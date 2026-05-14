"""HTTP reverse proxy mode — network-enforced MCP policy.

Runs as an HTTP server that accepts MCP-over-HTTP requests (JSON-RPC POST),
applies the same policy engine as stdio mode, and proxies to a remote MCP server.

Usage:
    mcpfw --listen :8443 --target https://mcp-server:3000 --policy policy.yaml
"""

from __future__ import annotations
import asyncio
import json
import sys
from http import HTTPStatus
from urllib.parse import urlparse

from .policy import Policy, Decision
from .audit import AuditLog
from .session import Session
from .rules.response_scanner import ResponseScanner


class HttpProxy:
    def __init__(self, target: str, policy: Policy, audit: AuditLog,
                 scanner: ResponseScanner | None = None):
        self.target = target.rstrip("/")
        self.policy = policy
        self.audit = audit
        self.scanner = scanner
        self.sessions: dict[str, Session] = {}  # keyed by agent identity

    def _get_session(self, agent_id: str) -> Session:
        if agent_id not in self.sessions:
            self.sessions[agent_id] = Session()
        return self.sessions[agent_id]

    async def handle_request(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter):
        """Handle one HTTP request."""
        try:
            request_line = await reader.readline()
            if not request_line:
                writer.close()
                return

            method, path, _ = request_line.decode().strip().split(" ", 2)
            headers = await self._read_headers(reader)
            content_length = int(headers.get("content-length", "0"))
            body = await reader.readexactly(content_length) if content_length else b""

            # Extract agent identity from header (or use IP as fallback)
            agent_id = headers.get("x-agent-id", headers.get("authorization", "anonymous"))
            session = self._get_session(agent_id)

            # Parse JSON-RPC body
            response_body = await self._process_request(body, session, agent_id)

            # Send response
            self._write_response(writer, 200, response_body)

        except Exception as e:
            error_body = json.dumps({"jsonrpc": "2.0", "id": None,
                                     "error": {"code": -32603, "message": str(e)}}).encode()
            self._write_response(writer, 500, error_body)
        finally:
            await writer.drain()
            writer.close()

    async def _process_request(self, body: bytes, session: Session, agent_id: str) -> bytes:
        """Evaluate policy, proxy if allowed, return response."""
        try:
            msg = json.loads(body)
        except json.JSONDecodeError:
            # Not JSON, proxy as-is
            return await self._forward(body)

        if msg.get("method") == "tools/call":
            params = msg.get("params", {})
            decision = self.policy.evaluate(params, session)
            session.record_call(params, decision)
            self.audit.log_call(msg, decision)

            if decision.action == "deny":
                return json.dumps({
                    "jsonrpc": "2.0",
                    "id": msg.get("id"),
                    "error": {"code": -32600,
                              "message": f"BLOCKED by mcpfw: {decision.message}"}
                }).encode()

        elif msg.get("method") == "tools/list":
            # Forward, then filter response
            resp_bytes = await self._forward(body)
            return self._filter_discovery(msg, resp_bytes)

        # Forward to target
        resp_bytes = await self._forward(body)

        # Scan response if this was a tool call
        if msg.get("method") == "tools/call" and self.scanner:
            resp_bytes = self._scan_response(msg, resp_bytes)

        return resp_bytes

    async def _forward(self, body: bytes) -> bytes:
        """Forward request to target MCP server via HTTP POST."""
        parsed = urlparse(self.target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"

        try:
            reader, writer = await asyncio.open_connection(host, port, ssl=use_ssl)
        except Exception as e:
            return json.dumps({"jsonrpc": "2.0", "id": None,
                               "error": {"code": -32603, "message": f"Target unreachable: {e}"}}).encode()

        # Build HTTP request to target
        path = parsed.path or "/"
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + body

        writer.write(request)
        await writer.drain()

        # Read response
        response = await reader.read(1024 * 1024)  # 1MB max
        writer.close()

        # Extract body from HTTP response
        if b"\r\n\r\n" in response:
            _, resp_body = response.split(b"\r\n\r\n", 1)
            return resp_body
        return response

    def _filter_discovery(self, original_msg: dict, resp_bytes: bytes) -> bytes:
        """Strip denied tools from tools/list response."""
        try:
            resp = json.loads(resp_bytes)
        except json.JSONDecodeError:
            return resp_bytes

        tools = resp.get("result", {}).get("tools") if isinstance(resp.get("result"), dict) else None
        if not isinstance(tools, list):
            return resp_bytes

        visible, hidden = self.policy.filter_tools(tools)
        if hidden:
            resp["result"]["tools"] = visible
            self.audit.log_discovery_filtered(hidden)
        return json.dumps(resp).encode()

    def _scan_response(self, original_msg: dict, resp_bytes: bytes) -> bytes:
        """Scan response for prompt injection."""
        try:
            resp = json.loads(resp_bytes)
        except json.JSONDecodeError:
            return resp_bytes

        text = self._extract_text(resp)
        if not text:
            return resp_bytes

        matched = self.scanner.scan(text)
        if matched:
            self.audit.log_response_blocked(original_msg.get("id"), matched)
            return json.dumps({
                "jsonrpc": "2.0",
                "id": original_msg.get("id"),
                "error": {"code": -32600,
                          "message": "BLOCKED by mcpfw: response contained suspected prompt injection"}
            }).encode()

        return resp_bytes

    def _extract_text(self, msg: dict) -> str:
        result = msg.get("result")
        if not result:
            return ""
        content = result.get("content") if isinstance(result, dict) else None
        if isinstance(content, list):
            return " ".join(c.get("text", "") for c in content if isinstance(c, dict))
        if isinstance(result, dict) and "text" in result:
            return str(result["text"])
        return json.dumps(result) if result else ""

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

    def _write_response(self, writer: asyncio.StreamWriter, status: int, body: bytes):
        status_text = HTTPStatus(status).phrase
        header = (
            f"HTTP/1.1 {status} {status_text}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        writer.write(header + body)


async def run_http_proxy(host: str, port: int, target: str,
                         policy: Policy, audit: AuditLog,
                         scanner: ResponseScanner | None = None) -> None:
    """Start the HTTP proxy server."""
    proxy = HttpProxy(target, policy, audit, scanner)

    server = await asyncio.start_server(proxy.handle_request, host, port)
    addr = server.sockets[0].getsockname()
    sys.stderr.write(f"mcpfw: HTTP proxy listening on {addr[0]}:{addr[1]}\n")
    sys.stderr.write(f"mcpfw: forwarding to {target}\n")
    sys.stderr.write(f"mcpfw: policy '{policy.name}' ({len(policy.rules)} rules)\n")
    if scanner:
        sys.stderr.write(f"mcpfw: response scanning enabled\n")

    async with server:
        await server.serve_forever()
