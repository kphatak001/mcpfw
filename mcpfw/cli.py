"""CLI entry point: mcpfw --policy policy.yaml -- npx server-filesystem /path.

HTTP proxy mode: mcpfw --listen :8443 --target https://mcp-server:3000 --policy policy.yaml
"""

from __future__ import annotations
import argparse
import asyncio
import sys

from .policy import load_policy
from .audit import AuditLog
from .proxy import run_proxy
from .http_proxy import run_http_proxy
from .streamable_proxy import run_streamable_proxy
from .rules.response_scanner import ResponseScanner


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="mcpfw",
        description="MCP Firewall — transparent policy enforcement proxy for MCP servers",
        usage="mcpfw [options] -- <mcp-server-command>\n       mcpfw --listen :8443 --target https://server:3000 --policy policy.yaml",
    )
    ap.add_argument("--policy", "-p", required=True, help="Path to policy YAML file")
    ap.add_argument("--audit-log", "-l", help="Path to audit log file (JSON-lines)")
    ap.add_argument("--dry-run", action="store_true", help="Log decisions but don't enforce")
    ap.add_argument("--listen", help="HTTP proxy mode: bind address (e.g. :8443, 127.0.0.1:8443)")
    ap.add_argument("--target", help="HTTP proxy mode: upstream MCP server URL")
    ap.add_argument("--transport", default="http", choices=["http", "streamable"],
                    help="Transport mode: http (simple POST) or streamable (MCP Streamable HTTP with SSE)")
    ap.add_argument("--envelope", "-e", help="Path to agent-envelope YAML (enables session-level enforcement)")
    ap.add_argument("command", nargs=argparse.REMAINDER, help="MCP server command (stdio mode)")

    args = ap.parse_args(argv)

    policy = load_policy(args.policy)
    audit = AuditLog(args.audit_log)
    scanner = _build_scanner(policy)

    if args.dry_run:
        for rule in policy.rules:
            if rule.action in ("deny", "ask"):
                rule.action = "allow"

    # Decide mode: HTTP proxy or stdio proxy
    if args.listen:
        if not args.target:
            ap.error("--target is required when using --listen (HTTP proxy mode)")
        return _run_http_mode(args.listen, args.target, policy, audit, scanner, args.envelope, args.transport)
    else:
        cmd = args.command
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        if not cmd:
            ap.error("Provide either --listen/--target (HTTP mode) or a command after -- (stdio mode)")
        return _run_stdio_mode(cmd, policy, audit, scanner)


def _run_http_mode(listen: str, target: str, policy, audit, scanner, envelope_path: str | None, transport: str) -> int:
    host, port = _parse_listen(listen)
    sys.stderr.write(f"mcpfw: starting {transport} proxy mode\n")
    try:
        if transport == "streamable":
            asyncio.run(run_streamable_proxy(host, port, target, policy, audit, scanner, envelope_path))
        else:
            asyncio.run(run_http_proxy(host, port, target, policy, audit, scanner, envelope_path))
    except KeyboardInterrupt:
        pass
    finally:
        audit.close()
    return 0


def _run_stdio_mode(cmd, policy, audit, scanner) -> int:
    sys.stderr.write(f"mcpfw: loaded policy '{policy.name}' ({len(policy.rules)} rules)\n")
    if scanner:
        sys.stderr.write(f"mcpfw: response scanning enabled\n")
    sys.stderr.write(f"mcpfw: proxying → {' '.join(cmd)}\n")
    try:
        rc = asyncio.run(run_proxy(cmd, policy, audit, scanner))
    except KeyboardInterrupt:
        rc = 0
    finally:
        audit.close()
    return rc


def _parse_listen(listen: str) -> tuple[str, int]:
    """Parse listen address like ':8443', '127.0.0.1:8443', '8443'."""
    if ":" in listen:
        parts = listen.rsplit(":", 1)
        host = parts[0] or "0.0.0.0"
        port = int(parts[1])
    else:
        host = "0.0.0.0"
        port = int(listen)
    return host, port


def _build_scanner(policy) -> ResponseScanner | None:
    """If policy has scan_responses config, build a scanner."""
    if not hasattr(policy, "scan_responses") or not policy.scan_responses:
        return None
    extra = policy.scan_responses.get("extra_patterns", [])
    return ResponseScanner.from_config(extra)


if __name__ == "__main__":
    sys.exit(main())
