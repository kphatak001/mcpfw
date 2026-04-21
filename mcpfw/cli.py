"""CLI entry point: mcpfw --policy policy.yaml -- npx server-filesystem /path."""

from __future__ import annotations
import argparse
import asyncio
import sys

from .policy import load_policy
from .audit import AuditLog
from .proxy import run_proxy


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="mcpfw",
        description="MCP Firewall — transparent policy enforcement proxy for MCP servers",
        usage="mcpfw [options] -- <mcp-server-command> [args...]",
    )
    ap.add_argument("--policy", "-p", required=True, help="Path to policy YAML file")
    ap.add_argument("--audit-log", "-l", help="Path to audit log file (JSON-lines)")
    ap.add_argument("--dry-run", action="store_true", help="Log decisions but don't enforce (allow everything)")
    ap.add_argument("command", nargs=argparse.REMAINDER, help="MCP server command (after --)")

    args = ap.parse_args(argv)

    # Strip leading -- from command
    cmd = args.command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        ap.error("No MCP server command provided. Usage: mcpfw --policy p.yaml -- <command>")

    policy = load_policy(args.policy)
    audit = AuditLog(args.audit_log)

    if args.dry_run:
        # In dry-run, override all deny/ask to allow but still log
        for rule in policy.rules:
            if rule.action in ("deny", "ask"):
                rule.action = "allow"

    sys.stderr.write(f"mcpfw: loaded policy '{policy.name}' ({len(policy.rules)} rules)\n")
    sys.stderr.write(f"mcpfw: proxying → {' '.join(cmd)}\n")

    try:
        rc = asyncio.run(run_proxy(cmd, policy, audit))
    except KeyboardInterrupt:
        rc = 0
    finally:
        audit.close()

    return rc


if __name__ == "__main__":
    sys.exit(main())
