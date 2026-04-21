#!/usr/bin/env python3
"""Fake MCP server that echoes tool calls. For testing mcpfw."""

import json
import sys

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        continue

    if msg.get("method") == "initialize":
        resp = {"jsonrpc": "2.0", "id": msg["id"], "result": {"capabilities": {"tools": {}}}}
    elif msg.get("method") == "tools/list":
        resp = {"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": [
            {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
            {"name": "write_file", "description": "Write a file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}}},
            {"name": "run_command", "description": "Run a shell command", "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}}},
        ]}}
    elif msg.get("method") == "tools/call":
        name = msg["params"]["name"]
        args = msg["params"].get("arguments", {})
        resp = {"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [
            {"type": "text", "text": f"[mock] {name} executed with {json.dumps(args)}"}
        ]}}
    else:
        resp = {"jsonrpc": "2.0", "id": msg.get("id"), "result": {}}

    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
