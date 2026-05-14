#!/bin/bash
# Start the mcpfw demo environment for use with Kiro/Claude Code/Cursor.
#
# This starts:
# 1. A mock MCP server (simulates customer DB + email tools) on :9000
# 2. mcpfw proxy on :8443 with policy + envelope enforcement
#
# Then configure your MCP client to connect to http://127.0.0.1:8443
# instead of the real server. Every tool call goes through the firewall.
#
# Usage:
#   bash demo/start_firewall.sh        # start in background
#   bash demo/start_firewall.sh stop   # stop both processes

set -e
cd "$(dirname "$0")"

DEMO_DIR="$(pwd)"
MCPFW_DIR="$(dirname "$DEMO_DIR")"
ENVELOPE_DIR="$HOME/projects/agent-envelope"
PID_FILE="$DEMO_DIR/.demo_pids"

if [ "$1" = "stop" ]; then
    if [ -f "$PID_FILE" ]; then
        while read pid; do
            kill "$pid" 2>/dev/null || true
        done < "$PID_FILE"
        rm "$PID_FILE"
        echo "🛑 Demo stopped."
    else
        echo "No running demo found."
    fi
    exit 0
fi

# Kill any existing demo
if [ -f "$PID_FILE" ]; then
    bash "$0" stop
fi

echo "🚀 Starting Agent Firewall demo environment..."
echo ""

# Start mock MCP server
python3 "$DEMO_DIR/mock_server.py" &
SERVER_PID=$!
echo "$SERVER_PID" > "$PID_FILE"
sleep 0.5

# Start mcpfw proxy
PYTHONPATH="$MCPFW_DIR:$ENVELOPE_DIR:$PYTHONPATH" python3 -m mcpfw.cli \
    --listen 127.0.0.1:8443 \
    --target http://127.0.0.1:9000 \
    --transport streamable \
    --policy "$DEMO_DIR/policy.yaml" \
    --envelope "$DEMO_DIR/envelope.yaml" \
    --audit-log "$DEMO_DIR/audit.jsonl" &
PROXY_PID=$!
echo "$PROXY_PID" >> "$PID_FILE"
sleep 1

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Agent Firewall running!                                    ║"
echo "║                                                             ║"
echo "║  Proxy:  http://127.0.0.1:8443                              ║"
echo "║  Server: http://127.0.0.1:9000 (mock, direct access)       ║"
echo "║  Audit:  $DEMO_DIR/audit.jsonl                              ║"
echo "║                                                             ║"
echo "║  To stop: bash demo/start_firewall.sh stop                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Configure your MCP client to use http://127.0.0.1:8443"
echo ""
echo "Try these tool calls:"
echo "  ✅ search_kb({query: 'password reset'})     → allowed"
echo "  ✅ read_customer({id: 'cust_001'})           → allowed"
echo "  ✅ send_reply({message: 'Hi Alice'})         → allowed"
echo "  🛑 read_customer x3 + send_email(external)  → BLOCKED by envelope"
echo ""
echo "Logs streaming below (Ctrl+C to stop):"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Tail the audit log
tail -f "$DEMO_DIR/audit.jsonl" 2>/dev/null || wait
