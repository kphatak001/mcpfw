#!/bin/bash
# Demo: Agent Firewall catches multi-step exfiltration
#
# Shows:
# 1. Normal agent workflow passes cleanly
# 2. Attack agent (prompt-injected) gets KILLED at the exfiltration step
# 3. Per-call policy allows every individual action — only the envelope catches it

set -e
cd "$(dirname "$0")"

DEMO_DIR="$(pwd)"
MCPFW_DIR="$(dirname "$DEMO_DIR")"
ENVELOPE_DIR="$HOME/projects/agent-envelope"

# Kill any existing processes on our ports
lsof -ti :9000 2>/dev/null | xargs kill 2>/dev/null || true
lsof -ti :8443 2>/dev/null | xargs kill 2>/dev/null || true
sleep 0.3

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          AGENT FIREWALL DEMO: Exfiltration Detection        ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Layer 3 (per-call): policies allow everything              ║"
echo "║  Layer 2 (session):  envelope blocks data exfiltration      ║"
echo "║                                                             ║"
echo "║  The attack: read customer DB → format → email externally   ║"
echo "║  Each step is individually allowed. The trajectory is not.  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Start mock MCP server
echo "Starting mock MCP server on :9000..."
python3 "$DEMO_DIR/mock_server.py" &
SERVER_PID=$!
sleep 0.5

# Start mcpfw in HTTP proxy mode with envelope
echo "Starting mcpfw proxy on :8443 (policy + envelope)..."
PYTHONPATH="$MCPFW_DIR:$ENVELOPE_DIR:$PYTHONPATH" python3 -m mcpfw.cli \
    --listen :8443 \
    --target http://127.0.0.1:9000 \
    --policy "$DEMO_DIR/policy.yaml" \
    --envelope "$DEMO_DIR/envelope.yaml" \
    --audit-log "$DEMO_DIR/audit.jsonl" &
PROXY_PID=$!
sleep 1

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Run agent scenarios
python3 "$DEMO_DIR/agent.py" http://127.0.0.1:8443

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Now run WITHOUT the firewall (direct to server) to show the difference
echo "🔓 Now running attack DIRECTLY against server (no firewall)..."
python3 -c "
import sys; sys.path.insert(0, '$DEMO_DIR')
from agent import attack_workflow
attack_workflow('http://127.0.0.1:9000')
"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Temporal preconditions demo (policy-only, no envelope)
echo "Stopping proxy for temporal demo..."
kill $PROXY_PID 2>/dev/null || true
sleep 0.5

echo "Restarting mcpfw with temporal policy (no envelope)..."
PYTHONPATH="$MCPFW_DIR:$ENVELOPE_DIR:$PYTHONPATH" python3 -m mcpfw.cli \
    --listen :8443 \
    --target http://127.0.0.1:9000 \
    --policy "$MCPFW_DIR/policies/temporal.yaml" \
    --audit-log "$DEMO_DIR/audit.jsonl" &
PROXY_PID=$!
sleep 1

python3 "$DEMO_DIR/agent.py" http://127.0.0.1:8443 --temporal

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📋 Audit log: $DEMO_DIR/audit.jsonl"
echo ""

# Cleanup
kill $PROXY_PID 2>/dev/null || true
kill $SERVER_PID 2>/dev/null || true
