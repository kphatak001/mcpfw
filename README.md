# mcpfw

Transparent policy enforcement proxy for MCP servers. Sits between your AI agent and MCP servers, inspecting every tool call against YAML policies before it reaches the server.

```
Agent ──stdin──▶ mcpfw ──stdin──▶ MCP Server
Agent ◀─stdout── mcpfw ◀─stdout── MCP Server
                   │
              Policy Engine
              Audit Log
```

## Install

```bash
pip install mcpfw
```

## Usage

Wrap any MCP server — one config line change:

```diff
 {
   "mcpServers": {
     "filesystem": {
-      "command": "npx",
-      "args": ["-y", "@modelcontextprotocol/server-filesystem", "."]
+      "command": "mcpfw",
+      "args": ["--policy", "policy.yaml", "--",
+               "npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
     }
   }
 }
```

Works with Claude Code, Kiro, Cline, or any MCP client. Zero client changes.

## Policy Files

```yaml
name: standard

# Scan MCP server responses for prompt injection
scan_responses:
  enabled: true

rules:
  # Session-wide call budget (prevents resource amplification)
  - name: session_budget
    action: budget
    max_calls: 200
    max_per_tool: 50
    message: "Session call budget exceeded"

  # Detect exfiltration sequences (read secrets → network call)
  - name: exfil_env_curl
    action: sequence
    pattern: ["read_file:*.env*", "run_command:*curl*"]
    message: "Blocked: read sensitive file then network call"

  # Block writes to sensitive paths
  - action: deny
    tools: ["write_file", "edit_file"]
    when:
      arg_matches:
        path: ["~/.ssh/**", "~/.bashrc", "/etc/**", "**/.env*"]
    message: "Write to sensitive path blocked"

  # Allow all reads
  - action: allow
    tools: ["read_file", "list_directory", "search_files"]

  # Allow writes within project
  - action: allow
    tools: ["write_file", "edit_file"]
    when:
      arg_matches:
        path: ["./src/**", "./tests/**"]

  # Rate limit everything
  - action: rate_limit
    tools: ["*"]
    rate: 60/minute

  # Ask human for anything else
  - action: ask
    tools: ["*"]
    message: "Requires approval"
```

## Rule Actions

| Action | Behavior |
|--------|----------|
| `allow` | Forward to MCP server |
| `deny` | Return error to agent, never reaches server |
| `ask` | Pause, prompt human in terminal, wait for y/n |
| `rate_limit` | Token bucket — deny if exceeded, otherwise fall through |
| `budget` | Session-wide call caps — total and per-tool |
| `sequence` | Detect suspicious multi-call patterns across session history |

## Default Action

By default, mcpfw allows tool calls that don't match any rule. Set `default_action` to change this:

```yaml
name: locked-down
default_action: deny   # or "ask"

rules:
  - action: allow
    tools: ["read_file", "list_directory"]
  # everything else is denied — fail closed
```

| Value | Behavior |
|-------|----------|
| `allow` | (default) Unmatched calls pass through |
| `deny` | Unmatched calls are blocked |
| `ask` | Unmatched calls require human approval |

The bundled `paranoid.yaml` uses `default_action: deny`.

## Argument Matching

```yaml
when:
  # Glob patterns on argument values
  arg_matches:
    path: ["~/.ssh/**", "/etc/**"]

  # Substring containment
  arg_contains:
    command: ["rm -rf", "curl | bash"]

  # Regex
  arg_regex:
    command: "curl.*\\|.*bash"
```

## Response Scanning

MCP server responses are scanned for prompt injection before reaching the agent. A compromised or malicious MCP server can embed instructions like "ignore previous instructions" in tool output — mcpfw catches these and returns a sanitized error instead.

Enable in your policy:

```yaml
scan_responses:
  enabled: true
  extra_patterns:          # optional — add your own regex
    - "CUSTOM_MARKER"
```

Default patterns detect common injection vectors: `ignore previous instructions`, `<system>` tags, `[INST]` markers, and similar.

Based on: [VIGIL: Verify-Before-Commit](https://arxiv.org/abs/2604.xxxxx), [MCP-ITP: Implicit Tool Poisoning](https://arxiv.org/abs/2604.xxxxx)

## Discovery Filtering

When an agent sends `tools/list`, mcpfw intercepts the response and strips out any tool that the policy would deny. The agent never sees denied tools — fewer tokens in context, no hallucinated calls to blocked tools, no wasted round-trips.

This happens automatically based on your existing deny rules. A tool is hidden when `evaluate` with empty arguments yields `deny`. Tools with argument-conditional deny rules (e.g. "deny write_file only to ~/.ssh") are **not** hidden — they might be allowed with different arguments.

```
MCP Server responds: 27 tools
                        │
                   mcpfw filters
                        │
Agent receives:    10 tools (denied tools invisible)
```

Filtered tools are logged to the audit trail:

```json
{"event":"discovery_filtered","hidden_tools":["issue_refund","cancel_subscription","deactivate_customer"],"count":3,"message":"Stripped 3 tool(s) from discovery response"}
```

No policy changes needed — if you already have deny rules, discovery filtering works out of the box.

## Session Budgets

Cap total tool calls per session and per-tool to prevent resource amplification attacks where a malicious MCP server triggers recursive tool chains that inflate costs.

```yaml
- name: session_budget
  action: budget
  max_calls: 200       # total calls across all tools
  max_per_tool: 50     # per individual tool
  message: "Session budget exceeded"
```

Per-tool limits only block the specific tool that exceeded its budget — other tools remain available.

Based on: [Beyond Max Tokens: Stealthy Resource Amplification via Tool Calling Chains](https://arxiv.org/abs/2604.xxxxx)

## Sequence Detection

Detect multi-step attack patterns across session history. Catches exfiltration sequences like "read .env file, then curl to external server."

```yaml
- name: exfil_env_curl
  action: sequence
  pattern: ["read_file:*.env*", "run_command:*curl*"]
  message: "Blocked: read sensitive file then network call"
```

Steps use `tool_name:arg_glob` syntax. The engine walks session history backwards to find preceding steps. Only fires when all steps match in order.

Based on: [Taming Privilege Escalation in LLM Agent Systems](https://arxiv.org/abs/2604.xxxxx), [AgentGuardian: Learning Access Control Policies](https://arxiv.org/abs/2604.xxxxx)

## Bundled Policies

| Policy | Description |
|--------|-------------|
| `permissive.yaml` | Log everything, block nothing |
| `standard.yaml` | Block sensitive paths, allow reads, ask for unscoped writes, session budgets, exfiltration detection, response scanning |
| `paranoid.yaml` | Ask for everything except reads, tight budgets, aggressive sequence detection, response scanning |

## Demo

Try it without any external MCP server — a mock server and test calls are included.

**Quick (single terminal):**

```bash
python3 tests/send_calls.py | mcpfw -p policies/standard.yaml -- python3 tests/mock_server.py
```

**Interactive (two terminals):**

```bash
# Terminal 1 — start mcpfw with mock server
mkfifo /tmp/mcpfw-demo
mcpfw -p policies/standard.yaml -l audit.jsonl -- python3 tests/mock_server.py < /tmp/mcpfw-demo

# Terminal 2 — send calls one at a time, press Enter between each
python3 tests/interactive_demo.py > /tmp/mcpfw-demo
```

Sends 6 tool calls that exercise every decision type: allow, deny, and the interactive `🔒 Allow? [y/N]` prompt.

## CLI Options

```
mcpfw --policy policy.yaml [options] -- <mcp-server-command>

Options:
  --policy, -p     Path to policy YAML (required)
  --audit-log, -l  Path to JSON-lines audit log
  --dry-run        Log decisions but allow everything
```

## Audit Log

Every tool call is logged as JSON-lines:

```json
{"event":"tool_call","tool":"write_file","arguments":{"path":"~/.ssh/key"},"decision":"deny","rule":"block_sensitive","message":"Write to sensitive path blocked","timestamp":1713700000}
```

Blocked responses are also logged:

```json
{"event":"response_blocked","request_id":3,"pattern":"(?i)ignore\\s+(all\\s+)?previous\\s+instructions","message":"Server response contained suspected prompt injection","timestamp":1713700001}
```

## Pair with agentspec

[agentspec](https://github.com/kphatak001/agentspec) scans your agent config and generates mcpfw policies automatically:

```bash
# Scan agent config → generate enforcement policy
agentspec model agent.yaml --emit-policy -o policy.yaml

# Enforce at runtime
mcpfw --policy policy.yaml -- npx @modelcontextprotocol/server-filesystem .
```

## Pair with findingfold

[findingfold](https://github.com/kphatak001/findingfold) is an MCP server that collapses security findings by root cause. Wrap it with mcpfw to enforce policies on which findings data the agent can access:

```bash
mcpfw --policy policy.yaml -- findingfold-mcp
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
