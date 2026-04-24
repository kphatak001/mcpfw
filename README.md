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
rules:
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

## Bundled Policies

| Policy | Description |
|--------|-------------|
| `permissive.yaml` | Log everything, block nothing |
| `standard.yaml` | Block sensitive paths, allow reads, ask for unscoped writes |
| `paranoid.yaml` | Ask for everything except reads |

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
