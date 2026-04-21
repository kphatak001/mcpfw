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

## License

MIT
