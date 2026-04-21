# How to Use mcpfw

## Quick Start

### 1. Install

```bash
# From source
git clone https://github.com/kphatak001/mcpfw
cd mcpfw
pip install -e .

# Or just run directly
python3 -m mcpfw --help
```

### 2. Wrap an MCP Server

Change one line in your MCP config. Before:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "."]
    }
  }
}
```

After:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcpfw",
      "args": ["--policy", "policies/standard.yaml", "--audit-log", "mcpfw.jsonl",
               "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
    }
  }
}
```

That's it. Your agent and MCP server don't know mcpfw is there.

### 3. Pick a Bundled Policy

| Policy | Use when |
|--------|----------|
| `permissive.yaml` | You want to audit what's happening before writing rules |
| `standard.yaml` | Day-to-day development — blocks sensitive paths, allows project writes |
| `paranoid.yaml` | Running untrusted agents or doing security-sensitive work |

Start with `permissive` to see what your agent actually does, then tighten.

## Writing Policies

Policies are YAML files with a list of rules evaluated top-to-bottom. First match wins.

```yaml
name: my-policy

rules:
  - name: block_ssh_writes
    action: deny
    tools: ["write_file", "edit_file"]
    when:
      arg_matches:
        path: ["~/.ssh/**"]
    message: "SSH key modification blocked"

  - name: allow_reads
    action: allow
    tools: ["read_file", "list_directory"]

  - name: ask_everything_else
    action: ask
    tools: ["*"]
```

### Rule Actions

**`deny`** — Block the call. Agent gets an error response. MCP server never sees it.

```yaml
- action: deny
  tools: ["write_file"]
  when:
    arg_matches:
      path: ["/etc/**"]
  message: "System file write blocked"
```

**`allow`** — Forward to MCP server transparently.

```yaml
- action: allow
  tools: ["read_file", "search_files", "list_directory"]
```

**`ask`** — Pause and prompt the human in the terminal. If no response in 2 minutes, deny.

```yaml
- action: ask
  tools: ["run_command"]
  message: "Shell command requires approval"
```

The prompt looks like:

```
============================================================
🔒 mcpfw: Tool call requires approval
   Tool: run_command
   Args: {
     "command": "git push origin main --force"
   }
============================================================
   Allow? [y/N]:
```

**`rate_limit`** — Token bucket. Deny if exceeded, otherwise fall through to next rule.

```yaml
- action: rate_limit
  tools: ["*"]
  rate: 60/minute
```

Supported rates: `N/second`, `N/minute`, `N/hour`.

### Argument Matching

Rules can inspect the actual arguments of a tool call, not just the tool name.

**Glob patterns** — match file paths, command prefixes:

```yaml
when:
  arg_matches:
    path: ["~/.ssh/**", "~/.aws/**", "**/.env*"]
    command: ["rm -rf *", "curl*|*bash*"]
```

**Substring containment** — match anywhere in the value:

```yaml
when:
  arg_contains:
    command: ["rm -rf", "DROP TABLE", "chmod 777"]
```

**Regex** — full regex power:

```yaml
when:
  arg_regex:
    command: "curl.*\\|.*(bash|sh|python)"
```

You can combine multiple match types in one `when` block — any match triggers the rule.

### Tool Name Patterns

Tool names support glob patterns:

```yaml
tools: ["write_*"]          # matches write_file, write_config, etc.
tools: ["*"]                # matches everything
tools: ["read_file"]        # exact match
tools: ["run_*", "exec_*"]  # multiple patterns
```

### Rule Evaluation Order

Rules are evaluated top-to-bottom. First match wins. Design your policies like firewall rules:

1. Explicit denies first (block dangerous stuff)
2. Explicit allows (known-safe operations)
3. Rate limits (apply to everything that passes)
4. Default ask/deny at the bottom (catch-all)

## Common Patterns

### Development Workstation

```yaml
name: dev-workstation
rules:
  # Never touch credentials
  - action: deny
    tools: ["*"]
    when:
      arg_matches:
        path: ["~/.ssh/**", "~/.aws/**", "~/.gnupg/**", "**/.env*"]
    message: "Credential path blocked"

  # Allow all reads
  - action: allow
    tools: ["read_file", "list_directory", "search_files", "get_file_info"]

  # Allow writes in project
  - action: allow
    tools: ["write_file", "edit_file", "create_file"]
    when:
      arg_matches:
        path: ["./**"]

  # Allow safe git commands
  - action: allow
    tools: ["run_command"]
    when:
      arg_matches:
        command: ["git status*", "git diff*", "git log*", "git add*", "git commit*"]

  # Ask for everything else
  - action: ask
    tools: ["*"]
```

### CI/CD Pipeline (No Human)

```yaml
name: ci-pipeline
rules:
  # Block everything dangerous
  - action: deny
    tools: ["*"]
    when:
      arg_matches:
        path: ["~/**", "/etc/**", "/root/**"]

  - action: deny
    tools: ["run_command"]
    when:
      arg_contains:
        command: ["curl", "wget", "nc", "ssh", "scp"]
    message: "Network commands blocked in CI"

  # Allow project operations
  - action: allow
    tools: ["read_file", "write_file", "list_directory", "run_command"]

  # Deny everything else (no human to ask)
  - action: deny
    tools: ["*"]
    message: "Not allowed in CI mode"
```

### Wrapping Multiple MCP Servers

Each server gets its own policy:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcpfw",
      "args": ["-p", "policies/standard.yaml", "-l", "audit.jsonl",
               "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
    },
    "github": {
      "command": "mcpfw",
      "args": ["-p", "policies/paranoid.yaml", "-l", "audit.jsonl",
               "--", "npx", "-y", "@modelcontextprotocol/server-github"]
    },
    "postgres": {
      "command": "mcpfw",
      "args": ["-p", "policies/db-readonly.yaml", "-l", "audit.jsonl",
               "--", "npx", "-y", "@modelcontextprotocol/server-postgres"]
    }
  }
}
```

## Audit Log

Every tool call is logged as JSON-lines, regardless of decision:

```bash
# Watch decisions in real-time
tail -f mcpfw.jsonl | python3 -m json.tool

# Count decisions by type
cat mcpfw.jsonl | python3 -c "
import json, sys, collections
c = collections.Counter(json.loads(l)['decision'] for l in sys.stdin if 'decision' in l)
for k,v in c.most_common(): print(f'{k}: {v}')
"

# Find all denied calls
cat mcpfw.jsonl | python3 -c "
import json, sys
for l in sys.stdin:
    e = json.loads(l)
    if e.get('decision') == 'deny':
        print(f\"{e['tool']} → {e['message']}\")
"
```

Each log entry contains:

```json
{
  "event": "tool_call",
  "tool": "write_file",
  "arguments": {"path": "~/.ssh/key", "content": "..."},
  "decision": "deny",
  "rule": "block_sensitive_paths",
  "message": "Write to sensitive path blocked",
  "timestamp": 1713700000,
  "iso_time": "2026-04-21T16:00:00Z"
}
```

## Dry Run Mode

See what mcpfw *would* do without actually blocking anything:

```bash
mcpfw --policy policies/paranoid.yaml --dry-run --audit-log audit.jsonl -- <mcp-command>
```

All deny/ask rules are converted to allow, but decisions are still logged. Use this to:
- Audit an existing agent's behavior before enforcing policies
- Test a new policy without breaking your workflow
- Generate data for writing better rules

## Testing Your Policies

Use the included mock server and test harness:

```bash
# Run test calls through your policy
python3 tests/send_calls.py | python3 -m mcpfw -p policies/standard.yaml -l /dev/stderr -- python3 tests/mock_server.py

# Expected output:
# Call 1 (read_file)           → ALLOW
# Call 2 (write ./src/main.py) → ALLOW
# Call 3 (write ~/.ssh/...)    → DENY
# Call 4 (write .env)          → DENY
# Call 5 (curl|bash)           → DENY
# Call 6 (write /tmp/...)      → ASK
```

## Config Locations

| Client | Config file |
|--------|------------|
| Claude Code | `.claude/settings.json` → `mcpServers` |
| Kiro CLI | `~/.kiro/settings/mcp.json` |
| Kiro IDE | `.kiro/settings/mcp.json` in project |
| Cline | `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |

## Relationship to agentspec

[agentspec](https://github.com/kphatak001/agentspec) does static analysis — it reads your agent config and tells you what's dangerous. mcpfw does runtime enforcement — it sits in the data path and blocks dangerous calls.

Use them together:
1. `agentspec model agent.yaml` → find risks
2. Write mcpfw policies to mitigate those risks
3. `mcpfw --policy ...` → enforce at runtime
4. Review audit logs → refine policies
