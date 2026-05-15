# Changelog

## 0.4.0 (2026-05-15)

### Temporal Preconditions

**New rule action: `requires`**
- Enforce that a prior event must have occurred within a time window before a tool call is allowed
- `requires_event` + `within`: "payment_api requires human_approval within last 30m"
- `cooldown_seconds`: "cannot delete_account within 5m of create_account"
- Glob pattern matching on event names (e.g., `auth_*` matches `auth_mfa`)
- Human-readable duration parsing: `30m`, `2h`, `300s`, `1h30m`
- Closes the biggest gap vs AgentCore Gateway's Layer 2 temporal policies

### Policy Composition

**Multiple `--policy` flags with precedence:**
- Layer policies: `--policy org.yaml --policy team.yaml --policy project.yaml`
- First = highest priority. Deny at org level cannot be overridden by team allow.
- Rules concatenated in priority order. scan_responses merged (any layer enabling wins).
- Default action from highest-priority policy.

**New bundled policies:** `org-baseline.yaml`, `team-support.yaml`

**Tests:** 89 total (21 new), all passing.

## 0.3.0 (2026-05-14)

### Rug-Pull Detection + Streamable HTTP Transport

**Rug-pull detection:**
- Caches tool descriptors on first `tools/list` response
- Alerts and blocks when descriptions or schemas change after registration
- Catches the postmark-mcp attack pattern (build trust, then modify)
- 6 new tests

**Streamable HTTP transport (`--transport streamable`):**
- Supports the MCP spec 2025-03-26 remote transport standard
- Handles both single JSON responses and SSE streaming
- Per-event inspection in SSE streams (injection scanning on each event)
- `Mcp-Session-Id` header tracking for session continuity
- Works with real MCP clients (Claude Code, Kiro, Cursor)

**Other:**
- `audit.log_event()` generic event logging method

**Tests:** 66 total (6 new), all passing.

## 0.2.0 (2026-05-14)

### HTTP Proxy Mode + Envelope Integration

**New features:**
- **HTTP proxy mode** (`--listen`/`--target`): Run mcpfw as a network reverse proxy instead of a stdio wrapper. Agents connect to mcpfw's port, mcpfw forwards to the real MCP server. Network-enforced, can't be bypassed.
- **Per-agent session state**: Each agent (identified by `X-Agent-Id` header) gets independent session tracking (rate limits, budgets, sequence detection).
- **agent-envelope integration** (`--envelope`): Session-level behavioral enforcement alongside per-call policy. Cross-action data flow tracking, workflow matching, drift scoring, kill switch.
- **Attack demo** (`demo/run_demo.sh`): Shows normal workflow passing cleanly, attack blocked by envelope, and same attack succeeding without firewall.

**Architecture:**
- Layer 3 (per-call, stateless): mcpfw policy engine evaluates each tool call
- Layer 2 (per-session, stateful): agent-envelope tracks trajectory and blocks drift
- Both layers in one network proxy. Agent can't bypass either.

**New files:**
- `mcpfw/http_proxy.py` — async HTTP reverse proxy with session state
- `demo/` — full attack demo (mock server, agent simulator, envelope, run script)

**Tests:** 60 total (5 new), all passing.

## 0.1.0 (2026-04-26)

### Initial Release

- Transparent stdio proxy for MCP servers
- YAML policy engine (allow, deny, ask, rate_limit, budget, sequence)
- Response scanning for prompt injection
- Discovery filtering (strip denied tools from tools/list)
- Session budgets and sequence detection
- Human-in-the-loop approval prompts
- JSONL audit logging
- Bundled policies: permissive, standard, paranoid
- 55 tests passing
