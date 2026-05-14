# Changelog

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
