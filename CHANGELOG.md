# Changelog

## 0.1.0 — 2026-04-26

Initial public release.

- **Policy engine** — YAML-based rules with allow, deny, ask, rate_limit actions
- **Argument matching** — glob, substring, and regex matching on tool call arguments
- **Response scanning** — detect prompt injection in MCP server responses before they reach the agent
- **Session budgets** — cap total and per-tool calls to prevent resource amplification
- **Sequence detection** — catch multi-step attack patterns (e.g. read .env → curl)
- **Discovery filtering** — strip denied tools from `tools/list` so agents never see them
- **Default action** — `allow`, `deny`, or `ask` for unmatched calls (fail-closed support)
- **Audit logging** — JSON-lines log of every decision
- **Bundled policies** — permissive, standard, and paranoid presets
- **CLI** — `mcpfw --policy policy.yaml -- <server-command>`
