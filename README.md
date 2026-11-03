# Sentinel MCP Server — by Aridon

An MCP (Model Context Protocol) server that puts **Sentinel**, Aridon's
pre-execution authorization layer for AI agents, in front of any MCP client.
Before an agent acts, Sentinel evaluates the proposed action and returns a
verdict — **allow**, **hold** (a human must approve first), or **deny** — and
records the decision in a SHA-256 hash-chained audit log.

> **Honest stage — read this first.** Sentinel is a **development-stage
> technical preview**. It has been validated in internal synthetic testing
> only (September 2026 harness: 18/18 scenarios passed, 13/13 hostile actions
> held pre-execution, 0 false positives). It has **no customers and no
> revenue**, has **not** had an independent penetration test, and carries **no
> SOC 2 / ISO / FedRAMP certification**. The evaluation is heuristic, not a
> guarantee of safety. This package is a small, working slice of Sentinel,
> published so agents and developers can try the evaluation model — it is
> **not the full Sentinel product** (no hosted policy store, no tenant
> management, no approval-workflow UI, no persistent audit storage).

## Tools

| Tool | What it does |
| --- | --- |
| `sentinel_evaluate_action` | Evaluate a proposed agent action **before execution**. Inputs: the action description, optional `requestedActions` (tool calls the agent wants to run, e.g. `["send email"]`, `["payment"]`), optional authorization `context`, optional conversation `history`. Returns the verdict (`allow` / `hold` / `deny`), risk score (0–100), disposition, the signals that fired with reasons, the action-gate decision, and the audit entry hash for the decision. |
| `sentinel_explain_policy` | Explains the scoring bands, the independent action gate for consequential tool calls, the trajectory/authorization adjustments, and the signal categories and weights Sentinel uses. |
| `sentinel_audit_status` | Reports the audit log state for this server process: entry count, genesis and tip hashes, and a full SHA-256 chain re-verification (`chainValid`). |

### How the verdict is decided

Sentinel scans the action text, prior turns, and requested tool calls with
weighted heuristic rules (credential theft, malware, data exfiltration,
instruction override / prompt injection, approval evasion, mass resource
provisioning, and others) and sums a 0–100 risk score:

- **0–24** allow · **25–49** allow with restrictions · **50–74** hold for
  human review · **75–100** deny

Independently of the score, an **action gate** covers consequential tool
calls (sending email, payments and transfers, shell/command execution,
database writes/deletes, credential or secret access, network requests, file
deletion): those require human approval even when the content looks benign,
and are denied outright when risk is elevated. Risk also accumulates across
conversation turns, and a clearly authorized defensive context (your own
systems, a lab, blue-team work) lowers the score — without disabling checks —
unless the action text itself carries clearly harmful language.

The evaluation and audit code in this package is the real Sentinel logic,
ported from Aridon's codebase (`lib/sentinel-grid.ts` and
`lib/sentinelAudit.ts` in the Aridon app repository).

### Audit log

Every `sentinel_evaluate_action` call appends a decision entry to a SHA-256
hash-chained log: each entry commits to the previous entry's hash, so any
edit, insertion, or deletion in the history breaks verification. In this
package the log is **process-local (in memory)** and resets when the server
restarts; the full product persists entries. `sentinel_audit_status`
re-verifies the whole chain on demand.

## Install and run

Requires Node.js 18+.

Run it directly with npx:

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "npx",
      "args": ["-y", "@aridon/sentinel-mcp"]
    }
  }
}
```

That configuration works in MCP clients that read `mcpServers` config
(e.g. Claude Desktop, Cursor, and similar). The server speaks MCP over
stdio; it needs no API keys, accounts, or network access.

Or install it:

```bash
npm install -g @aridon/sentinel-mcp
sentinel-mcp
```

## Build and test from source

```bash
npm install
npm run build   # tsc -> dist/
npm run smoke   # starts the server over stdio and calls every tool
```

## Repository and registry

- Source (Aridon app monorepo): https://github.com/jimrusk/aridon-app
- MCP Registry name: `io.github.jimrusk/sentinel-mcp` (see `server.json`)
- Product page: https://aridon-v02.vercel.app/sentinel

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Aridon (Triple R
Restoration, LLC dba Aridon).
