# Sentinel MCP Server, by Aridon

**Sentinel is the action-control platform for AI agents.** This MCP (Model
Context Protocol) server puts Sentinel in front of any MCP client. Before an
agent acts, Sentinel evaluates the proposed action and returns a verdict:
**allow**, **hold** (a human must approve first), or **deny**. Every decision
is recorded in a SHA-256 hash-chained audit log.

- **Live demo:** https://aridon-v02.vercel.app/sentinel-demo
- **Paper:** Sentinel and NetGuard design paper, Zenodo,
  https://doi.org/10.5281/zenodo.23920785
- **npm:** `@aridon/sentinel-mcp`

> **Results and stage, stated plainly.** In our internal test harness
> (September 2026, internal synthetic testing): **18/18 scenarios passed, 13
> hostile actions held before execution, 0 false positives.** Sentinel is in
> **early access**, and we are opening design-partner pilot conversations
> now. This package is a small, working slice of Sentinel, published so
> agents and developers can try the evaluation model. It is **not the full
> Sentinel product** (no hosted policy store, no tenant management, no
> approval-workflow UI, no persistent audit storage). The evaluation is
> heuristic, not a guarantee of safety, and it has not had an independent
> penetration test or SOC 2 / ISO / FedRAMP certification.

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
systems, a lab, blue-team work) lowers the score without disabling checks,
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
- Product page and live demo: https://aridon-v02.vercel.app/sentinel-demo
- Paper (Zenodo): https://doi.org/10.5281/zenodo.23920785

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 Aridon (Triple R
Restoration, LLC dba Aridon).

## NetGuard: protection for devices outside the agent path (new in v0.2.0)

Some systems never propose actions to an agent: legacy and OT devices that
accept commands directly over a network. In November 2026, attackers reached
end-of-life refrigeration controllers in European supermarkets over the
internet and ran them hot. NetGuard is the layer for those devices:

1. **Command broker** (`sentinel_register_device`, `sentinel_device_command`):
   the only identity allowed to command a registered device. Enrolled sources
   only; parameters outside hard safety limits are denied outright; defrosts
   and out-of-band changes hold for a human; command text is scored by the
   same intent engine as agent actions.
2. **Enforcement plan** (`sentinel_enforcement_plan`): generated segmentation
   rules (JSON + nftables) making the broker the only reachable path: no
   internet route to the devices, no device egress.
3. **Telemetry watchdog** (`sentinel_device_telemetry`): observed state is
   compared with the last brokered state. A change nobody brokered is treated
   as tampering: an audit-chained incident and a quarantine rule set.

Test it: `node test/netguard.mjs` replays the supermarket attack end to end
(18 checks). Honest scope: NetGuard protects devices enrolled in its registry
behind the enforcement rules it generates; it does not patch the devices.
NetGuard is in the same early access stage as the rest of Sentinel, validated
in internal testing only. We are looking for lab testing partners, especially
controller manufacturers and food-retail operators. Contact:
jimrusk66@gmail.com.
