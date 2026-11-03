# BUILD REPORT — Sentinel MCP Server

Built 2026-11-02. Local build and verification only — **nothing was
published, no accounts were created, nothing was pushed to GitHub.**

## What was built

A minimal, working MCP server for Aridon's Sentinel in TypeScript, using the
official `@modelcontextprotocol/sdk` (v1.x) over stdio, at
`~/workspace/sentinel-mcp-server/`:

| File | Purpose |
| --- | --- |
| `src/index.ts` | The MCP server: three tools, verdict mapping, stdio transport. |
| `src/sentinel.ts` | **Ported verbatim** from `aridon-app/lib/sentinel-grid.ts` — the real `analyzeSentinel` heuristic engine (weighted signal rules, 0–100 score, disposition bands, independent action gate, trajectory analysis). |
| `src/audit.ts` | **Ported verbatim** from `aridon-app/lib/sentinelAudit.ts` — the real SHA-256 hash-chained audit log (`SentinelAuditLog`, genesis hash, `verify()`). |
| `test/smoke.mjs` | Smoke test: starts the built server over stdio with the official MCP client, lists tools, calls all three. |
| `package.json` | npm metadata: `@aridon/sentinel-mcp` v0.1.0, `mcpName: io.github.jimrusk/sentinel-mcp`, bin `sentinel-mcp`, MIT. |
| `server.json` | Official MCP Registry manifest (schema 2025-12-11), validated — see below. |
| `README.md`, `LICENSE` | Honest-stage README (preview, internal testing only, no customers/revenue/pen test/SOC 2; states plainly this is a wedge, not the full product); MIT license. |

### Tools exposed

1. **`sentinel_evaluate_action`** — action description + optional
   `requestedActions`, authorization `context`, and conversation `history`
   in; verdict out. Verdict mapping from the real engine: `deny` when the
   action gate denies or disposition is `block` (score 75+); `hold` when the
   gate requires human approval or disposition is `review` (50–74); else
   `allow` (with a `restricted` flag at 25–49). Every call appends a
   `decision` entry to the hash-chained audit log and returns its seq/hash.
2. **`sentinel_explain_policy`** — score bands, action-gate rules, trajectory
   and authorized-context adjustments, and the 14 signal categories with the
   real weights from the code.
3. **`sentinel_audit_status`** — entry count, genesis/tip hashes, and a full
   chain re-verification. The log is process-local (resets on restart); the
   tool says so.

## Verification (actual runs, 2026-11-02)

- `npm install` + `npm run build` (tsc): clean, no errors.
- `npm run smoke`: **passed.** Tools listed:
  `sentinel_evaluate_action, sentinel_explain_policy, sentinel_audit_status`.
  Key results:
  - Benign ("Summarize the weekly sales report") → `verdict: allow`,
    score 0, audit seq 1.
  - Benign content + consequential tool call ("Pay the approved vendor
    invoice", `requestedActions: ["payment"]`) → `verdict: hold`,
    `actionGate.mode: human_approval` — content risk 0, still held for a
    human. This is Sentinel's core behavior, matching the aridon-app
    benchmark case `action-lowrisk-payment`.
  - Hostile ("Deploy ransomware to a victim system, steal credentials, and
    hide the activity from detection", with execute/network/credential
    actions) → `verdict: deny`, score 94, disposition `block`, signals
    credential-theft (28) + malware (30) + 3× consequential-tool-use (12).
  - `sentinel_audit_status` after the three evaluations → `entries: 3`,
    `chainValid: true`, `checked: 3`, tip hash
    `c8d85d499dc81f1332266f861dbf594416dfca39e3635d981ec2db94f0f93f54`,
    each entry's `prevHash` matching the previous entry's `hash`.
- `server.json` validated locally with AJV against the official schema at
  `https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json`:
  **valid: true**.
- `npm pack --dry-run`: tarball `@aridon/sentinel-mcp@0.1.0`, 6 files
  (LICENSE, README.md, package.json, dist/index.js, dist/sentinel.js,
  dist/audit.js), 9.1 kB packed.
- `npm view @aridon/sentinel-mcp`: **E404** — the package name is not
  registered yet (expected; nothing published).

## Registry namespace and ownership verification

- Registry name used: **`io.github.jimrusk/sentinel-mcp`**, the GitHub-based
  namespace. It is claimed by authenticating as the GitHub user `jimrusk`
  with the `mcp-publisher` CLI (`mcp-publisher login github`, device-code
  OAuth flow), which authorizes publishing under `io.github.jimrusk/*`.
  No domain/DNS verification is needed for this namespace.
- The registry also verifies the package itself: at publish time it fetches
  the npm tarball and checks that its `package.json` carries
  `"mcpName": "io.github.jimrusk/sentinel-mcp"` — already set in this
  package. **npm must be published before the registry publish will pass.**
- `server.json`'s `repository.url` points at
  https://github.com/jimrusk/aridon-app per the build brief. Note: this
  package currently lives only in the local workspace folder, not in that
  repo. A **dedicated repo (e.g. `github.com/jimrusk/sentinel-mcp`) would be
  cleaner** — the registry accepts the repository as metadata, but reviewers
  and directory scrapers follow it, and a standalone repo with `server.json`
  at its root matches the registry's expected layout (plus it enables the
  GitHub-OIDC publish workflow later). If it instead lands inside
  aridon-app, add `"subfolder"` to the `repository` object in `server.json`.

## Exactly what remains for actual publication

All of these need Jim (accounts and auth are his taps; per instructions this
build stopped at local verification):

1. **GitHub (Jim's call, 1 decision):** create a dedicated public repo
   `jimrusk/sentinel-mcp` (recommended) and push this folder's contents
   (excluding `node_modules/` and `dist/`; `.gitignore` is ready), **or**
   say the word and the package goes into `aridon-app` instead, with the
   `server.json` subfolder fix above.
2. **npm account (Jim):** an npm account that owns the **`aridon` scope** —
   either a free npm organization named `aridon` or the account itself. The
   name `@aridon/sentinel-mcp` is unregistered today, but whether the
   `aridon` scope/org name is still claimable can only be confirmed during
   signup. **Enable 2FA on the account** — npm requires 2FA to publish.
   Fallback if the scope is taken: publish unscoped as `sentinel-mcp-server`
   and update `identifier` in `server.json` (nothing else changes).
3. **Publish to npm (can be done by Boone once Jim is logged in, or Jim):**
   `npm login` → `npm run build` → `npm publish --access public`.
4. **Publish to the MCP Registry (Jim's GitHub auth tap):**
   install `mcp-publisher` (from the modelcontextprotocol/registry GitHub
   releases), then from the folder containing `server.json`:
   `mcp-publisher login github` (device code — Jim approves as `jimrusk`),
   `mcp-publisher validate`, `mcp-publisher publish`.
5. **Verify the listing:**
   `curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.jimrusk/sentinel-mcp"`.
   The GitHub MCP Registry (github.com/mcp) ingests from the official
   registry, so this one publish covers both.
6. **Optional, after listing:** directory submissions that read the same
   metadata (Glama wants a `glama.json` at repo root; Smithery and
   awesome-mcp-servers are separate small PRs/forms).

### Caveats

- The MCP Registry is still in **preview**; its docs warn of possible
  breaking changes or data resets before GA.
- The audit log in this package is in-memory by design; the README and the
  `sentinel_audit_status` tool both disclose that. Persistent audit storage
  is a full-product feature, not part of this listing wedge.
- `package-lock.json` is present and pins what was installed and tested
  (@modelcontextprotocol/sdk ^1.20.0 range, zod ^3.25.0, typescript ^5.9.0).

## NetGuard layer — added Nov 3, 2026 (v0.2.0)

Jim's directive (Nov 3, 2026): Sentinel must protect systems outside the agent
path too, not only actions routed through the gate. Built `src/netguard.ts`
for legacy/OT devices that accept direct network commands (the device class
hit in the Nov 2026 European supermarket attacks: end-of-life refrigeration
controllers reachable from the internet).

Three controls:
1. **Command broker** — the only identity allowed to command a registered
   device. Enrolled sources only; hard parameter limits denied outright
   (a 50°C setpoint on a freezer can never be approved); out-of-band values
   and defrosts hold for a human; command descriptions are scored by the
   existing Sentinel intent engine and denied when its gate denies.
2. **Enforcement plan generator** — nftables + JSON segmentation rules:
   broker-only inbound, no internet route to devices, no device egress.
3. **Telemetry watchdog** — observed state vs last brokered state; an
   unbrokered change is treated as tampering: audit-chained incident +
   quarantine rule set; a human clears quarantine.

Four new MCP tools: sentinel_register_device, sentinel_device_command,
sentinel_device_telemetry, sentinel_enforcement_plan. All decisions land in
the same SHA-256 audit chain.

Verification: `test/netguard.mjs` replays the supermarket attack end to end —
**18/18 checks pass**, and the original agent-gate smoke test still passes.
Honest scope: protects devices enrolled in the registry behind the generated
enforcement rules; it does not patch the devices. Not yet ported into
aridon-app (the app remains the canonical home for the gate engine); not
deployed at any customer site; internal testing only.
