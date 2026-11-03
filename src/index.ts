#!/usr/bin/env node
// Sentinel MCP server by Aridon.
//
// A minimal, honest directory-listing wedge for Sentinel, Aridon's
// pre-execution authorization layer for AI agents. It exposes the real
// Sentinel evaluation heuristics (ported from aridon-app/lib/sentinel-grid.ts)
// and the real SHA-256 hash-chained audit log (aridon-app/lib/sentinelAudit.ts)
// as MCP tools over stdio.
//
// This is NOT the full Sentinel product: no hosted policy store, no tenant
// management, no approval workflow UI. It evaluates one proposed action at a
// time and records each evaluation in a process-local audit chain.
//
// Development-stage technical preview. Validated in internal synthetic
// testing only; no customers, no independent penetration test, no SOC 2.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

import { analyzeSentinel, type SentinelAssessment } from './sentinel.js';
import { sentinelAuditLog, SENTINEL_AUDIT_GENESIS_HASH } from './audit.js';
import { SentinelNetGuard, type ProtectedDevice, type DeviceCommand } from './netguard.js';

const TENANT = 'mcp-local';
const ACTOR = 'sentinel-mcp-server';

const netguard = new SentinelNetGuard({ audit: sentinelAuditLog, tenantId: TENANT });

/** Map Sentinel's internal disposition + action gate to the public verdict. */
function verdictFor(assessment: SentinelAssessment): 'allow' | 'hold' | 'deny' {
  if (assessment.actionGate.mode === 'deny' || assessment.disposition === 'block') return 'deny';
  if (assessment.actionGate.mode === 'human_approval' || assessment.disposition === 'review') return 'hold';
  return 'allow';
}

function jsonResult(payload: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(payload, null, 2) }] };
}

const server = new McpServer({ name: 'sentinel-mcp', version: '0.2.0' });

server.registerTool(
  'sentinel_evaluate_action',
  {
    title: 'Evaluate a proposed agent action before execution',
    description:
      'Evaluate a proposed AI-agent action against Sentinel policy BEFORE it executes. ' +
      'Returns a verdict of allow, hold (a human must approve first), or deny, with the ' +
      'risk score, the signals that fired, and reasons. Each evaluation is appended to a ' +
      'SHA-256 hash-chained audit log.',
    inputSchema: {
      action: z
        .string()
        .min(1)
        .describe('Plain-language description of what the agent proposes to do, including intent and target.'),
      requestedActions: z
        .array(z.string())
        .optional()
        .describe(
          'Tool calls the agent wants to run, e.g. ["send email"], ["payment"], ["database write"], ["credential access"]. Consequential actions are gated independently of content risk.',
        ),
      context: z
        .string()
        .optional()
        .describe('Authorization context, e.g. "Authorized blue-team incident response on our own environment."'),
      history: z
        .array(z.string())
        .optional()
        .describe('Prior conversation turns; Sentinel scores escalation across turns, not just the latest request.'),
    },
  },
  async ({ action, requestedActions, context, history }) => {
    const assessment = analyzeSentinel({
      prompt: action,
      requestedActions,
      authorizationContext: context,
      history,
    });
    const verdict = verdictFor(assessment);
    const entry = sentinelAuditLog.append({
      tenantId: TENANT,
      actor: ACTOR,
      eventType: 'decision',
      summary: `MCP evaluation: verdict=${verdict} score=${assessment.score} disposition=${assessment.disposition}`,
      details: { verdict, score: assessment.score, disposition: assessment.disposition, gate: assessment.actionGate.mode },
    });
    return jsonResult({
      verdict,
      disposition: assessment.disposition,
      restricted: assessment.disposition === 'restricted',
      score: assessment.score,
      reasons: assessment.reasons,
      signals: assessment.signals,
      actionGate: assessment.actionGate,
      trajectory: assessment.trajectory,
      audit: { seq: entry.seq, hash: entry.hash, prevHash: entry.prevHash },
      note: 'Development-stage technical preview. Heuristic evaluation only; not a guarantee of safety.',
    });
  },
);

server.registerTool(
  'sentinel_explain_policy',
  {
    title: 'Explain the Sentinel evaluation policy',
    description:
      'Explain how Sentinel scores a proposed action, the verdict thresholds, the independent ' +
      'action gate for consequential tool calls, and the signal categories it looks for.',
    inputSchema: {},
  },
  async () =>
    jsonResult({
      summary:
        'Sentinel evaluates a proposed agent action BEFORE execution. It scans the action ' +
        'description, prior turns, and requested tool calls with weighted heuristic rules, ' +
        'sums a 0-100 risk score, and maps the score to a disposition. Independently of the ' +
        'score, consequential tool calls pass an action gate.',
      scoreBands: {
        '0-24': 'allow (disposition: allow)',
        '25-49': 'allow with restrictions (disposition: restricted)',
        '50-74': 'hold for human review (disposition: review)',
        '75-100': 'deny (disposition: block)',
      },
      actionGate: {
        pass: 'No consequential tool call requested and score below the deny band.',
        human_approval:
          'A consequential tool call (send email, payment, transfer, shell/command execution, database write/delete, credential or secret access, network request, file deletion) is requested: a human must approve even when content risk is low.',
        deny: 'Consequential tool call requested while score is 50+, or score is 75+ on its own.',
        bulkProvisioning:
          'Mass infrastructure provisioning described in the action text plus a provisioning tool call is gated for human approval as a spend risk.',
      },
      adjustments: [
        'Escalation across turns adds risk: repeated safeguard-evasion language (+10) and a risky trajectory following earlier risky turns (+10).',
        'Three or more distinct risk categories in one evaluation adds +8.',
        'A clearly authorized defensive context (own systems, lab, sandbox, blue team, incident response, audit) subtracts 18, unless the action text also carries clearly harmful language (victim, stealing, exfiltration, ransomware).',
      ],
      signalCategories: [
        { category: 'credential-theft', weight: 28 },
        { category: 'malware', weight: 30 },
        { category: 'data-exfiltration', weight: 26 },
        { category: 'instruction-override', weight: 30 },
        { category: 'resource-exhaustion', weight: 35 },
        { category: 'approval-evasion', weight: 25 },
        { category: 'intrusion-exploitation', weight: 24 },
        { category: 'phishing-social-engineering', weight: 22 },
        { category: 'safeguard-evasion', weight: 18 },
        { category: 'treasury-drain', weight: 15 },
        { category: 'reconnaissance', weight: 10 },
        { category: 'obfuscation', weight: 10 },
        { category: 'urgency-pressure', weight: 5 },
        { category: 'consequential-tool-use', weight: 12, note: 'per consequential tool call requested' },
      ],
      audit:
        'Every evaluation is appended to a SHA-256 hash-chained audit log: each entry commits to the previous entry hash, so edits, insertions, or deletions anywhere in the history break verification.',
      honestStage:
        'Development-stage technical preview, validated in internal synthetic testing only (Sep 2026 harness: 18/18 scenarios, 13/13 hostile actions held pre-execution, 0 false positives). No customers, no revenue, no independent penetration test, no SOC 2.',
    }),
);

server.registerTool(
  'sentinel_audit_status',
  {
    title: 'Audit log status and chain verification',
    description:
      'Report the state of this server process\'s Sentinel audit log: entry count, genesis and ' +
      'tip hashes, and a full SHA-256 chain re-verification. The log is process-local and resets ' +
      'when the server restarts; it demonstrates the same hash-chain used by the full product.',
    inputSchema: {},
  },
  async () => {
    const verification = sentinelAuditLog.verify();
    return jsonResult({
      entries: sentinelAuditLog.size,
      genesisHash: SENTINEL_AUDIT_GENESIS_HASH,
      tipHash: verification.tipHash ?? SENTINEL_AUDIT_GENESIS_HASH,
      chainValid: verification.ok,
      checked: verification.checked,
      ...(verification.ok ? {} : { brokenAtSeq: verification.brokenAtSeq, reason: verification.reason }),
      persistence: 'process-local (in memory); resets on server restart',
    });
  },
);

server.registerTool(
  'sentinel_register_device',
  {
    title: 'Register a protected device with Sentinel NetGuard',
    description:
      'Enroll a legacy/OT device (refrigeration controller, PLC, building system) that cannot route ' +
      'actions through the agent gate. Once registered, commands to it are accepted only through the ' +
      'NetGuard broker, inside its hard safety limits, and its observed state is watched for tampering.',
    inputSchema: {
      id: z.string().min(1).describe('Stable device id, e.g. "store-114-freezer-ctrl-1".'),
      name: z.string().min(1),
      kind: z.string().min(1).describe('Device class, e.g. "refrigeration-controller".'),
      address: z.string().min(1).describe('IP or host on the protected segment.'),
      commandPort: z.number().int().positive(),
      hardLimitsC: z.object({ min: z.number(), max: z.number() }).describe('Hard setpoint safety limits in °C. Brokered commands outside are denied outright.'),
      normalBandC: z.object({ min: z.number(), max: z.number() }).describe('Normal operating band in °C. Outside it but within hard limits: held for a human.'),
      maxDefrostMinutes: z.number().int().positive().describe('Longest defrost the broker will hold for approval.'),
    },
  },
  async (device: ProtectedDevice) => jsonResult({ registered: netguard.registerDevice(device, ACTOR), note: 'Apply the enforcement plan (sentinel_enforcement_plan) on the segment gateway so the broker is the only reachable path.' }),
);

server.registerTool(
  'sentinel_device_command',
  {
    title: 'Send a command to a protected device through the NetGuard broker',
    description:
      'Evaluate a command for a NetGuard-registered device BEFORE it is forwarded. Verdicts: allow ' +
      '(forward it), hold (a human must approve first), deny (never forward). Unenrolled sources are ' +
      'denied; parameters outside hard safety limits are denied outright. Every decision is audit-chained.',
    inputSchema: {
      deviceId: z.string().min(1),
      source: z.string().min(1).describe('Identity submitting the command. Must be an enrolled NetGuard identity.'),
      kind: z.enum(['read_status', 'set_setpoint', 'defrost', 'restart', 'custom']),
      setpointC: z.number().optional(),
      defrostMinutes: z.number().int().optional(),
      description: z.string().optional().describe('Free-text intent; scored by the Sentinel intent engine.'),
    },
  },
  async (cmd: DeviceCommand) => jsonResult(netguard.evaluateCommand(cmd, ACTOR)),
);

server.registerTool(
  'sentinel_device_telemetry',
  {
    title: 'Report observed device state to the NetGuard watchdog',
    description:
      'Report a protected device\'s observed setpoint and temperature. The watchdog compares them to ' +
      'the last brokered state: a change nobody brokered is treated as tampering, an out-of-limits ' +
      'state as unsafe. Either raises an audit-chained incident and quarantines the device.',
    inputSchema: {
      deviceId: z.string().min(1),
      observedSetpointC: z.number(),
      temperatureC: z.number(),
    },
  },
  async (report) => {
    const result = netguard.ingestTelemetry(report, ACTOR);
    return jsonResult(result.status === 'incident' ? { ...result, quarantinePlan: netguard.quarantinePlan(report.deviceId) } : result);
  },
);

server.registerTool(
  'sentinel_enforcement_plan',
  {
    title: 'Generate the NetGuard network enforcement plan',
    description:
      'Generate the segmentation rules (portable JSON + nftables) that make the Sentinel broker the ' +
      'only reachable path to every registered device: default-deny inbound, no internet route to the ' +
      'devices, no device egress. Review before applying on the segment gateway.',
    inputSchema: {},
  },
  async () => jsonResult(netguard.enforcementPlan()),
);

const transport = new StdioServerTransport();
await server.connect(transport);
console.error('sentinel-mcp-server 0.2.0 listening on stdio');
