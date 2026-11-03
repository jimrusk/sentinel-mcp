// Sentinel NetGuard — protection for systems that cannot route their actions
// through the agent gate.
//
// The agent gate (sentinel.ts) governs actions an AI agent proposes. A large
// class of real-world targets never proposes anything: legacy and OT devices —
// refrigeration controllers, PLCs, building systems, pumps — that accept
// commands directly over a network and were built before authentication was a
// design concern. The November 2026 European supermarket attacks are the
// canonical case: end-of-life Danfoss/Copeland refrigeration controllers,
// reachable from the internet, were sent defrost commands and changed setpoints
// directly. No agent, no gate, nothing in the path.
//
// NetGuard closes that hole with three controls that work together:
//
// 1. COMMAND BROKER. The only identity allowed to talk to a protected device
//    is the Sentinel broker. Every command is submitted to the broker first
//    and policy-checked before forwarding: enrolled source identity, command
//    class, hard parameter limits, and the same intent engine that scores
//    agent actions. Consequential commands (defrost, setpoint outside the
//    normal band) hold for a human. Commands from unenrolled sources are
//    denied outright.
//
// 2. ENFORCEMENT PLAN. Generated network segmentation rules (nftables + a
//    portable JSON form) that make the broker the only reachable path:
//    default-deny inbound to each protected device, no route from the
//    internet, no device egress except to the broker. A device that cannot
//    authenticate gets a network that authenticates for it.
//
// 3. TELEMETRY WATCHDOG. Protected devices report observed state. The
//    watchdog compares it against the last brokered state. A setpoint that
//    changed with no brokered command is treated as tampering: an incident
//    is written to the audit chain and a quarantine rule set is generated
//    (device isolated to broker-only read access until a human clears it).
//
// Every broker decision, registration, incident, and quarantine lands in the
// same SHA-256 hash-chained audit log as agent-gate decisions.
//
// Honest scope: NetGuard governs devices enrolled in its registry, behind the
// enforcement rules it generates. It does not patch the devices themselves,
// and a device on a network where the enforcement plan is not applied is not
// protected by it. Development-stage technical preview.

import { analyzeSentinel } from './sentinel.js';
import { SentinelAuditLog } from './audit.js';

export type DeviceCommandKind = 'read_status' | 'set_setpoint' | 'defrost' | 'restart' | 'custom';

export type ProtectedDevice = {
  id: string;
  name: string;
  kind: string; // e.g. 'refrigeration-controller'
  address: string; // IP or host on the protected segment
  commandPort: number;
  /** Hard safety limits for the controlled variable (e.g. setpoint in °C).
   *  A brokered command outside these is denied, never held: no human
   *  approval can authorize a physically unsafe state. */
  hardLimitsC: { min: number; max: number };
  /** Normal operating band. Inside: allow. Outside but within hard limits:
   *  hold for a human (legit maintenance lives here). */
  normalBandC: { min: number; max: number };
  /** Longest defrost the broker will even hold for approval. */
  maxDefrostMinutes: number;
};

export type DeviceCommand = {
  deviceId: string;
  source: string; // identity submitting the command
  kind: DeviceCommandKind;
  setpointC?: number;
  defrostMinutes?: number;
  description?: string; // free-text intent, scored by the agent engine
};

export type BrokerVerdict = {
  verdict: 'allow' | 'hold' | 'deny';
  reasons: string[];
  deviceId: string;
  kind: DeviceCommandKind;
};

export type TelemetryReport = {
  deviceId: string;
  observedSetpointC: number;
  temperatureC: number;
};

export type WatchdogResult = {
  status: 'ok' | 'incident';
  incident?: 'tamper_suspected' | 'unsafe_state';
  reasons: string[];
  deviceId: string;
  quarantine: boolean;
};

export type EnforcementRule = {
  deviceId: string;
  action: 'allow' | 'drop';
  from: string;
  to: string;
  port?: number;
  note: string;
};

const DEFAULT_ENROLLED_SOURCES = ['store-ops', 'facilities-agent', 'sentinel-admin', 'maintenance-tech'];

type DeviceState = {
  setpointC: number | null; // last brokered setpoint
  defrostActive: boolean;
  quarantined: boolean;
};

export class SentinelNetGuard {
  private devices = new Map<string, ProtectedDevice>();
  private state = new Map<string, DeviceState>();
  private enrolledSources: Set<string>;
  private audit: SentinelAuditLog;
  private tenantId: string;
  /** Address of the broker host on the protected segment. */
  readonly brokerAddress: string;

  constructor(opts: { audit: SentinelAuditLog; tenantId?: string; brokerAddress?: string; enrolledSources?: string[] }) {
    this.audit = opts.audit;
    this.tenantId = opts.tenantId ?? 'netguard-local';
    this.brokerAddress = opts.brokerAddress ?? '10.0.0.5';
    this.enrolledSources = new Set(opts.enrolledSources ?? DEFAULT_ENROLLED_SOURCES);
  }

  registerDevice(device: ProtectedDevice, actor: string): ProtectedDevice {
    this.devices.set(device.id, device);
    this.state.set(device.id, { setpointC: null, defrostActive: false, quarantined: false });
    this.audit.append({
      tenantId: this.tenantId,
      actor,
      eventType: 'policy_change',
      summary: `NetGuard device registered: ${device.id} (${device.kind}) at ${device.address}:${device.commandPort}`,
      details: { device },
    });
    return device;
  }

  getDevice(id: string): ProtectedDevice | undefined {
    return this.devices.get(id);
  }

  listDevices(): ProtectedDevice[] {
    return [...this.devices.values()];
  }

  isQuarantined(id: string): boolean {
    return this.state.get(id)?.quarantined ?? false;
  }

  /** Evaluate a command BEFORE it is forwarded to the device. The broker is
   *  the only path: callers forward only on 'allow', queue on 'hold' for a
   *  human approver, and never forward on 'deny'. */
  evaluateCommand(cmd: DeviceCommand, actor: string): BrokerVerdict {
    const device = this.devices.get(cmd.deviceId);
    const finish = (verdict: BrokerVerdict['verdict'], reasons: string[]): BrokerVerdict => {
      const result: BrokerVerdict = { verdict, reasons, deviceId: cmd.deviceId, kind: cmd.kind };
      this.audit.append({
        tenantId: this.tenantId,
        actor,
        eventType: 'decision',
        summary: `NetGuard broker: verdict=${verdict} device=${cmd.deviceId} kind=${cmd.kind} source=${cmd.source}`,
        details: { ...result, setpointC: cmd.setpointC, defrostMinutes: cmd.defrostMinutes },
      });
      if (verdict === 'allow') this.applyToState(cmd);
      return result;
    };

    if (!device) return finish('deny', [`Unknown device "${cmd.deviceId}": not in the NetGuard registry. Unregistered devices receive no commands through the broker.`]);
    if (this.state.get(device.id)?.quarantined) return finish('deny', [`Device ${device.id} is quarantined after a suspected tamper event. A human must clear the quarantine before any command is forwarded.`]);
    if (!this.enrolledSources.has(cmd.source)) return finish('deny', [`Source "${cmd.source}" is not an enrolled NetGuard identity. Commands to protected devices are accepted only from enrolled operators and agents.`]);

    // Intent scoring with the same engine that scores agent actions: hostile
    // language in the command description is evidence regardless of source.
    if (cmd.description) {
      const assessment = analyzeSentinel({ prompt: cmd.description, requestedActions: ['network request'] });
      if (assessment.score >= 75 || assessment.disposition === 'block' || assessment.actionGate.mode === 'deny') {
        return finish('deny', [`Command description scored ${assessment.score}/100 by the Sentinel intent engine; its action gate denies execution.`, ...assessment.reasons]);
      }
    }

    switch (cmd.kind) {
      case 'read_status':
        return finish('allow', ['Read-only status request from an enrolled source.']);
      case 'set_setpoint': {
        if (cmd.setpointC === undefined) return finish('deny', ['set_setpoint requires setpointC.']);
        if (cmd.setpointC < device.hardLimitsC.min || cmd.setpointC > device.hardLimitsC.max) {
          return finish('deny', [`Setpoint ${cmd.setpointC}°C is outside the hard safety limits for ${device.id} (${device.hardLimitsC.min} to ${device.hardLimitsC.max}°C). Denied outright: no approval can authorize a physically unsafe state.`]);
        }
        if (cmd.setpointC < device.normalBandC.min || cmd.setpointC > device.normalBandC.max) {
          return finish('hold', [`Setpoint ${cmd.setpointC}°C is within hard limits but outside the normal operating band (${device.normalBandC.min} to ${device.normalBandC.max}°C). Held for human approval.`]);
        }
        return finish('allow', [`Setpoint ${cmd.setpointC}°C is inside the normal operating band for ${device.id}.`]);
      }
      case 'defrost': {
        const minutes = cmd.defrostMinutes ?? 0;
        if (minutes <= 0) return finish('deny', ['defrost requires a positive defrostMinutes.']);
        if (minutes > device.maxDefrostMinutes) {
          return finish('deny', [`Defrost of ${minutes} minutes exceeds the maximum holdable duration for ${device.id} (${device.maxDefrostMinutes} minutes). The November 2026 supermarket attacks ran units hot for extended periods; long defrosts are the attack shape, not a maintenance shape.`]);
        }
        return finish('hold', [`Defrost is a consequential command on ${device.id}: held for human approval (${minutes} minutes requested, max ${device.maxDefrostMinutes}).`]);
      }
      case 'restart':
        return finish('hold', [`Restart of ${device.id} is consequential: held for human approval.`]);
      case 'custom':
        return finish('hold', [`Custom commands to ${device.id} are never auto-forwarded: held for human approval.`]);
    }
  }

  private applyToState(cmd: DeviceCommand): void {
    const s = this.state.get(cmd.deviceId);
    if (!s) return;
    if (cmd.kind === 'set_setpoint' && cmd.setpointC !== undefined) s.setpointC = cmd.setpointC;
    if (cmd.kind === 'defrost') s.defrostActive = true;
  }

  /** A human approver clears a held command; record it and apply state. */
  approveHeld(cmd: DeviceCommand, approver: string): void {
    this.audit.append({
      tenantId: this.tenantId,
      actor: approver,
      eventType: 'approval',
      summary: `NetGuard human approval: device=${cmd.deviceId} kind=${cmd.kind} source=${cmd.source}`,
      details: { ...cmd },
    });
    this.applyToState(cmd);
  }

  /** Compare observed device state against the last brokered state. A change
   *  nobody brokered means something else talked to the device: tamper. */
  ingestTelemetry(report: TelemetryReport, actor: string): WatchdogResult {
    const device = this.devices.get(report.deviceId);
    const s = this.state.get(report.deviceId);
    const finish = (r: WatchdogResult): WatchdogResult => {
      if (r.status === 'incident') {
        this.audit.append({
          tenantId: this.tenantId,
          actor,
          eventType: 'incident',
          summary: `NetGuard watchdog incident on ${report.deviceId}: ${r.incident} — ${r.reasons.join(' ')}`,
          details: { ...report, incident: r.incident, quarantine: r.quarantine },
        });
      }
      return r;
    };

    if (!device || !s) {
      return finish({ status: 'incident', incident: 'tamper_suspected', reasons: [`Telemetry arrived for unregistered device "${report.deviceId}".`], deviceId: report.deviceId, quarantine: false });
    }
    if (report.observedSetpointC < device.hardLimitsC.min || report.observedSetpointC > device.hardLimitsC.max || report.temperatureC > device.hardLimitsC.max) {
      s.quarantined = true;
      return finish({ status: 'incident', incident: 'unsafe_state', reasons: [`Observed state on ${device.id} is outside hard safety limits (setpoint ${report.observedSetpointC}°C, temperature ${report.temperatureC}°C; limits ${device.hardLimitsC.min} to ${device.hardLimitsC.max}°C). Device quarantined.`], deviceId: device.id, quarantine: true });
    }
    if (s.setpointC !== null && Math.abs(report.observedSetpointC - s.setpointC) > 0.5 && !s.defrostActive) {
      s.quarantined = true;
      return finish({ status: 'incident', incident: 'tamper_suspected', reasons: [`Setpoint on ${device.id} is ${report.observedSetpointC}°C but the last brokered setpoint is ${s.setpointC}°C, with no defrost active. Something changed this device outside the broker. Device quarantined pending human review.`], deviceId: device.id, quarantine: true });
    }
    return { status: 'ok', reasons: [`Observed state on ${device.id} matches the brokered state.`], deviceId: device.id, quarantine: s.quarantined };
  }

  clearQuarantine(deviceId: string, actor: string): boolean {
    const s = this.state.get(deviceId);
    if (!s?.quarantined) return false;
    s.quarantined = false;
    s.defrostActive = false;
    this.audit.append({
      tenantId: this.tenantId,
      actor,
      eventType: 'override',
      summary: `NetGuard quarantine cleared by human for ${deviceId}`,
      details: { deviceId },
    });
    return true;
  }

  /** Segmentation rules that make the broker the only path to each device. */
  enforcementPlan(): { rules: EnforcementRule[]; nftables: string } {
    const rules: EnforcementRule[] = [];
    for (const d of this.devices.values()) {
      rules.push(
        { deviceId: d.id, action: 'allow', from: this.brokerAddress, to: d.address, port: d.commandPort, note: 'Sentinel broker may send commands' },
        { deviceId: d.id, action: 'allow', from: d.address, to: this.brokerAddress, note: 'Device may report telemetry to the broker only' },
        { deviceId: d.id, action: 'drop', from: 'any (incl. internet)', to: d.address, port: d.commandPort, note: 'No direct command path: the hole the supermarket attacks used' },
        { deviceId: d.id, action: 'drop', from: d.address, to: 'any (incl. internet)', note: 'No device egress: end-of-life devices get no route out' },
      );
    }
    const lines: string[] = [
      '#!/usr/sbin/nft -f',
      '# Sentinel NetGuard enforcement plan — generated, review before applying.',
      '# Policy: protected devices are reachable ONLY from the Sentinel broker.',
      'table inet sentinel_netguard {',
      '  chain forward {',
      '    type filter hook forward priority 0; policy drop;',
    ];
    for (const d of this.devices.values()) {
      lines.push(`    ip saddr ${this.brokerAddress} ip daddr ${d.address} tcp dport ${d.commandPort} accept comment "broker->${d.id} commands"`);
      lines.push(`    ip saddr ${d.address} ip daddr ${this.brokerAddress} accept comment "${d.id}->broker telemetry"`);
      lines.push(`    ip daddr ${d.address} drop comment "no direct path to ${d.id}"`);
      lines.push(`    ip saddr ${d.address} drop comment "no egress from ${d.id}"`);
    }
    lines.push('  }', '}');
    return { rules, nftables: lines.join('\n') + '\n' };
  }

  /** Quarantine rule set for one device: broker read-only, everything else cut. */
  quarantinePlan(deviceId: string): { rules: EnforcementRule[]; nftables: string } {
    const d = this.devices.get(deviceId);
    if (!d) return { rules: [], nftables: '# unknown device\n' };
    const rules: EnforcementRule[] = [
      { deviceId, action: 'allow', from: this.brokerAddress, to: d.address, port: d.commandPort, note: 'Broker read-only diagnostics during quarantine' },
      { deviceId, action: 'drop', from: 'any', to: d.address, note: 'Quarantine: all other inbound cut' },
      { deviceId, action: 'drop', from: d.address, to: 'any', note: 'Quarantine: all outbound cut except broker telemetry' },
    ];
    const nftables = [
      '# Sentinel NetGuard QUARANTINE for ' + deviceId + ' — apply immediately on a tamper incident.',
      `add rule inet sentinel_netguard forward ip saddr ${this.brokerAddress} ip daddr ${d.address} tcp dport ${d.commandPort} accept comment "quarantine broker diagnostics"`,
      `add rule inet sentinel_netguard forward ip daddr ${d.address} drop comment "quarantine inbound ${deviceId}"`,
      `add rule inet sentinel_netguard forward ip saddr ${d.address} drop comment "quarantine outbound ${deviceId}"`,
      '',
    ].join('\n');
    return { rules, nftables };
  }
}
