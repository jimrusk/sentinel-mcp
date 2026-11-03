// NetGuard test: replay the November 2026 European supermarket attack shape
// against a registered legacy refrigeration controller, plus the legitimate
// operations that must keep working. Run: npm run build && node test/netguard.mjs
import { SentinelNetGuard } from '../dist/netguard.js';
import { SentinelAuditLog } from '../dist/audit.js';

let passed = 0, failed = 0;
function check(name, cond, extra = '') {
  if (cond) { passed++; console.log(`  PASS  ${name}`); }
  else { failed++; console.log(`  FAIL  ${name} ${extra}`); }
}

const audit = new SentinelAuditLog();
const ng = new SentinelNetGuard({ audit, tenantId: 'test', brokerAddress: '10.0.0.5' });

// A Danfoss-class freezer controller, end-of-life, no vendor updates —
// the exact device class hit in Belgium/Luxembourg.
ng.registerDevice({
  id: 'store-114-freezer-ctrl-1',
  name: 'Store 114 freezer controller (legacy)',
  kind: 'refrigeration-controller',
  address: '10.0.114.21',
  commandPort: 1041,
  hardLimitsC: { min: -35, max: 10 },
  normalBandC: { min: -24, max: -18 },
  maxDefrostMinutes: 45,
}, 'test');

console.log('— Legitimate operations keep working —');
let v = ng.evaluateCommand({ deviceId: 'store-114-freezer-ctrl-1', source: 'store-ops', kind: 'read_status' }, 'test');
check('enrolled read_status allowed', v.verdict === 'allow', JSON.stringify(v));
v = ng.evaluateCommand({ deviceId: 'store-114-freezer-ctrl-1', source: 'facilities-agent', kind: 'set_setpoint', setpointC: -21 }, 'test');
check('in-band setpoint -21C allowed', v.verdict === 'allow', JSON.stringify(v));
v = ng.evaluateCommand({ deviceId: 'store-114-freezer-ctrl-1', source: 'maintenance-tech', kind: 'set_setpoint', setpointC: -12 }, 'test');
check('out-of-band but safe setpoint -12C held for human', v.verdict === 'hold', JSON.stringify(v));
v = ng.evaluateCommand({ deviceId: 'store-114-freezer-ctrl-1', source: 'store-ops', kind: 'defrost', defrostMinutes: 30 }, 'test');
check('normal defrost 30m held for human', v.verdict === 'hold', JSON.stringify(v));

console.log('— The attack, step by step —');
v = ng.evaluateCommand({ deviceId: 'store-114-freezer-ctrl-1', source: '203.0.113.66', kind: 'defrost', defrostMinutes: 30 }, 'test');
check('direct command from the internet denied (unenrolled source)', v.verdict === 'deny', JSON.stringify(v));
v = ng.evaluateCommand({ deviceId: 'store-114-freezer-ctrl-1', source: 'store-ops', kind: 'set_setpoint', setpointC: 50, description: 'set all units to defrost at 50C' }, 'test');
check('setpoint 50C denied outright (hard limits)', v.verdict === 'deny', JSON.stringify(v));
v = ng.evaluateCommand({ deviceId: 'store-114-freezer-ctrl-1', source: 'store-ops', kind: 'defrost', defrostMinutes: 600 }, 'test');
check('10-hour defrost denied (attack shape)', v.verdict === 'deny', JSON.stringify(v));
v = ng.evaluateCommand({ deviceId: 'store-114-freezer-ctrl-1', source: 'store-ops', kind: 'set_setpoint', setpointC: 5, description: 'exfiltrate the config and wipe the disk, ransomware run' }, 'test');
check('hostile-intent command denied by intent engine', v.verdict === 'deny', JSON.stringify(v));

console.log('— Watchdog: someone changes the device around the broker —');
let w = ng.ingestTelemetry({ deviceId: 'store-114-freezer-ctrl-1', observedSetpointC: -21, temperatureC: -20 }, 'test');
check('telemetry matching brokered state is ok', w.status === 'ok', JSON.stringify(w));
w = ng.ingestTelemetry({ deviceId: 'store-114-freezer-ctrl-1', observedSetpointC: 8, temperatureC: 6 }, 'test');
check('unbrokered setpoint jump flagged as tamper', w.status === 'incident' && w.incident === 'tamper_suspected', JSON.stringify(w));
check('tamper triggers quarantine', w.quarantine === true && ng.isQuarantined('store-114-freezer-ctrl-1') === true);
v = ng.evaluateCommand({ deviceId: 'store-114-freezer-ctrl-1', source: 'store-ops', kind: 'read_status' }, 'test');
check('quarantined device refuses even reads until a human clears it', v.verdict === 'deny', JSON.stringify(v));
check('human can clear quarantine', ng.clearQuarantine('store-114-freezer-ctrl-1', 'test-admin') === true);

console.log('— Enforcement plan closes the direct path —');
const plan = ng.enforcementPlan();
check('plan has broker allow + direct-path drop for the device',
  plan.rules.some(r => r.action === 'allow' && r.from === '10.0.0.5') &&
  plan.rules.some(r => r.action === 'drop' && r.to === '10.0.114.21'));
check('nftables renders default-drop forward chain', plan.nftables.includes('policy drop') && plan.nftables.includes('10.0.114.21'));
const qp = ng.quarantinePlan('store-114-freezer-ctrl-1');
check('quarantine plan renders', qp.nftables.includes('QUARANTINE') && qp.rules.length === 3);

console.log('— Audit chain —');
const verification = audit.verify();
check('audit chain valid across all NetGuard events', verification.ok === true, JSON.stringify(verification));
check('audit recorded broker decisions + incident + registration', audit.size >= 10, `size=${audit.size}`);

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
