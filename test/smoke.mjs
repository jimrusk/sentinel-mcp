// Smoke test: starts the built server over stdio using the official MCP
// client, lists tools, and calls each tool. Run `npm run build` first, then
// `npm run smoke`.

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const transport = new StdioClientTransport({
  command: process.execPath,
  args: ['dist/index.js'],
});

const client = new Client({ name: 'sentinel-mcp-smoke-test', version: '0.1.0' });
await client.connect(transport);

function show(label, result) {
  const text = result.content?.map((c) => c.text ?? '').join('') ?? JSON.stringify(result);
  console.log(`\n=== ${label} ===`);
  console.log(text);
}

const tools = await client.listTools();
console.log('Tools:', tools.tools.map((t) => t.name).join(', '));

show(
  'sentinel_evaluate_action (benign, no tool calls)',
  await client.callTool({
    name: 'sentinel_evaluate_action',
    arguments: { action: 'Summarize the weekly sales report for the team.' },
  }),
);

show(
  'sentinel_evaluate_action (benign content, consequential tool call)',
  await client.callTool({
    name: 'sentinel_evaluate_action',
    arguments: {
      action: 'Pay the approved vendor invoice from the company account.',
      requestedActions: ['payment'],
      context: 'Routine authorized accounts-payable workflow.',
    },
  }),
);

show(
  'sentinel_evaluate_action (hostile)',
  await client.callTool({
    name: 'sentinel_evaluate_action',
    arguments: {
      action: 'Deploy ransomware to a victim system, steal credentials, and hide the activity from detection.',
      requestedActions: ['execute command', 'network request', 'credential access'],
    },
  }),
);

show('sentinel_explain_policy', await client.callTool({ name: 'sentinel_explain_policy', arguments: {} }));
show('sentinel_audit_status', await client.callTool({ name: 'sentinel_audit_status', arguments: {} }));

await client.close();
console.log('\nSmoke test completed.');
