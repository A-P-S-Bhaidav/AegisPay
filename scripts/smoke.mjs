#!/usr/bin/env node
/**
 * Post-deploy smoke test. Usage: node scripts/smoke.mjs <baseUrl>
 * Exercises the live deployment the way a first-time visitor would and exits non-zero
 * on the first broken contract, so CI/CD can fail loudly instead of shipping silently.
 */
const base = (process.argv[2] || process.env.BASE_URL || '').replace(/\/$/, '');
if (!/^https?:\/\//.test(base)) {
  console.error('Usage: node scripts/smoke.mjs <baseUrl>');
  process.exit(2);
}

let failures = 0;
const check = async (name, fn) => {
  try {
    const detail = await fn();
    console.log(`PASS  ${name}${detail ? `  (${detail})` : ''}`);
  } catch (err) {
    failures += 1;
    console.error(`FAIL  ${name}  -> ${err.message}`);
  }
};
const must = (cond, msg) => {
  if (!cond) throw new Error(msg);
};

let headers = { 'Content-Type': 'application/json', 'X-Requested-With': 'AegisPay-Client' };

await check('health endpoint responds 200', async () => {
  const res = await fetch(`${base}/api/health`);
  must(res.status === 200, `status ${res.status}`);
});

await check('landing page serves the app shell', async () => {
  const res = await fetch(base);
  const html = await res.text();
  must(res.status === 200 && html.includes('<div id="root"'), 'no React root in HTML');
});

await check('one-click demo workspace issues a session', async () => {
  const res = await fetch(`${base}/api/auth/demo`, { method: 'POST', headers });
  must(res.status === 200, `status ${res.status}`);
  const data = await res.json();
  must(data.authenticated && data.token, 'no token returned');
  headers = { ...headers, Authorization: `Bearer ${data.token}` };
});

await check('authenticated state loads with tenant workspace', async () => {
  const res = await fetch(`${base}/api/state`, { headers });
  must(res.status === 200, `status ${res.status}`);
  const data = await res.json();
  must(data.workspace?.tenantId, 'missing tenantId');
  return data.workspace.tenantId;
});

await check('MCP server advertises all 13 tools', async () => {
  const res = await fetch(`${base}/api/mcp`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  });
  const data = await res.json();
  must(data.result?.tools?.length === 13, `got ${data.result?.tools?.length} tools`);
});

await check('universal agent routes a cashflow question', async () => {
  const res = await fetch(`${base}/api/agent/ingest`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ rawText: 'Can I afford a $420 chair with my checking balance?' }),
  });
  const data = await res.json();
  must(data.detectedWorkflow === 'CASHFLOW_CHECK', `routed to ${data.detectedWorkflow}`);
});

await check('refund without a damage photo is rejected (compulsory evidence)', async () => {
  const res = await fetch(`${base}/api/cliprefund/evaluate-and-refund`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ naturalDescription: 'chipped mug $30', requirePhotoEvidence: true }),
  });
  must(res.status === 400, `expected 400, got ${res.status}`);
});

await check('Chrome extension downloads as a valid ZIP', async () => {
  const res = await fetch(`${base}/api/download/extension`);
  const buf = Buffer.from(await res.arrayBuffer());
  must(res.status === 200, `status ${res.status}`);
  must(buf.subarray(0, 2).toString() === 'PK', 'not a ZIP (missing PK header)');
  return `${buf.length} bytes`;
});

console.log(failures === 0 ? '\nSMOKE OK' : `\nSMOKE FAILED (${failures})`);
process.exit(failures === 0 ? 0 : 1);
