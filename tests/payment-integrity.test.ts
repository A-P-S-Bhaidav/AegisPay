import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { Server } from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createAegisServer } from '../server/index';
import { PayPalSandboxGateway } from '../server/paypal';
import { AegisMultiTenantStore } from '../server/store';

const secret = 'payment-integrity-regression-secret-2026';
const credentials = { clientId: 'test-client', clientSecret: 'test-secret', environment: 'sandbox' as const };
const orderInput = {
  ownerTenantId: 'tenant-a', intent: 'CAPTURE' as const, amountCents: 4500,
  merchantName: 'billing@example.com', description: 'Reviewed invoice', customHash: 'review-hash',
  idempotencyKey: 'request-1', pillar: 'SCAMSHIELD' as const, autoExecuteInSandbox: false,
};

describe('PayPal settlement integrity', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('never exposes a checkout order when the PayPal recipient differs from the reviewed recipient', async () => {
    const mock = vi.fn()
      .mockResolvedValueOnce(Response.json({ access_token: 'test-token', expires_in: 3600 }))
      .mockResolvedValueOnce(Response.json({ id: 'ORDER-WRONG-RECIPIENT', status: 'CREATED' }))
      .mockResolvedValueOnce(Response.json({
        id: 'ORDER-WRONG-RECIPIENT', purchase_units: [{
          payee: { email_address: 'wrong@example.com' },
          amount: { currency_code: 'USD', value: '45.00' }, custom_id: orderInput.customHash,
        }],
      }));
    vi.stubGlobal('fetch', mock);
    const gateway = new PayPalSandboxGateway(credentials, secret);
    await expect(gateway.createOrder({ ...orderInput, reviewedPayeeEmail: 'billing@example.com' }))
      .rejects.toThrow('do not match');
    expect(gateway.getOrders('tenant-a')).toHaveLength(0);
  });

  it('verifies the purchase unit before returning a link and the amount before reporting capture', async () => {
    const orderId = 'ORDER-VERIFIED';
    const reviewedOrder = () => Response.json({ id: orderId, purchase_units: [{
      payee: { email_address: 'billing@example.com' }, amount: { currency_code: 'USD', value: '45.00' },
      custom_id: orderInput.customHash,
    }] });
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(Response.json({ access_token: 'test-token', expires_in: 3600 }))
      .mockResolvedValueOnce(Response.json({ id: orderId, status: 'CREATED' }))
      .mockResolvedValueOnce(reviewedOrder())
      .mockResolvedValueOnce(reviewedOrder())
      .mockResolvedValueOnce(Response.json({ id: orderId, status: 'COMPLETED', purchase_units: [{
        payments: { captures: [{ id: 'CAPTURE-WRONG-AMOUNT', status: 'COMPLETED', amount: { currency_code: 'USD', value: '4.50' } }] },
      }] })));
    const gateway = new PayPalSandboxGateway(credentials, secret);
    const order = await gateway.createOrder({ ...orderInput, reviewedPayeeEmail: 'billing@example.com' });
    expect(order.verifiedPayeeEmail).toBe('billing@example.com');
    await expect(gateway.captureLiveOrder(orderId, 'SCAMSHIELD', 'tenant-a')).rejects.toThrow('did not confirm capture');
    expect(order.liveCaptureVerified).toBe(false);
  });

  it('completes a real-mode held payment only through PayPal authorization and exact capture', async () => {
    const orderId = 'HELD-ORDER';
    const amount = { currency_code: 'USD', value: '45.00' };
    const details = () => Response.json({ id: orderId, purchase_units: [{ amount,
      payee: { email_address: 'billing@example.com' }, custom_id: orderInput.customHash,
    }] });
    const mock = vi.fn()
      .mockResolvedValueOnce(Response.json({ access_token: 'test-token', expires_in: 3600 }))
      .mockResolvedValueOnce(Response.json({ id: orderId, status: 'PAYER_ACTION_REQUIRED' }))
      .mockResolvedValueOnce(details())
      .mockResolvedValueOnce(details())
      .mockResolvedValueOnce(Response.json({ id: orderId, purchase_units: [{ payments: {
        authorizations: [{ id: 'AUTH-VERIFIED', status: 'CREATED', amount }],
      } }] }))
      .mockResolvedValueOnce(Response.json({ id: 'CAPTURE-VERIFIED', status: 'COMPLETED', amount }));
    vi.stubGlobal('fetch', mock);
    const gateway = new PayPalSandboxGateway(credentials, secret);
    await gateway.createOrder({ ...orderInput, intent: 'AUTHORIZE', pillar: 'LUPAPERMIT', reviewedPayeeEmail: 'billing@example.com' });
    const result = await gateway.resolveHeldAuthorization({ orderId, ownerTenantId: 'tenant-a', action: 'CAPTURE', operatorNote: 'Approved in test' });
    expect(result.authorizationId).toBe('AUTH-VERIFIED');
    expect(result.captureId).toBe('CAPTURE-VERIFIED');
    expect(result.liveCaptureVerified).toBe(true);
    expect(mock.mock.calls[4][0]).toMatch(/\/authorize$/);
    expect(mock.mock.calls[5][0]).toMatch(/\/authorizations\/AUTH-VERIFIED\/capture$/);
  });

  it('persists real payment ownership across a single instance restart, scoped to its PayPal app', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-payment-restart-'));
    try {
      const options = { rootDir: dir, customFilePath: path.join(dir, 'store.json') };
      const store = new AegisMultiTenantStore(options);
      const gateway = new PayPalSandboxGateway(credentials, secret);
      store.setPayPalStateSource(() => gateway.snapshot());
      vi.stubGlobal('fetch', vi.fn()
        .mockResolvedValueOnce(Response.json({ access_token: 'test-token', expires_in: 3600 }))
        .mockResolvedValueOnce(Response.json({ id: 'PERSISTED-ORDER', status: 'CREATED' })));
      await gateway.createOrder(orderInput);
      await store.flushAsync();
      const reloaded = new AegisMultiTenantStore(options);
      const restored = new PayPalSandboxGateway(credentials, secret, reloaded.getPayPalState());
      expect(restored.getOrder('PERSISTED-ORDER', 'tenant-a')?.status).toBe('CREATED');
      expect(restored.getOrder('PERSISTED-ORDER', 'tenant-b')).toBeUndefined();
      expect(restored.getOrder('PERSISTED-ORDER', 'tenant-a')?.rawPayPalResponse).toBeUndefined();
      const otherApp = new PayPalSandboxGateway({ ...credentials, clientId: 'other-app' }, secret, reloaded.getPayPalState());
      expect(otherApp.getOrders()).toHaveLength(0);
      await reloaded.flushAsync();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('fails closed when configured PayPal authentication is unavailable', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{}', { status: 401 })));
    const gateway = new PayPalSandboxGateway(credentials, secret);
    await expect(gateway.createOrder(orderInput)).rejects.toThrow('authentication');
    expect(gateway.getOrders()).toHaveLength(0);
  });

  it('fails closed when a real PayPal order request is rejected', async () => {
    const mock = vi.fn()
      .mockResolvedValueOnce(Response.json({ access_token: 'test-token', expires_in: 3600 }))
      .mockResolvedValueOnce(new Response('{}', { status: 422 }));
    vi.stubGlobal('fetch', mock);
    const gateway = new PayPalSandboxGateway(credentials, secret);
    await expect(gateway.createOrder(orderInput)).rejects.toThrow('rejected order creation');
    expect(gateway.getOrders()).toHaveLength(0);
  });

  it('requires completed provider capture evidence and preserves unconfirmed order state on failure', async () => {
    const mock = vi.fn()
      .mockResolvedValueOnce(Response.json({ access_token: 'test-token', expires_in: 3600 }))
      .mockResolvedValueOnce(Response.json({ id: 'REAL-ORDER-1', status: 'PAYER_ACTION_REQUIRED' }))
      .mockResolvedValueOnce(new Response('{}', { status: 422 }));
    vi.stubGlobal('fetch', mock);
    const gateway = new PayPalSandboxGateway(credentials, secret);
    const order = await gateway.createOrder({ ...orderInput, autoExecuteInSandbox: true });
    expect(order.status).toBe('CREATED');
    expect(order.captureId).toBeUndefined();
    await expect(gateway.captureLiveOrder(order.orderId, 'SCAMSHIELD', 'tenant-a')).rejects.toThrow('did not confirm capture');
    expect(order.liveCaptureVerified).toBe(false);
    expect(order.settlementStage).toBe('LIVE_PAYER_APPROVAL_READY');
    expect(order.status).toBe('CREATED');
  });

  it('does not capture unknown or foreign orders', async () => {
    const gateway = new PayPalSandboxGateway({ ...credentials, clientId: '', clientSecret: '' }, secret);
    await expect(gateway.captureLiveOrder('UNKNOWN', 'SCAMSHIELD', 'tenant-a')).rejects.toThrow('not found');
    const order = await gateway.createOrder(orderInput);
    await expect(gateway.captureLiveOrder(order.orderId, 'SCAMSHIELD', 'tenant-b')).rejects.toThrow('not found');
  });

  it('isolates public demo requests from configured PayPal credentials', async () => {
    const mock = vi.fn();
    vi.stubGlobal('fetch', mock);
    const gateway = new PayPalSandboxGateway(credentials, secret);
    const order = await gateway.createOrder({ ...orderInput, ownerTenantId: 'OP-DEMO-isolated' });
    expect(order.mode).toBe('CRYPTOGRAPHIC_SANDBOX_EMULATOR');
    expect(gateway.getStatus('OP-DEMO-isolated').publicClientId).toBe('');
    expect(mock).not.toHaveBeenCalled();
  });

  it('deduplicates concurrent order creation and rejects changed parameters on the same key', async () => {
    const gateway = new PayPalSandboxGateway({ ...credentials, clientId: '', clientSecret: '' }, secret);
    const orders = await Promise.all(Array.from({ length: 12 }, () => gateway.createOrder(orderInput)));
    expect(new Set(orders.map((order) => order.orderId)).size).toBe(1);
    expect(gateway.getOrders('tenant-a')).toHaveLength(1);
    await expect(gateway.createOrder({ ...orderInput, amountCents: 9999 })).rejects.toThrow('Idempotency');
  });

  it('rejects oversized and mismatched-capture refunds', async () => {
    const gateway = new PayPalSandboxGateway({ ...credentials, clientId: '', clientSecret: '' }, secret);
    const order = await gateway.createOrder({ ...orderInput, autoExecuteInSandbox: true });
    const refund = { ownerTenantId: 'tenant-a', orderId: order.orderId, captureId: order.captureId!, refundCents: 5000, reasonNote: 'Damage', calculationHash: 'refund' };
    await expect(gateway.issuePartialRefund(refund)).rejects.toThrow('remaining captured amount');
    await expect(gateway.issuePartialRefund({ ...refund, refundCents: 1000, captureId: 'wrong-capture' })).rejects.toThrow('mismatches capture');
    expect(order.refundedCents).toBe(0);
  });

  it('does not seed the publicly known privileged operator outside the test environment', async () => {
    const vaultPath = path.join(os.tmpdir(), `aegis-seed-regression-${crypto.randomUUID()}.json`);
    const previous = process.env.VITEST;
    delete process.env.VITEST;
    try {
      const store = new AegisMultiTenantStore({ rootDir: os.tmpdir(), customFilePath: vaultPath });
      expect(store.getUserByEmail('operator@aegispay.io')).toBeUndefined();
      await store.flushAsync();
    } finally {
      if (previous !== undefined) process.env.VITEST = previous;
      fs.rmSync(vaultPath, { force: true });
    }
  });
});

describe('HTTP payment authorization regressions', () => {
  let server: Server;
  let app: ReturnType<typeof createAegisServer>;
  let base = '';
  let headers: Record<string, string>;
  const vaultPath = path.join(os.tmpdir(), `aegis-payment-http-${crypto.randomUUID()}.json`);
  const post = (route: string, body: unknown, customHeaders = headers) => fetch(`${base}${route}`, { method: 'POST', headers: customHeaders, body: JSON.stringify(body) });

  beforeAll(async () => {
    app = createAegisServer({ customStoreFilePath: vaultPath });
    await new Promise<void>((resolve, reject) => {
      server = app.listen(0, '127.0.0.1', () => resolve());
      server.once('error', reject);
    });
    const address = server.address();
    if (address && typeof address === 'object') base = `http://127.0.0.1:${address.port}`;
    const demo = await (await post('/api/auth/demo', {}, { 'Content-Type': 'application/json' })).json();
    headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${demo.token}` };
  });
  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await (app as unknown as { flushStoreAsync: () => Promise<void> }).flushStoreAsync();
    fs.rmSync(vaultPath, { force: true });
  });

  it('creates independent demo tenants and exposes deterministic provider mode', async () => {
    const first = await (await fetch(`${base}/api/state`, { headers })).json();
    const second = await (await post('/api/auth/demo', {}, { 'Content-Type': 'application/json' })).json();
    expect(first.workspace.tenantId).not.toBe(second.operator.id);
    expect(first.system.paypal.activeMode).toBe('CRYPTOGRAPHIC_SANDBOX_EMULATOR');
    expect(first.system.gemini.hasLiveGeminiKey).toBe(false);
    expect(first.system.gemini.hasLiveGroqKey).toBe(false);
  });

  it('rejects unauthenticated MCP tools/call while keeping discovery public', async () => {
    const response = await post('/api/mcp', { method: 'tools/call', params: { name: 'aegispay_list_permits' } }, { 'Content-Type': 'application/json' });
    expect(response.status).toBe(401);
    expect((await response.json()).error.code).toBe(-32001);
  });

  it('rejects forged checkout tokens and capture requests without a reviewed order', async () => {
    const forged = { payload: { tokenId: 'forged', amountCents: 1, currency: 'USD', payeeIdentifier: 'attacker@example.com', verdict: 'ALLOW' }, signature: 'fake' };
    expect((await post('/api/scamshield/create-paypal-order', { signedToken: forged })).status).toBe(403);
    expect((await post('/api/scamshield/capture-paypal-order', { orderId: 'arbitrary' })).status).toBe(403);
  });

  it('binds a review to its exact order and deduplicates repeated checkout creation', async () => {
    const review = await (await post('/api/scamshield/review', { rawText: 'Invoice for web hosting $45.00 USD', claimedAmountCents: 4500, currency: 'USD', payeeIdentifier: 'billing@example.com' })).json();
    const payload = { signedToken: review.signedToken };
    const results = await Promise.all([post('/api/scamshield/create-paypal-order', payload), post('/api/scamshield/create-paypal-order', payload)]);
    const orders = await Promise.all(results.map((response) => response.json()));
    expect(orders[0].orderId).toBe(orders[1].orderId);
    const capture = await post('/api/scamshield/capture-paypal-order', { ...payload, orderId: orders[0].orderId });
    expect(capture.status).toBe(200);
    expect((await capture.json()).mode).toBe('CRYPTOGRAPHIC_SANDBOX_EMULATOR');
    const replay = await post('/api/scamshield/capture-paypal-order', { ...payload, orderId: orders[0].orderId });
    expect(replay.status).toBe(403);
  });

  it('serializes simultaneous same-photo refund claims and rejects a real replay', async () => {
    const body = { presetId: 'chipped_ceramic_mug', originalOrderCents: 2800, imageBase64: Buffer.from('identical-image-content-regression').toString('base64'), imageMimeType: 'image/png' };
    const responses = await Promise.all([post('/api/cliprefund/evaluate-and-refund', body), post('/api/cliprefund/evaluate-and-refund', body)]);
    const results = await Promise.all(responses.map((response) => response.json()));
    expect(results.filter((result) => result.calculation.approved)).toHaveLength(1);
    expect(results.filter((result) => result.paypalRefund)).toHaveLength(1);
    expect(results[0].imageSha256).toBe(results[1].imageSha256);
  });

  it('rejects forged recovery settlement feedback and never updates the learner', async () => {
    const recovery = await (await post('/api/payrevive/recover', { presetId: 'PAYDAY_LIQUIDITY', executeLivePayPal: false })).json();
    const confirm = await post('/api/payrevive/confirm-settlement', { decisionId: recovery.decision.decisionId, settled: true });
    expect(confirm.status).toBe(409);
    expect((await confirm.json()).updated).toBe(false);
  });
});
