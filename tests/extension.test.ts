import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import vm from 'node:vm';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { Server } from 'node:http';
import { createAegisServer } from '../server/index';

const workerSource = fs.readFileSync(new URL('../extension/service-worker.js', import.meta.url), 'utf8');
const manifest = JSON.parse(fs.readFileSync(new URL('../extension/manifest.json', import.meta.url), 'utf8'));

function makeWorker(base: string, fetchImpl: typeof fetch = fetch) {
  let listener: (message: unknown, sender: unknown, respond: (data: any) => void) => boolean;
  const local: Record<string, any> = { apiBaseUrl: base };
  const session: Record<string, any> = {};
  const storage = (values: Record<string, any>) => ({
    get: async (keys: string | string[]) => Object.fromEntries(
      (Array.isArray(keys) ? keys : [keys]).map((key) => [key, structuredClone(values[key])]),
    ),
    set: async (data: Record<string, any>) => Object.assign(values, structuredClone(data)),
    remove: async (key: string) => { delete values[key]; },
  });
  const context = vm.createContext({
    fetch: fetchImpl, AbortSignal, console, setTimeout, clearTimeout,
    chrome: {
      runtime: { onInstalled: { addListener: () => {} }, onMessage: { addListener: (fn: typeof listener) => { listener = fn; } } },
      contextMenus: { onClicked: { addListener: () => {} } },
      storage: { local: storage(local), session: storage(session) },
      action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {} },
    },
  });
  vm.runInContext(workerSource, context, { filename: 'extension/service-worker.js' });
  return {
    local, session,
    call: (message: unknown) => new Promise<any>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Extension response timed out')), 10000);
      listener(message, { id: 'test-extension' }, (result) => { clearTimeout(timer); resolve(result); });
    }),
  };
}

describe('Manifest V3 worker against the actual HTTP API', () => {
  let server: Server;
  let base = '';
  const storePath = path.join(os.tmpdir(), `aegispay-extension-${process.pid}.store.json`);
  beforeAll(async () => {
    const app = createAegisServer({ customStoreFilePath: storePath });
    await new Promise<void>((resolve) => { server = app.listen(0, '127.0.0.1', () => resolve()); });
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('No test server address');
    // The shipped extension allows localhost:8787 only; remap that selected URL to this isolated test server.
    base = `http://127.0.0.1:${address.port}`;
  });
  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(storePath, { force: true });
  });
  const makeConnectedWorker = () => makeWorker('http://localhost:8787', ((url, init) =>
    fetch(String(url).replace('http://localhost:8787', base), init)) as typeof fetch);
  const signIn = (worker: ReturnType<typeof makeWorker>) => worker.call({
    type: 'AEGISPAY_SIGN_IN', payload: { email: 'operator@aegispay.io', password: 'AegisPay2026!' },
  });

  it('requests only user-initiated tab access and the two explicit API origins', () => {
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.permissions).toContain('activeTab');
    expect(manifest.host_permissions).toEqual(['http://localhost:8787/*', 'https://aegispay-orpin.vercel.app/*']);
    expect(manifest.host_permissions).not.toContain('<all_urls>');
    new vm.Script(fs.readFileSync(new URL('../extension/sidepanel.js', import.meta.url), 'utf8'));
  });

  it('refuses unauthenticated scans without creating an implicit account or sending data', async () => {
    let requests = 0;
    const worker = makeWorker('http://localhost:8787', (async () => { requests++; throw new Error('Unexpected network request'); }) as typeof fetch);
    const result = await worker.call({ type: 'AEGISPAY_RUN_REVIEW', payload: { rawText: 'private invoice' } });
    expect(result.ok).toBe(false);
    expect(result.error).toContain('Sign in');
    expect(requests).toBe(0);
  });

  it('signs in explicitly and stores only a session token and email, never the password', async () => {
    const worker = makeConnectedWorker();
    expect((await signIn(worker)).ok).toBe(true);
    expect((await worker.call({ type: 'AEGISPAY_AUTH_STATUS' })).authenticated).toBe(true);
    expect(JSON.stringify(worker.local)).not.toContain('AegisPay2026!');
    expect(JSON.stringify(worker.session)).not.toContain('AegisPay2026!');
    expect(worker.session.accountTokenMap['http://localhost:8787'].token).toBeTruthy();
  });

  it('uses current review and checkout API contracts end to end', async () => {
    const worker = makeConnectedWorker();
    await signIn(worker);
    const review = await worker.call({ type: 'AEGISPAY_RUN_REVIEW', payload: {
      rawText: 'Invoice for completed design work, $45 USD via PayPal Goods and Services.',
      claimedAmountCents: 4500, currency: 'USD', payeeIdentifier: 'billing@example.com',
    } });
    expect(review.ok).toBe(true);
    expect(review.data.finalVerdict).toBe('ALLOW');
    expect(review.data.signedToken.payload.amountCents).toBe(4500);
    const order = await worker.call({ type: 'AEGISPAY_CREATE_PAYPAL_ORDER', payload: { signedToken: review.data.signedToken } });
    expect(order.ok).toBe(true);
    expect(order.data.orderId).toBeTruthy();
    expect(order.endpointUsed).toBe('http://localhost:8787');
    const capture = await worker.call({ type: 'AEGISPAY_CAPTURE_PAYPAL_ORDER', payload: {
      signedToken: review.data.signedToken, orderId: order.data.orderId,
    } });
    expect(capture.ok).toBe(true);
    expect(capture.data.mode).toBe('CRYPTOGRAPHIC_SANDBOX_EMULATOR');
    expect(capture.data.captured).toBe(true);
  });

  it('rejects bad credentials and leaves the extension signed out', async () => {
    const worker = makeConnectedWorker();
    const result = await worker.call({ type: 'AEGISPAY_SIGN_IN', payload: { email: 'operator@aegispay.io', password: 'wrong-password' } });
    expect(result.ok).toBe(false);
    expect((await worker.call({ type: 'AEGISPAY_AUTH_STATUS' })).authenticated).toBe(false);
  });

  it('clears an expired bearer and does not silently retry with demo authentication', async () => {
    const worker = makeConnectedWorker();
    worker.session.accountTokenMap = { 'http://localhost:8787': { token: 'expired', email: 'test@example.com' } };
    const result = await worker.call({ type: 'AEGISPAY_RUN_REVIEW', payload: {} });
    expect(result.ok).toBe(false);
    expect(result.error).toContain('expired');
    expect((await worker.call({ type: 'AEGISPAY_AUTH_STATUS' })).authenticated).toBe(false);
  });

  it('never transmits page text to an unapproved endpoint or a remote failover host', async () => {
    const requests: string[] = [];
    const worker = makeWorker('https://attacker.example', (async (url) => {
      requests.push(String(url)); throw new Error('unexpected network');
    }) as typeof fetch);
    expect((await worker.call({ type: 'AEGISPAY_RUN_REVIEW', payload: { rawText: 'private' } })).ok).toBe(false);
    expect(requests).toEqual([]);
    worker.local.apiBaseUrl = 'http://localhost:8787';
    worker.session.accountTokenMap = { 'http://localhost:8787': { token: 'private-token', email: 'test@example.com' } };
    expect((await worker.call({ type: 'AEGISPAY_RUN_REVIEW', payload: {} })).ok).toBe(false);
    expect(requests).toEqual(['http://localhost:8787/api/scamshield/review']);
  });

  it('signs out and revokes the selected endpoint session', async () => {
    const worker = makeConnectedWorker();
    await signIn(worker);
    expect((await worker.call({ type: 'AEGISPAY_SIGN_OUT' })).ok).toBe(true);
    expect((await worker.call({ type: 'AEGISPAY_AUTH_STATUS' })).authenticated).toBe(false);
  });
});
