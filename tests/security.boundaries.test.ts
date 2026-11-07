import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { Server } from 'node:http';
import { PayPalSandboxGateway, type PayPalOrderRecord } from '../server/paypal';
import { createAegisServer } from '../server/index';

const gateway = () => new PayPalSandboxGateway({
  clientId: 'test-client', clientSecret: 'test-secret', webhookId: 'test-webhook', environment: 'sandbox',
}, 'test-only-boundary-kernel-secret');

function providerMock(cancelStatus = 204) {
  return vi.fn(async (input: string | URL | Request) => {
    const url = String(input);
    if (url.endsWith('/v1/oauth2/token')) return Response.json({ access_token: 'test-provider-token', expires_in: 3600 });
    if (url.endsWith('/generate-next-invoice-number')) return Response.json({ invoice_number: 'TEST-1' });
    if (url.endsWith('/v2/invoicing/invoices')) return Response.json({ id: 'INV2-OWNED', href: 'https://api-m.sandbox.paypal.com/v2/invoicing/invoices/INV2-OWNED' });
    if (url.endsWith('/v2/invoicing/invoices/INV2-OWNED')) return Response.json({ id: 'INV2-OWNED', status: 'SENT', amount: { value: '25.00', currency_code: 'USD' } });
    if (url.endsWith('/v1/catalogs/products')) return Response.json({ id: 'PROD-OWNED' });
    if (url.endsWith('/v1/billing/plans')) return Response.json({ id: 'P-OWNED' });
    if (url.endsWith('/v1/billing/subscriptions')) return Response.json({ id: 'I-OWNED', status: 'APPROVAL_PENDING' });
    if (url.endsWith('/v1/billing/subscriptions/I-OWNED')) return Response.json({ id: 'I-OWNED', status: 'ACTIVE' });
    if (url.endsWith('/I-OWNED/cancel')) return new Response(null, { status: cancelStatus });
    if (url.endsWith('/verify-webhook-signature')) return Response.json({ verification_status: 'SUCCESS' });
    throw new Error(`Unexpected provider call: ${url}`);
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe('PayPal tenant boundaries', () => {
  it('rejects unknown and foreign invoice lookups before any provider request', async () => {
    const mock = providerMock();
    vi.stubGlobal('fetch', mock);
    const paypal = gateway();
    await paypal.createLiveInvoice({ ownerTenantId: 'tenant-a', title: 'Work', note: '', recipientEmail: 'buyer@example.test', amountCents: 2500, pillar: 'PAYSTREAM', contractOrPlanHash: 'plan-hash', sendImmediately: false });
    mock.mockClear();
    expect((await paypal.lookupLiveInvoice('INV2-OWNED', 'tenant-b')).found).toBe(false);
    expect((await paypal.lookupLiveInvoice('INV2-UNKNOWN', 'tenant-a')).found).toBe(false);
    expect((await paypal.lookupLiveInvoice('INV2-OWNED')).found).toBe(false);
    expect(mock).not.toHaveBeenCalled();
    expect((await paypal.lookupLiveInvoice('INV2-OWNED', 'tenant-a')).amountValue).toBe('25.00');
    expect(mock).toHaveBeenCalledTimes(1);
  });

  it('requires subscription ownership and never treats provider rejection as cancellation', async () => {
    const mock = providerMock(422);
    vi.stubGlobal('fetch', mock);
    const paypal = gateway();
    await paypal.createLiveSubscription({ ownerTenantId: 'tenant-a', planName: 'Service', monthlyPriceCents: 2500, pillar: 'LUPAPERMIT' });
    mock.mockClear();
    await expect(paypal.cancelLiveSubscription({ ownerTenantId: 'tenant-b', subscriptionId: 'I-OWNED' })).rejects.toThrow('not found');
    await expect(paypal.cancelLiveSubscription({ ownerTenantId: 'tenant-a', subscriptionId: 'I-UNKNOWN' })).rejects.toThrow('not found');
    expect(mock).not.toHaveBeenCalled();
    await expect(paypal.cancelLiveSubscription({ ownerTenantId: 'tenant-a', subscriptionId: 'I-OWNED' })).rejects.toThrow('rejected');
    expect(paypal.getSubscriptions('tenant-a')[0].status).toBe('APPROVAL_PENDING');
  });

  it('cancels an owned subscription once and reuses confirmed cancellation', async () => {
    const mock = providerMock();
    vi.stubGlobal('fetch', mock);
    const paypal = gateway();
    await paypal.createLiveSubscription({ ownerTenantId: 'tenant-a', planName: 'Service', monthlyPriceCents: 2500, pillar: 'LUPAPERMIT' });
    mock.mockClear();
    const request = { ownerTenantId: 'tenant-a', subscriptionId: 'I-OWNED' };
    expect((await paypal.cancelLiveSubscription(request)).cancelled).toBe(true);
    expect((await paypal.cancelLiveSubscription(request)).cancelled).toBe(true);
    expect(mock).toHaveBeenCalledTimes(1);
  });

  it('subscription discovery refreshes only bound tenant records without creating subscriptions', async () => {
    const mock = providerMock();
    vi.stubGlobal('fetch', mock);
    const paypal = gateway();
    expect((await paypal.discoverRecurringFromPayPalSandbox('tenant-a')).discovered).toEqual([]);
    expect(mock).not.toHaveBeenCalled();
    await paypal.createLiveSubscription({ ownerTenantId: 'tenant-a', planName: 'Service', monthlyPriceCents: 2500, pillar: 'LUPAPERMIT' });
    mock.mockClear();
    expect((await paypal.discoverRecurringFromPayPalSandbox('tenant-a')).discovered.map((s) => s.agreementId)).toEqual(['I-OWNED']);
    expect(paypal.getSubscriptions('tenant-a')[0].status).toBe('ACTIVE');
    expect(mock).toHaveBeenCalledTimes(1);
    expect(String(mock.mock.calls[0][0])).toBe('https://api-m.sandbox.paypal.com/v1/billing/subscriptions/I-OWNED');
    mock.mockClear();
    expect((await paypal.discoverRecurringFromPayPalSandbox('tenant-b')).discovered).toEqual([]);
    expect(paypal.getSubscriptions('tenant-b')).toEqual([]);
    expect(mock).not.toHaveBeenCalled();
  });

  it('attributes verified provider webhooks to stored resources and hides unmatched events', async () => {
    vi.stubGlobal('fetch', providerMock());
    const paypal = gateway();
    const order: PayPalOrderRecord = {
      orderId: 'ORDER-A', ownerTenantId: 'tenant-a', intent: 'CAPTURE', status: 'COMPLETED', paypalServerStatus: 'COMPLETED', settlementStage: 'LIVE_BUYER_CAPTURED', amountCents: 2500, refundedCents: 0, currency: 'USD', merchantName: 'Test merchant', description: '', customHash: 'test-order-hash', captureId: 'CAPTURE-A', liveCaptureVerified: true, approvalUrl: '', buyerCheckoutReady: false, mode: 'LIVE_PAYPAL_SANDBOX_API', createdAtIso: new Date().toISOString(), updatedAtIso: new Date().toISOString(),
    };
    paypal.seedInitialOrder(order);
    const headers = { 'paypal-transmission-id': 'test-tx', 'paypal-transmission-time': new Date().toISOString(), 'paypal-transmission-sig': 'test-provider-signature', 'paypal-cert-url': 'https://api.sandbox.paypal.com/cert/test', 'paypal-auth-algo': 'SHA256withRSA' };
    const matched = await paypal.verifyAndIngestExternalWebhook({ headers, body: { id: 'WH-TEST', ownerTenantId: 'tenant-b', event_type: 'PAYMENT.CAPTURE.COMPLETED', resource: { id: 'CAPTURE-A', supplementary_data: { related_ids: { order_id: 'ORDER-A' } } } } });
    expect(matched.verified).toBe(true);
    expect(matched.event?.ownerTenantId).toBe('tenant-a');
    expect(paypal.getWebhookStream('tenant-a')).toHaveLength(1);
    expect(paypal.getWebhookStream('tenant-b')).toEqual([]);
    const unmatched = await paypal.verifyAndIngestExternalWebhook({ headers, body: { id: 'WH-UNKNOWN', event_type: 'PAYMENT.CAPTURE.COMPLETED', resource: { id: 'CAPTURE-UNKNOWN' } } });
    expect(unmatched.verified).toBe(true);
    expect(unmatched.event?.ownerTenantId).toBe('TNT-UNMATCHED');
    expect(paypal.getWebhookStream('tenant-a')).toHaveLength(1);
    expect(paypal.getWebhookStream('tenant-b')).toEqual([]);
  });
});

describe('Google identity verification', () => {
  async function withServer(callback: (url: string) => Promise<void>) {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'aegis-boundary-test-'));
    const app = createAegisServer({ customStoreFilePath: path.join(directory, 'store.json') });
    let server: Server | undefined;
    try {
      server = await new Promise<Server>((resolve, reject) => {
        const listening = app.listen(0, '127.0.0.1', () => resolve(listening));
        listening.once('error', reject);
      });
      const address = server.address();
      if (!address || typeof address === 'string') throw new Error('Missing test server address');
      await callback(`http://127.0.0.1:${address.port}`);
    } finally {
      if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
      await (app as typeof app & { flushStoreAsync: () => Promise<void> }).flushStoreAsync();
      await rm(directory, { recursive: true, force: true });
    }
  }

  it('rejects token sign-in when no Google audience is configured', async () => {
    vi.stubEnv('GOOGLE_CLIENT_ID', '');
    await withServer(async (url) => {
      const response = await fetch(`${url}/api/auth/google`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ idToken: 'test.token.signature' }) });
      expect(response.status).toBe(503);
      expect(response.headers.get('set-cookie')).toBeNull();
    });
  });

  it('rejects a Google token issued for a different client audience', async () => {
    vi.stubEnv('GOOGLE_CLIENT_ID', 'expected-client');
    const realFetch = fetch;
    vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      if (String(input).startsWith('https://oauth2.googleapis.com/tokeninfo')) return Response.json({ aud: 'foreign-client', email: 'owner@example.test', email_verified: true });
      return realFetch(input, init);
    }));
    await withServer(async (url) => {
      const response = await fetch(`${url}/api/auth/google`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ idToken: 'test.token.signature' }) });
      expect(response.status).toBe(401);
      expect(response.headers.get('set-cookie')).toBeNull();
    });
  });

  it('requires a positive verified-email claim in the OAuth callback', async () => {
    vi.stubEnv('GOOGLE_CLIENT_ID', 'expected-client');
    vi.stubEnv('GOOGLE_CLIENT_SECRET', 'test-client-secret');
    const realFetch = fetch;
    vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      if (String(input) === 'https://oauth2.googleapis.com/token') return Response.json({ access_token: 'test-google-token' });
      if (String(input) === 'https://www.googleapis.com/oauth2/v3/userinfo') return Response.json({ email: 'unverified@example.test' });
      return realFetch(input, init);
    }));
    await withServer(async (url) => {
      const start = await fetch(`${url}/api/auth/google/url`);
      const data = await start.json();
      const state = new URL(data.authUrl).searchParams.get('state')!;
      const cookie = start.headers.get('set-cookie')!.split(';')[0];
      const response = await fetch(`${url}/api/auth/google/callback?code=test-code&state=${encodeURIComponent(state)}`, { headers: { Cookie: cookie }, redirect: 'manual' });
      expect(response.status).toBe(302);
      expect(response.headers.get('location')).toBe('/?auth_error=oauth_email_unverified');
      expect(response.headers.get('set-cookie')).not.toContain('aegis_session=');
    });
  });
});
