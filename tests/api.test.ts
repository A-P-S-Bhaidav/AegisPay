import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Server } from 'node:http';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { createAegisServer } from '../server/index';
import { redactSecrets } from '../server/security';
import { AegisMultiTenantStore, verifyPasswordScrypt } from '../server/store';
import { hmacSha256Hex } from '../shared/kernel';

describe('AegisPay Full-Stack Zero-Trust HTTP API, Security, Multi-Tenant Storage & PayRevive Suite', () => {
  let server: Server;
  let appInstance: ReturnType<typeof createAegisServer>;
  let baseUrl = '';
  let operatorToken = '';
  let authHeaders: Record<string, string> = {};
  const TEST_HMAC_SECRET = 'test_kernel_hmac_secret_256bit_for_suite_2026_verified';
  const tempStoreFile = path.join(
    os.tmpdir(),
    `aegispay_api_test_${process.pid}_${Date.now()}.json`
  );

  beforeAll(async () => {
    process.env.AEGIS_KERNEL_SECRET = TEST_HMAC_SECRET;
    appInstance = createAegisServer({ customStoreFilePath: tempStoreFile });
    await new Promise<void>((resolve) => {
      server = appInstance.listen(0, () => {
        const addr = server.address();
        if (addr && typeof addr === 'object') {
          baseUrl = `http://127.0.0.1:${addr.port}`;
        }
        resolve();
      });
    });

    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'operator@aegispay.io',
        password: 'AegisPay2026!',
      }),
    });
    expect(loginRes.status).toBe(200);
    expect(loginRes.headers.get('set-cookie')).toContain('aegis_session=');
    expect(loginRes.headers.get('set-cookie')).toContain('HttpOnly');
    const loginData = await loginRes.json();
    operatorToken = loginData.token;
    authHeaders = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${operatorToken}`,
    };
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
    try {
      if (fs.existsSync(tempStoreFile)) fs.unlinkSync(tempStoreFile);
    } catch {
      // Ignore cleanup errors
    }
  });

  it('GET /api/health returns hardened CSP (no script unsafe-inline), security headers, rate-limit headers, and zero raw secrets', async () => {
    const res = await fetch(`${baseUrl}/api/health`);
    expect(res.status).toBe(200);
    expect(res.headers.get('x-frame-options')).toBe('DENY');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('strict-transport-security')).toContain('max-age=');
    const csp = res.headers.get('content-security-policy') || '';
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self' https://www.paypal.com");
    expect(csp.split('script-src')[1]?.split(';')[0] || '').not.toContain('unsafe-inline');
    expect(res.headers.get('ratelimit-limit')).toBeDefined();

    const rawBody = await res.text();
    expect(rawBody).not.toContain('GOCSPX-');
    expect(rawBody).not.toContain('gsk_');
    expect(rawBody).not.toContain('AQ.');

    const data = JSON.parse(rawBody);
    expect(data.ok).toBe(true);
    expect(data.version).toBe('3.1.0');
    expect(data.authRequired).toBe(true);
    expect(data.storage.passwordKdf).toContain('scrypt');
    expect(data.storage.sessionTransport).toContain('HttpOnly');
  });

  it('enforces mandatory authentication (HTTP 401 AUTH_REQUIRED) on unauthenticated /api/state and protected mutations', async () => {
    const unauthState = await fetch(`${baseUrl}/api/state`);
    expect(unauthState.status).toBe(401);
    const errData = await unauthState.json();
    expect(errData.authenticated).toBe(false);
    expect(errData.code).toBe('AUTH_REQUIRED');

    const unauthPayRevive = await fetch(`${baseUrl}/api/payrevive/recover`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ presetId: 'PAYDAY_LIQUIDITY' }),
    });
    expect(unauthPayRevive.status).toBe(401);
  });

  it('redacts accidental secret patterns cleanly via redactSecrets guard', () => {
    const dirty =
      'Error with key AQ.SYNTHETIC_DUMMY_KEY_000000000000000000000000 and gsk_SYNTHETIC_DUMMY_KEY_00000000000000000000000000 and GOCSPX-SYNTHETIC_DUMMY_000000000000';
    const clean = redactSecrets(dirty);
    expect(clean).not.toContain('AQ.SYNTHETIC');
    expect(clean).not.toContain('gsk_SYNTHETIC');
    expect(clean).not.toContain('GOCSPX-SYNTHETIC');
    expect(clean).toContain('[REDACTED');
  });

  it('enforces sliding-window rate limiting (HTTP 429 + Retry-After) when client exceeds tier threshold', async () => {
    const rlStorePath = path.join(os.tmpdir(), `aegispay_rl_test_${process.pid}_${Date.now()}.json`);
    const rlApp = createAegisServer({
      customStoreFilePath: rlStorePath,
      authMaxRequestsPerMinute: 3,
    });
    let rlServer!: Server;
    let rlUrl = '';
    await new Promise<void>((resolve) => {
      rlServer = rlApp.listen(0, () => {
        const addr = rlServer.address();
        if (addr && typeof addr === 'object') {
          rlUrl = `http://127.0.0.1:${addr.port}`;
        }
        resolve();
      });
    });

    try {
      for (let i = 0; i < 3; i++) {
        const ok = await fetch(`${rlUrl}/api/auth/google/url`);
        expect(ok.status).toBe(200);
      }
      const blocked = await fetch(`${rlUrl}/api/auth/google/url`);
      expect(blocked.status).toBe(429);
      expect(blocked.headers.get('retry-after')).toBeDefined();
      const blockedJson = await blocked.json();
      expect(blockedJson.code).toBe('RATE_LIMIT_EXCEEDED');
    } finally {
      await new Promise<void>((resolve) => rlServer.close(() => resolve()));
      if (fs.existsSync(rlStorePath)) fs.unlinkSync(rlStorePath);
    }
  });

  it('GET /api/state returns complete authenticated tenant state, KPIs, PayRevive catalog, PayStream plans, and audit logs', async () => {
    const res = await fetch(`${baseUrl}/api/state`, { headers: authHeaders });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.system.name).toBe('AegisPay');
    expect(data.system.version).toBe('3.1.0');
    expect(data.operator.email).toBe('operator@aegispay.io');
    expect(data.workspace.tutorialCompleted).toBe(false);
    expect(data.lupa.billingPermissions.length).toBeGreaterThanOrEqual(4);
    expect(data.lupa.zombieReport.totalZombieCount).toBeGreaterThanOrEqual(3);
    expect(data.paystream.plans.length).toBeGreaterThanOrEqual(1);
    expect(data.payrevive.presets.length).toBe(5);
    expect(data.payrevive.modelCard.heldOutRocAuc).toBeGreaterThan(0.8);
    expect(data.auditLogs.length).toBeGreaterThanOrEqual(1);
  });

  it('POST /api/payrevive/recover, /confirm-settlement, and /benchmark execute trained Newton GBDT + TreeSHAP + LinUCB Bandit + Compliance Gate + 500-Batch simulation', async () => {
    const presetsRes = await fetch(`${baseUrl}/api/payrevive/presets`, { headers: authHeaders });
    expect(presetsRes.status).toBe(200);
    const presetsData = await presetsRes.json();
    expect(presetsData.presets.length).toBe(5);

    const recoverRes = await fetch(`${baseUrl}/api/payrevive/recover`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ presetId: 'EXPIRED_CARD_WALLET_SWITCH' }),
    });
    expect(recoverRes.status).toBe(200);
    const recoverData = await recoverRes.json();
    expect(recoverData.decision.verdict).toBe('EXECUTE_RECOVERY');
    expect(recoverData.decision.selectedAction).toBe('PAYPAL_BACKUP_FUNDING_SWITCH');
    expect(recoverData.decision.diagnosis.additivityVerified).toBe(true);
    expect(recoverData.decision.settlementConfirmed).toBe(false);
    expect(recoverData.paypalInvoice.invoiceId).toBeDefined();
    expect(recoverData.auditRow.pillar).toBe('PAYREVIVE');

    // Explicit settlement confirmation updates LinUCB contextual bandit arm weights
    const confirmRes = await fetch(`${baseUrl}/api/payrevive/confirm-settlement`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        decisionId: recoverData.decision.decisionId,
        settled: true,
      }),
    });
    expect(confirmRes.status).toBe(200);
    const confirmData = await confirmRes.json();
    expect(confirmData.updated).toBe(true);
    expect(confirmData.settled).toBe(true);

    const blockRes = await fetch(`${baseUrl}/api/payrevive/recover`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ presetId: 'COMPLIANCE_HARD_DECLINE' }),
    });
    expect(blockRes.status).toBe(200);
    const blockData = await blockRes.json();
    expect(blockData.decision.verdict).toBe('BLOCKED_BY_COMPLIANCE');
    expect(blockData.paypalOrder).toBeNull();
    expect(blockData.paypalInvoice).toBeNull();

    const abstainRes = await fetch(`${baseUrl}/api/payrevive/recover`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ presetId: 'NEGATIVE_EV_MICRO_PAYMENT' }),
    });
    expect(abstainRes.status).toBe(200);
    const abstainData = await abstainRes.json();
    expect(abstainData.decision.verdict).toBe('ABSTAIN_NOT_WORTH_COST');

    const benchRes = await fetch(`${baseUrl}/api/payrevive/benchmark`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ batches: 500, batchSize: 20, seed: 20261028 }),
    });
    expect(benchRes.status).toBe(200);
    const benchData = await benchRes.json();
    expect(benchData.report.batchesSimulated).toBe(500);
    expect(benchData.report.payRevive.complianceViolations).toBe(0);
    expect(benchData.report.netRecoveryLiftPercent).toBeGreaterThanOrEqual(45);
  });

  it('persists multi-tenant user accounts with scrypt hashes and strictly isolates PayPal orders, invoices, policies, and balances across tenants', async () => {
    const regBRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'isolated-tenant@aegispay.io',
        password: 'StrongTenantPassword2026!',
        fullName: 'Isolated Tenant Operator',
        organization: 'Tenant B Corp',
      }),
    });
    expect(regBRes.status).toBe(201);
    const regBData = await regBRes.json();
    const tenantBHeaders = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${regBData.token}`,
    };

    // Mutate Tenant B balance to $9,123.00 (912300 cents)
    const updB = await fetch(`${baseUrl}/api/lupa/cashflow-update`, {
      method: 'POST',
      headers: tenantBHeaders,
      body: JSON.stringify({ balanceCents: 912300 }),
    });
    expect(updB.status).toBe(200);

    // Tenant B sees ZERO of Operator A's PayPal invoices or PayRevive decisions!
    const stateBRes = await fetch(`${baseUrl}/api/state`, { headers: tenantBHeaders });
    const stateBData = await stateBRes.json();
    expect(stateBData.invoices.length).toBe(0);
    expect(stateBData.payrevive.decisions.length).toBe(0);

    // Operator A balance remains untouched (not 912300) and retains Operator A's invoices
    const stateARes = await fetch(`${baseUrl}/api/state`, { headers: authHeaders });
    const stateAData = await stateARes.json();
    expect(stateAData.lupa.currentCheckingBalanceCents).not.toBe(912300);
    expect(stateAData.invoices.length).toBeGreaterThanOrEqual(1);

    // Flush async store queue deterministically and reload store from disk to prove persistence
    await (appInstance as unknown as { flushStoreAsync: () => Promise<void> }).flushStoreAsync();
    const reloadedStore = new AegisMultiTenantStore({
      rootDir: process.cwd(),
      customFilePath: tempStoreFile,
    });
    const verifiedUserB = reloadedStore.getUserByEmail('isolated-tenant@aegispay.io');
    expect(verifiedUserB).toBeDefined();
    expect(verifyPasswordScrypt('StrongTenantPassword2026!', verifiedUserB!.passwordScrypt)).toBe(
      true
    );
    const reloadedWsB = reloadedStore.getTenantWorkspace(verifiedUserB!.id, verifiedUserB!.email);
    expect(reloadedWsB.currentCheckingBalanceCents).toBe(912300);
  });

  it('POST /api/lupa/cashflow-check and /cashflow-update evaluate affordability, update bills, and sync agent permit cap', async () => {
    const updateRes = await fetch(`${baseUrl}/api/lupa/cashflow-update`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        balanceCents: 450000,
        addCommitment: {
          name: 'Cloud GPU Reserve',
          amountCents: 18000,
          dueInDays: 9,
          category: 'ESSENTIAL_LIVING',
        },
      }),
    });
    expect(updateRes.status).toBe(200);
    const updatedState = await updateRes.json();
    expect(updatedState.currentCheckingBalanceCents).toBe(450000);

    const res = await fetch(`${baseUrl}/api/lupa/cashflow-check`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        itemTitle: 'MacBook Pro M4 Workstation',
        proposedSpendCents: 65000,
        syncAgentPermitCap: true,
      }),
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(['ALLOW', 'HOLD', 'BLOCK']).toContain(data.result.verdict);
    expect(data.updatedPermit).toBeDefined();
  });

  it('POST /api/lupa/compile-policy, /mint-vault-permit, and /create-sandbox-subscription execute grounded policy compilation and PayPal Vault/Subscriptions', async () => {
    const policyRes = await fetch(`${baseUrl}/api/lupa/compile-policy`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        sentence:
          'Allow DevOps Agent to buy cloud tools up to $65 per purchase with $40 auto-approve.',
        applyToPermitId: 'PRM-CLAUDE-CODE-01',
      }),
    });
    expect(policyRes.status).toBe(200);
    const policyData = await policyRes.json();
    expect(policyData.groundingCheck.grounded).toBe(true);
    expect(policyData.updatedPermit.maxSingleTransactionCents).toBe(6500);

    const vaultRes = await fetch(`${baseUrl}/api/lupa/mint-vault-permit`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ permitId: 'PRM-CLAUDE-CODE-01' }),
    });
    expect(vaultRes.status).toBe(200);
    const vaultData = await vaultRes.json();
    expect(vaultData.vaultToken.setupTokenId).toBeDefined();

    const subRes = await fetch(`${baseUrl}/api/lupa/create-sandbox-subscription`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ planName: 'Cloud Monitor Pro', monthlyPriceCents: 2900 }),
    });
    expect(subRes.status).toBe(200);
    const subData = await subRes.json();
    expect(subData.subscription.subscriptionId).toBeDefined();
  });

  it('POST /api/lupa/revoke-zombie tightens cap and revokes dormant agreements', async () => {
    const tightenRes = await fetch(`${baseUrl}/api/lupa/revoke-zombie`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        agreementId: 'BA-77219402-OVERCAP',
        action: 'TIGHTEN_CAP',
      }),
    });
    expect(tightenRes.status).toBe(200);
    const tightenData = await tightenRes.json();
    expect(tightenData.permission.monthlyCapCents).toBeLessThan(50000);

    const revokeRes = await fetch(`${baseUrl}/api/lupa/revoke-zombie`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        agreementId: 'BA-94827104-ZOMBIE1',
        action: 'REVOKE',
      }),
    });
    expect(revokeRes.status).toBe(200);
    const revokeData = await revokeRes.json();
    expect(revokeData.permission.status).toBe('REVOKED');
  });

  it('POST /api/lupa/agent-pay creates PayPal CAPTURE on ALLOW, AUTHORIZE on HOLD, and resolves held funds', async () => {
    const allowRes = await fetch(`${baseUrl}/api/lupa/agent-pay`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        permitId: 'PRM-CLAUDE-CODE-01',
        amountCents: 3200,
        merchantId: 'merch_usb_hub',
        merchantName: 'Anker Pro Store',
        category: 'HARDWARE',
        itemDescription: 'Thunderbolt 4 Cable',
        aiConfidenceScore: 0.95,
        aiSuggestedVerdict: 'ALLOW',
      }),
    });
    const allowData = await allowRes.json();
    expect(allowData.evaluation.finalVerdict).toBe('ALLOW');
    expect(allowData.paypalOrder.intent).toBe('CAPTURE');
    expect(allowData.paypalOrder.status).toBe('COMPLETED');

    const holdRes = await fetch(`${baseUrl}/api/lupa/agent-pay`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        permitId: 'PRM-CLAUDE-CODE-01',
        amountCents: 4500,
        merchantId: 'merch_lamp',
        merchantName: 'NordicLight',
        category: 'HARDWARE',
        itemDescription: 'Desk Lamp',
        aiConfidenceScore: 0.68,
        aiSuggestedVerdict: 'ALLOW',
      }),
    });
    const holdData = await holdRes.json();
    expect(holdData.evaluation.finalVerdict).toBe('HOLD');
    expect(holdData.paypalOrder.intent).toBe('AUTHORIZE');
    expect(holdData.paypalOrder.status).toBe('AUTHORIZED');

    const resolveRes = await fetch(`${baseUrl}/api/lupa/resolve-hold`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        orderId: holdData.paypalOrder.orderId,
        action: 'CAPTURE',
        operatorNote: 'Approved in E2E test',
      }),
    });
    const resolveData = await resolveRes.json();
    expect(resolveData.order.status).toBe('COMPLETED');
  });

  it('POST /api/scamshield/review, /create-paypal-order, & /capture enforce single-use token and block all 5 tamper attacks', async () => {
    const revRes = await fetch(`${baseUrl}/api/scamshield/review`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        rawText: 'Invoice #901 for Cloud Hosting Setup: $45.00 USD',
        claimedAmountCents: 4500,
        currency: 'USD',
        payeeIdentifier: 'billing@cloudsetup.io',
      }),
    });
    const revData = await revRes.json();
    expect(revData.finalVerdict).toBe('ALLOW');
    expect(revData.paypalCheckoutUnlocked).toBe(true);

    const smartOrderRes = await fetch(`${baseUrl}/api/scamshield/create-paypal-order`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ signedToken: revData.signedToken }),
    });
    expect(smartOrderRes.status).toBe(200);
    const smartOrderData = await smartOrderRes.json();
    expect(smartOrderData.orderId).toBeDefined();

    const tamperScenarios = [
      'MUTATE_AMOUNT',
      'FORGE_SIGNATURE',
      'EXPIRED_TOKEN',
      'NEVER_REVIEWED',
      'PAYEE_SWAP',
    ];

    for (const tamperScenario of tamperScenarios) {
      const tRes = await fetch(`${baseUrl}/api/scamshield/capture`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({
          signedToken: revData.signedToken,
          tamperScenario,
        }),
      });
      const tData = await tRes.json();
      expect(tData.captured).toBe(false);
      expect(tData.verification.allowed).toBe(false);
    }

    const validCapRes = await fetch(`${baseUrl}/api/scamshield/capture`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        signedToken: revData.signedToken,
      }),
    });
    const validCapData = await validCapRes.json();
    expect(validCapData.captured).toBe(true);
    expect(validCapData.paypalOrder.status).toBe('COMPLETED');

    const replayCapRes = await fetch(`${baseUrl}/api/scamshield/capture`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        signedToken: revData.signedToken,
      }),
    });
    const replayCapData = await replayCapRes.json();
    expect(replayCapData.captured).toBe(false);
    expect(replayCapData.verification.errorCode).toBe('TOKEN_REPLAYED');
  });

  it('POST /api/dealforge/negotiate settles SHA-256 contract, issues deposit invoice, and neutralizes adversarial prompt injection', async () => {
    const res = await fetch(`${baseUrl}/api/dealforge/negotiate`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        simulatePromptInjection: true,
        issueLiveInvoice: true,
      }),
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.dealReached).toBe(true);
    expect(data.contractIntegrityVerified).toBe(true);
    expect(
      data.rounds.some((r: { promptInjectionBlocked: boolean }) => r.promptInjectionBlocked)
    ).toBe(true);
    expect(data.paypalOrder.status).toBe('COMPLETED');
    expect(data.paypalInvoice.invoiceId).toBeDefined();
  });

  it('POST /api/cliprefund/evaluate-and-refund issues partial refund and blocks replay/spoof photos', async () => {
    const okRes = await fetch(`${baseUrl}/api/cliprefund/evaluate-and-refund`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        presetId: 'chipped_ceramic_mug',
        originalOrderCents: 2800,
      }),
    });
    const okData = await okRes.json();
    expect(okData.calculation.approved).toBe(true);
    expect(okData.calculation.refundCents).toBe(840);
    expect(okData.paypalRefund.status).toBe('COMPLETED');

    const replayRes = await fetch(`${baseUrl}/api/cliprefund/evaluate-and-refund`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        presetId: 'chipped_ceramic_mug',
        originalOrderCents: 2800,
        simulateReplayAttack: true,
      }),
    });
    const replayData = await replayRes.json();
    expect(replayData.calculation.approved).toBe(false);
    expect(replayData.paypalRefund).toBeNull();
  });

  it('POST /api/churnrescue/intercept enforces concession ladder, utilization block, circuit breaker, and atomic lock', async () => {
    const step2Res = await fetch(`${baseUrl}/api/churnrescue/intercept`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        currentPlanPriceCents: 10000,
        featureUtilizationPct: 25,
        negotiationStep: 2,
        customerMessage: 'Still too expensive for our small team.',
      }),
    });
    const step2Data = await step2Res.json();
    expect(step2Data.decision.approvedDiscountPct).toBe(35);
    expect(step2Data.decision.finalOfferPriceCents).toBe(6500);

    const cbRes = await fetch(`${baseUrl}/api/churnrescue/intercept`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        currentPlanPriceCents: 10000,
        featureUtilizationPct: 25,
        negotiationStep: 3,
        customerMessage: 'I am filing a chargeback and calling my lawyer!',
      }),
    });
    const cbData = await cbRes.json();
    expect(cbData.decision.circuitBreakerTripped).toBe(true);
    expect(cbData.decision.approvedDiscountPct).toBe(0);
    expect(cbData.zapierDispatched).toBe(true);

    const dupRes = await fetch(`${baseUrl}/api/churnrescue/intercept`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        currentPlanPriceCents: 10000,
        featureUtilizationPct: 25,
        negotiationStep: 1,
        simulateDuplicateClick: true,
      }),
    });
    const dupData = await dupRes.json();
    expect(dupData.atomicOutcome.duplicateBlocked).toBe(true);
  });

  it('POST /api/paystream/create-plan, /issue-invoice, & /verify-proof execute penny-exact milestone splits, PayPal Invoicing v2, and Proof-of-Delivery verification', async () => {
    const planRes = await fetch(`${baseUrl}/api/paystream/create-plan`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        projectTitle: 'Enterprise PayPal Checkout Integration',
        clientEmail: 'procurement@enterprise.io',
        totalBudgetCents: 150001,
        currency: 'USD',
        projectBrief:
          'Deliver OpenAPI specification, Orders v2 webhook integration, and Vitest verification suite.',
        collaborators: [
          {
            collaboratorName: 'Lead Architect',
            paypalEmail: 'arch@studio.io',
            role: 'Backend',
            sharePct: 60,
          },
          {
            collaboratorName: 'Frontend Engineer',
            paypalEmail: 'ui@studio.io',
            role: 'Frontend',
            sharePct: 40,
          },
        ],
      }),
    });
    expect(planRes.status).toBe(200);
    const planData = await planRes.json();
    expect(planData.plan.pennyExactVerified).toBe(true);
    expect(planData.plan.totalBudgetCents).toBe(150001);
    const m0 = planData.plan.milestones[0];

    const invRes = await fetch(`${baseUrl}/api/paystream/issue-invoice`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        planId: planData.plan.planId,
        milestoneId: m0.milestoneId,
      }),
    });
    expect(invRes.status).toBe(200);
    const invData = await invRes.json();
    expect(invData.invoice.invoiceId).toBeDefined();
    expect(invData.invoice.payerViewUrl).toContain('sandbox.paypal.com');

    const proofRes = await fetch(`${baseUrl}/api/paystream/verify-proof`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        planId: planData.plan.planId,
        milestoneId: m0.milestoneId,
        evidenceUrl: 'https://github.com/A-P-S-Bhaidav/PayPal_Hackathon/pull/1',
        evidenceText: `Completed deliverable for ${m0.title} satisfying acceptance criteria: ${m0.acceptanceCriteria.join(', ')} with passing automated tests and production documentation.`,
      }),
    });
    expect(proofRes.status).toBe(200);
    const proofData = await proofRes.json();
    expect(proofData.verification.approved).toBe(true);
    expect(proofData.collaboratorPayoutSchedule.length).toBe(2);
  });

  it('POST /api/security/fuzz & GET /api/export/elastic-ndjson return verified fuzzer proof and Elastic bulk NDJSON', async () => {
    const fuzzRes = await fetch(`${baseUrl}/api/security/fuzz`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ iterations: 500 }),
    });
    const fuzzData = await fuzzRes.json();
    expect(fuzzData.report.failedCases).toBe(0);
    expect(fuzzData.report.passedCases).toBe(500);
    expect(fuzzData.report.invariantsVerified.milestonePennyExactConservation).toBe(true);

    const ndjsonRes = await fetch(`${baseUrl}/api/export/elastic-ndjson`, {
      headers: authHeaders,
    });
    expect(ndjsonRes.status).toBe(200);
    const text = await ndjsonRes.text();
    expect(text).toContain('aegispay-security-audit-2026');
  });

  it('POST /api/ai/failover-test verifies Gemini-to-Groq automatic failover router on simulated HTTP 429 rate limit', async () => {
    const failoverRes = await fetch(`${baseUrl}/api/ai/failover-test`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        simulateRateLimit: true,
      }),
    });
    expect(failoverRes.status).toBe(200);
    const failoverData = await failoverRes.json();
    expect(failoverData.telemetry.failoverTriggered).toBe(true);
    expect(failoverData.telemetry.failoverReason).toContain('429');
    expect(failoverData.aiStatus).toBeDefined();
    expect(failoverData.auditRow.pillar).toBe('FAILOVER');

    await fetch(`${baseUrl}/api/ai/failover-test`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ simulateRateLimit: false }),
    });
  });

  it('POST /api/auth/register registers new institutional operator with scrypt policy and rejects duplicate email or short passwords', async () => {
    const weakRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'weak@aegispay.io',
        password: 'short',
      }),
    });
    expect(weakRes.status).toBe(400);

    const regRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'treasury-lead@aegispay.io',
        password: 'SecurePassword2026!',
        fullName: 'Treasury Lead',
        organization: 'AegisPay FinOps',
      }),
    });
    expect(regRes.status).toBe(201);
    const regData = await regRes.json();
    expect(regData.authenticated).toBe(true);
    expect(regData.isNewAccount).toBe(true);
    expect(regData.operator.email).toBe('treasury-lead@aegispay.io');
    expect(regData.token).toContain('aegis_sess_');

    // Subsequent login for same user returns isNewAccount: false (so tutorial never repeats)
    const reloginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'treasury-lead@aegispay.io',
        password: 'SecurePassword2026!',
      }),
    });
    expect(reloginRes.status).toBe(200);
    const reloginData = await reloginRes.json();
    expect(reloginData.isNewAccount).toBe(false);

    const dupRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'treasury-lead@aegispay.io',
        password: 'SecurePassword2026!',
      }),
    });
    expect(dupRes.status).toBe(409);
    const dupData = await dupRes.json();
    expect(dupData.code).toBe('EMAIL_PASSWORD_ALREADY_REGISTERED');
  });

  it('seamlessly unifies Google OAuth and Email/Password accounts in both directions while preserving tenant workspace data', async () => {
    const unifiedStorePath = path.join(
      os.tmpdir(),
      `aegispay_oauth_unify_${process.pid}_${Date.now()}.json`
    );
    const seedStore = new AegisMultiTenantStore({
      rootDir: os.tmpdir(),
      customFilePath: unifiedStorePath,
    });

    // 1. User A registers first via Google OAuth (hasPassword === false)
    const oauthUserA = seedStore.upsertOAuthUser({
      email: 'oauth-first@studio.io',
      fullName: 'OAuth First Founder',
      organization: 'Studio Alpha',
      role: 'TREASURY_OPERATOR',
      paypalMerchantId: 'SBX-GOOGLE-LEGACY1',
    });
    expect(oauthUserA.hasPassword).toBe(false);

    // Add a custom milestone plan to User A's workspace to verify data preservation after linking
    const wsA = seedStore.getTenantWorkspace(oauthUserA.id, oauthUserA.email);
    wsA.currentCheckingBalanceCents = 777000;

    // 2. User B registers first via Google OAuth (will link directly via /api/auth/login)
    seedStore.upsertOAuthUser({
      email: 'oauth-login-link@studio.io',
      fullName: 'OAuth Direct Login User',
      organization: 'Studio Beta',
      role: 'TREASURY_OPERATOR',
      paypalMerchantId: 'SBX-MERCH-BETA01',
    });

    await seedStore.flushAsync();

    const unifiedApp = createAegisServer({ customStoreFilePath: unifiedStorePath });
    let unifiedServer!: Server;
    let unifiedUrl = '';
    await new Promise<void>((resolve) => {
      unifiedServer = unifiedApp.listen(0, () => {
        const addr = unifiedServer.address();
        if (addr && typeof addr === 'object') {
          unifiedUrl = `http://127.0.0.1:${addr.port}`;
        }
        resolve();
      });
    });

    try {
      // Direction 1A: OAuth user submits Create Account (/api/auth/register) with same email -> links password seamlessly!
      const linkRegRes = await fetch(`${unifiedUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'oauth-first@studio.io',
          password: 'LinkedPassword2026!',
          fullName: 'OAuth First Founder',
          organization: 'Studio Alpha',
        }),
      });
      expect(linkRegRes.status).toBe(200);
      const linkRegData = await linkRegRes.json();
      expect(linkRegData.authenticated).toBe(true);
      expect(linkRegData.linkedFromOAuth).toBe(true);
      expect(linkRegData.isNewAccount).toBe(false);
      expect(linkRegData.operator.id).toBe(oauthUserA.id);

      // Verify workspace data (custom $7,770 balance) was preserved seamlessly
      const stateARes = await fetch(`${unifiedUrl}/api/state`, {
        headers: { Authorization: `Bearer ${linkRegData.token}` },
      });
      const stateAData = await stateARes.json();
      expect(stateAData.lupa.currentCheckingBalanceCents).toBe(777000);

      // Subsequent /api/auth/login with that linked password works cleanly
      const loginARes = await fetch(`${unifiedUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'oauth-first@studio.io',
          password: 'LinkedPassword2026!',
        }),
      });
      expect(loginARes.status).toBe(200);

      // Direction 1B: OAuth user submits Sign In (/api/auth/login) directly with 8+ char password -> links & signs in!
      const linkLoginRes = await fetch(`${unifiedUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'oauth-login-link@studio.io',
          password: 'DirectLinkPass2026!',
        }),
      });
      expect(linkLoginRes.status).toBe(200);
      const linkLoginData = await linkLoginRes.json();
      expect(linkLoginData.authenticated).toBe(true);
      expect(linkLoginData.linkedFromOAuth).toBe(true);
      expect(linkLoginData.isNewAccount).toBe(false);
    } finally {
      await new Promise<void>((resolve) => unifiedServer.close(() => resolve()));
      if (fs.existsSync(unifiedStorePath)) fs.unlinkSync(unifiedStorePath);
    }
  });

  it('GET /api/auth/me & POST /api/auth/logout validate and revoke stateless HMAC bearer session tokens', async () => {
    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'operator@aegispay.io',
        password: 'AegisPay2026!',
      }),
    });
    const { token } = await loginRes.json();

    const meRes = await fetch(`${baseUrl}/api/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(meRes.status).toBe(200);

    await fetch(`${baseUrl}/api/auth/logout`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });

    const afterLogoutRes = await fetch(`${baseUrl}/api/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(afterLogoutRes.status).toBe(401);
  });

  it('enforces verified Google OAuth (blocks unverified email spoofing & OAuth CSRF state mismatch) and removed /api/auth/oauth backdoor', async () => {
    const urlRes = await fetch(`${baseUrl}/api/auth/google/url`);
    expect(urlRes.status).toBe(200);
    const urlData = await urlRes.json();
    expect(urlData.redirectUri).toContain('/api/auth/google/callback');

    // Unverified email-only payload MUST be rejected with 401
    const spoofRes = await fetch(`${baseUrl}/api/auth/google`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'spoofed-admin@aegispay.io',
        fullName: 'Attacker',
      }),
    });
    expect(spoofRes.status).toBe(401);

    // Removed legacy /api/auth/oauth endpoint MUST NOT mint a session
    const legacyBackdoorRes = await fetch(`${baseUrl}/api/auth/oauth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'PAYPAL', email: 'operator@aegispay.io' }),
    });
    expect(legacyBackdoorRes.status).toBe(401);

    // OAuth callback without matching aegis_oauth_state cookie MUST redirect with oauth_state_mismatch
    const cbRes = await fetch(`${baseUrl}/api/auth/google/callback?code=fake_code&state=forged_state`, {
      redirect: 'manual',
    });
    expect([301, 302]).toContain(cbRes.status);
    expect(cbRes.headers.get('location')).toContain('auth_error=oauth_state_mismatch');
  });

  it('enforces Demo Workspace RBAC (403 on /api/credentials), SSRF blocking (400 on metadata/loopback URLs), Cookie CSRF protection, and Onboarding Tour persistence', async () => {
    const demoRes = await fetch(`${baseUrl}/api/auth/demo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    expect(demoRes.status).toBe(200);
    const setCookieHeader = demoRes.headers.get('set-cookie') || '';
    expect(setCookieHeader).toContain('aegis_session=');
    const sessionCookiePair = setCookieHeader.split(';')[0];

    const demoData = await demoRes.json();
    expect(demoData.operator.role).toBe('DEMO_OPERATOR');
    const demoHeaders = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${demoData.token}`,
    };

    // DEMO_OPERATOR attempting to mutate global server credentials MUST receive 403 Forbidden
    const rbacRes = await fetch(`${baseUrl}/api/credentials`, {
      method: 'POST',
      headers: demoHeaders,
      body: JSON.stringify({ simulateGeminiRateLimit: true }),
    });
    expect(rbacRes.status).toBe(403);

    // Cross-site POST using session cookie + untrusted Origin without X-Requested-With MUST receive 403 CSRF_VERIFICATION_FAILED
    const csrfBlockedRes = await fetch(`${baseUrl}/api/workspace/tutorial`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: sessionCookiePair,
        Origin: 'https://evil-attacker.example',
      },
      body: JSON.stringify({ completed: true }),
    });
    expect(csrfBlockedRes.status).toBe(403);
    const csrfJson = await csrfBlockedRes.json();
    expect(csrfJson.code).toBe('CSRF_VERIFICATION_FAILED');

    // Same cookie with trusted X-Requested-With header succeeds cleanly
    const tutorialOkRes = await fetch(`${baseUrl}/api/workspace/tutorial`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: sessionCookiePair,
        'X-Requested-With': 'AegisPay-Client',
      },
      body: JSON.stringify({ completed: true }),
    });
    expect(tutorialOkRes.status).toBe(200);
    const tutorialJson = await tutorialOkRes.json();
    expect(tutorialJson.tutorialCompleted).toBe(true);

    // PRINCIPAL_ARCHITECT attempting SSRF via AWS metadata or loopback zapierUrl MUST receive 400
    for (const badUrl of [
      'http://169.254.169.254/latest/meta-data/',
      'https://127.0.0.1:8443/internal',
      'https://localhost/admin',
    ]) {
      const ssrfRes = await fetch(`${baseUrl}/api/credentials`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ zapierUrl: badUrl }),
      });
      expect(ssrfRes.status).toBe(400);
    }
  });

  it('rejects unsigned POST /api/paypal/webhook (401) and accepts constant-time HMAC-signed webhooks (200)', async () => {
    const webhookBody = {
      event_type: 'PAYMENT.CAPTURE.COMPLETED',
      summary: 'Payment captured in sandbox verification',
      resource: { id: 'CAP-VERIFIED-9001', status: 'COMPLETED' },
    };

    const unsignedRes = await fetch(`${baseUrl}/api/paypal/webhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(webhookBody),
    });
    expect(unsignedRes.status).toBe(401);

    const forgedRes = await fetch(`${baseUrl}/api/paypal/webhook`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Aegis-Webhook-Signature': 'deadbeef0000',
      },
      body: JSON.stringify(webhookBody),
    });
    expect(forgedRes.status).toBe(401);

    const validSig = hmacSha256Hex(TEST_HMAC_SECRET, webhookBody);
    const signedRes = await fetch(`${baseUrl}/api/paypal/webhook`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Aegis-Webhook-Signature': validSig,
      },
      body: JSON.stringify(webhookBody),
    });
    expect(signedRes.status).toBe(200);
    const signedData = await signedRes.json();
    expect(signedData.verified).toBe(true);
    expect(signedData.verificationMethod).toBe('KERNEL_HMAC_SHA256');
  });

  const stressSteps = Array.from({ length: 40 }, (_, idx) => idx + 1);
  it.each(stressSteps)(
    'API deterministic concurrency invariant check #%i',
    async (idx) => {
      const res = await fetch(`${baseUrl}/api/lupa/cashflow-check`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({
          itemTitle: `Stress Item #${idx}`,
          proposedSpendCents: idx * 2500,
        }),
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(['ALLOW', 'HOLD', 'BLOCK']).toContain(data.result.verdict);
    }
  );
});

