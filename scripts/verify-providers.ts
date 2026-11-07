import 'dotenv/config';
import { randomBytes, randomUUID } from 'node:crypto';
import { PayPalSandboxGateway } from '../server/paypal';
import { GeminiCognitiveEngine } from '../server/gemini';

// Opt-in integration check. Prints no credentials, access tokens, or raw provider bodies.
// Creates an unapproved $1 sandbox order; does not capture funds or send invoices.
async function main() {
  if ((process.env.PAYPAL_ENV || 'sandbox') !== 'sandbox') {
    throw new Error('Provider verification requires PAYPAL_ENV=sandbox.');
  }
  if (!process.env.PAYPAL_CLIENT_ID || !process.env.PAYPAL_CLIENT_SECRET) {
    throw new Error('Set sandbox PayPal credentials in the local .env first.');
  }
  if (!process.env.GEMINI_API_KEY && !process.env.GROQ_API_KEY) {
    throw new Error('Set a Gemini or Groq key to verify an actual AI provider.');
  }
  const gateway = new PayPalSandboxGateway({
    clientId: process.env.PAYPAL_CLIENT_ID,
    clientSecret: process.env.PAYPAL_CLIENT_SECRET,
    environment: 'sandbox',
  }, randomBytes(32).toString('hex'));
  const ai = new GeminiCognitiveEngine(
    process.env.GEMINI_API_KEY,
    process.env.GEMINI_MODEL,
    process.env.GROQ_API_KEY,
    process.env.GROQ_TEXT_MODEL,
    process.env.GROQ_VISION_MODEL,
  );
  const auth = await gateway.getAccessToken();
  if (!auth.live) throw new Error('OAuth used an emulator instead of PayPal.');
  console.log('PayPal sandbox OAuth: PASS');
  const request = {
    ownerTenantId: 'PROVIDER-SMOKE',
    intent: 'CAPTURE' as const,
    amountCents: 100,
    currency: 'USD',
    merchantName: 'AegisPay sandbox verification',
    description: 'Unapproved integration check; no money captured',
    customHash: randomUUID(),
    idempotencyKey: randomUUID(),
    pillar: 'SCAMSHIELD' as const,
    autoExecuteInSandbox: false,
  };
  const order = await gateway.createOrder(request);
  if (order.mode !== 'LIVE_PAYPAL_SANDBOX_API' || order.liveCaptureVerified ||
      order.settlementStage !== 'LIVE_PAYER_APPROVAL_READY' ||
      !order.approvalUrl.startsWith('https://www.sandbox.paypal.com/')) {
    throw new Error('Unexpected PayPal order or settlement state.');
  }
  const repeated = await gateway.createOrder(request);
  if (repeated.orderId !== order.orderId) throw new Error('Order replay was not idempotent.');
  console.log('PayPal sandbox order + idempotent replay: PASS (awaiting buyer approval)');

  const detailsResponse = await fetch(`https://api-m.sandbox.paypal.com/v2/checkout/orders/${encodeURIComponent(order.orderId)}`, {
    headers: { Authorization: `Bearer ${auth.token}` },
    signal: AbortSignal.timeout(10_000),
  });
  const details = await detailsResponse.json();
  const payee = details.purchase_units?.[0]?.payee?.email_address;
  if (!detailsResponse.ok || typeof payee !== 'string') throw new Error('Could not verify the sandbox merchant.');
  const bound = await gateway.createOrder({ ...request, idempotencyKey: randomUUID(), reviewedPayeeEmail: payee });
  if (bound.verifiedPayeeEmail !== payee) throw new Error('Could not verify the reviewed recipient.');
  console.log('PayPal reviewed recipient, amount, currency and order binding: PASS');

  const invoice = await gateway.createLiveInvoice({
    ownerTenantId: 'PROVIDER-SMOKE', title: 'AegisPay sandbox verification draft',
    note: 'Automated verification. Do not send or pay.', recipientEmail: 'sandbox-verification@example.com',
    amountCents: 100, currency: 'USD', pillar: 'PAYSTREAM', contractOrPlanHash: randomUUID(),
    sendImmediately: false,
  });
  if (invoice.mode !== 'LIVE_PAYPAL_SANDBOX_API' || invoice.status !== 'DRAFT' || !invoice.invoiceId.startsWith('INV2-')) {
    throw new Error('PayPal did not confirm draft invoice creation.');
  }
  console.log('PayPal sandbox Invoicing v2 draft: PASS (no invoice email sent)');
  const review = await ai.analyzePaymentScamSemantics({
    sanitizedText: 'Invoice for completed design work: $1 USD via PayPal Goods and Services.',
    claimedAmountCents: 100,
    payeeIdentifier: 'sandbox-verification@example.com',
  });
  if (review.engineMode === 'DETERMINISTIC_NEURAL_ENGINE') {
    throw new Error('AI providers unavailable; deterministic fallback is not a live AI pass.');
  }
  console.log(JSON.stringify({
    ai: 'PASS',
    provider: review.telemetry.activeProviderUsed,
    model: review.telemetry.modelUsed,
    verdict: review.aiSuggestedVerdict,
    failover: review.telemetry.failoverTriggered,
    latencyMs: review.telemetry.latencyMs,
  }));

  if (process.env.GROQ_API_KEY) {
    const diagnostic = ai.createDiagnosticEngine(true);
    const result = await diagnostic.analyzePaymentScamSemantics({
      sanitizedText: 'Invoice for completed design work: $1 USD via PayPal Goods and Services.',
      claimedAmountCents: 100,
      payeeIdentifier: 'sandbox-verification@example.com',
    });
    if (result.engineMode !== 'GROQ_LPU_LLAMA_3_3_70B' || !result.telemetry.failoverTriggered) {
      throw new Error('Groq did not respond to the isolated failover diagnostic.');
    }
    console.log(JSON.stringify({ aiFailover: 'PASS', trigger: 'simulated 429', model: result.telemetry.modelUsed, latencyMs: result.telemetry.latencyMs }));
  }
}

const deadline = setTimeout(() => {
  console.error('Provider verification timed out after 45 seconds.');
  process.exit(1);
}, 45_000);

main().catch(() => {
  console.error('Provider verification FAILED. Check the last completed stage, model access, and sandbox credentials. No payment was captured.');
  process.exitCode = 1;
}).finally(() => clearTimeout(deadline));
