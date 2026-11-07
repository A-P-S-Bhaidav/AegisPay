#!/usr/bin/env node
/**
 * AegisPay Model Context Protocol (MCP) Server for Autonomous AI Agents (v3.2.0)
 * Supports stdio JSON-RPC 2.0 and proxies to the live /api/mcp or REST endpoints on AegisPay.
 * Exposes 13 PayPal + Agentic Financial Tools:
 *  1. aegispay_list_permits
 *  2. aegispay_check_cashflow
 *  3. aegispay_audit_subscriptions
 *  4. aegispay_compile_spending_rule
 *  5. aegispay_agent_pay
 *  6. aegispay_scamshield_review
 *  7. aegispay_payrevive_recover
 *  8. aegispay_cliprefund_evaluate
 *  9. aegispay_churnrescue_intercept
 * 10. aegispay_paystream_create_plan
 * 11. aegispay_paystream_issue_invoice
 * 12. aegispay_dealforge_negotiate
 * 13. aegispay_universal_ingest
 */

import readline from 'node:readline';

const API_BASE = process.env.AEGISPAY_API_URL || 'http://localhost:8787';
const OPERATOR_EMAIL = process.env.AEGISPAY_OPERATOR_EMAIL || '';
const OPERATOR_PASSWORD = process.env.AEGISPAY_OPERATOR_PASSWORD || '';

let cachedSessionToken = process.env.AEGISPAY_SESSION_TOKEN || '';

async function ensureAuthHeaders() {
  if (!cachedSessionToken && OPERATOR_EMAIL && OPERATOR_PASSWORD) {
    try {
      const loginRes = await fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: OPERATOR_EMAIL, password: OPERATOR_PASSWORD }),
      });
      if (loginRes.ok) {
        const loginData = await loginRes.json();
        cachedSessionToken = loginData.token || '';
      }
    } catch {
      // Will fallback to /api/mcp direct call
    }
  }
  if (!cachedSessionToken) throw new Error('Set AEGISPAY_SESSION_TOKEN or explicit AEGISPAY_OPERATOR_EMAIL and AEGISPAY_OPERATOR_PASSWORD.');
  return {
    'Content-Type': 'application/json',
    ...(cachedSessionToken ? { Authorization: `Bearer ${cachedSessionToken}` } : {}),
  };
}

export const AEGISPAY_MCP_TOOLS = [
  {
    name: 'aegispay_list_permits',
    description:
      'List all active PayPal buyer-side spending permits delegated to AI agents, including single-transaction caps, daily caps, auto-allow thresholds, and confidence floors.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'aegispay_check_cashflow',
    description:
      'Evaluate whether a proposed purchase is affordable (supports natural language queries like "Can I afford a $1,200 MacBook if my checking balance is $4,100?" or structured itemTitle + proposedSpendCents).',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Optional natural-language affordability question',
        },
        itemTitle: { type: 'string', description: 'Name of the item or service being evaluated' },
        proposedSpendCents: {
          type: 'integer',
          description: 'Proposed purchase price in integer cents (e.g. 4500 for $45.00)',
        },
      },
    },
  },
  {
    name: 'aegispay_audit_subscriptions',
    description:
      'Discover, import, or auto-clean recurring PayPal subscriptions and autopay billing agreements (detects price hikes, unused subscriptions, and oversized pull caps).',
    inputSchema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['AUDIT', 'SYNC_PAYPAL', 'CLEAN_ALL', 'IMPORT_TEXT'],
          description: 'Subscription action to run',
        },
        rawText: {
          type: 'string',
          description: 'Optional statement CSV/text when action is IMPORT_TEXT',
        },
      },
    },
  },
  {
    name: 'aegispay_compile_spending_rule',
    description:
      'Compile a plain-English spending rule sentence into deterministic PayPal agent spending limits with numeric grounding verification.',
    inputSchema: {
      type: 'object',
      properties: {
        sentence: {
          type: 'string',
          description:
            'Plain-English spending rule (e.g. "Allow up to $150 per order, auto-approve under $60 at 88% confidence")',
        },
      },
      required: ['sentence'],
    },
  },
  {
    name: 'aegispay_agent_pay',
    description:
      'Submit an autonomous agent payment request against a delegated PayPal permit. Returns ALLOW (PayPal CAPTURE), HOLD (PayPal AUTHORIZE awaiting human approval), or BLOCK.',
    inputSchema: {
      type: 'object',
      properties: {
        permitId: { type: 'string', description: 'Delegated permit ID (e.g. PRM-CLAUDE-CODE-01)' },
        amountCents: { type: 'integer', description: 'Payment amount in integer cents' },
        merchantName: { type: 'string', description: 'Merchant display name' },
        category: {
          type: 'string',
          description: 'Purchase category (HARDWARE, SAAS, OFFICE, CLOUD)',
        },
        itemDescription: { type: 'string', description: 'Line-item description' },
        aiConfidenceScore: {
          type: 'number',
          description: 'Agent confidence score from 0.0 to 1.0',
        },
      },
      required: ['amountCents', 'merchantName', 'itemDescription'],
    },
  },
  {
    name: 'aegispay_scamshield_review',
    description:
      'Scan an invoice, email, or payment request text for social-engineering scams, lookalike domains, and prompt injection before creating a PayPal order.',
    inputSchema: {
      type: 'object',
      properties: {
        rawText: { type: 'string', description: 'Raw text of the invoice or payment message' },
        claimedAmountCents: { type: 'integer', description: 'Amount requested in integer cents' },
        payeeIdentifier: { type: 'string', description: 'Payee email or merchant handle' },
      },
      required: ['rawText'],
    },
  },
  {
    name: 'aegispay_payrevive_recover',
    description:
      'Diagnose any failed payment (via natural language description or structured decline parameters) using Newton GBDT + Exact TreeSHAP + Disjoint LinUCB + Compliance Gate, and execute PayPal recovery.',
    inputSchema: {
      type: 'object',
      properties: {
        naturalDescription: {
          type: 'string',
          description: 'Plain-English description or gateway log of the failed payment',
        },
        presetId: {
          type: 'string',
          description: 'Optional preset ID',
        },
        amountCents: { type: 'integer', description: 'Failed payment amount in integer cents' },
        declineCode: { type: 'string', description: 'Decline code' },
        daysUntilPayday: { type: 'integer', description: 'Estimated days until payday (0..14)' },
      },
    },
  },
  {
    name: 'aegispay_cliprefund_evaluate',
    description:
      'Evaluate a customer damaged-delivery claim (natural language description or item details) and issue an instant Keep-the-Item partial PayPal refund.',
    inputSchema: {
      type: 'object',
      properties: {
        naturalDescription: {
          type: 'string',
          description: 'Plain-English description of the item, order price, and shipping damage',
        },
        itemTitle: { type: 'string', description: 'Item name' },
        originalOrderCents: { type: 'integer', description: 'Order total in integer cents' },
        customerNote: { type: 'string', description: 'Customer damage description' },
      },
    },
  },
  {
    name: 'aegispay_churnrescue_intercept',
    description:
      'Analyze a subscriber cancellation message or email, enforce the legal/chargeback escalation circuit breaker, and issue a right-sized PayPal retention offer.',
    inputSchema: {
      type: 'object',
      properties: {
        naturalDescription: {
          type: 'string',
          description: 'Plain-English cancellation email or subscriber context',
        },
        customerName: { type: 'string' },
        planName: { type: 'string' },
        currentPlanPriceCents: { type: 'integer' },
        customerMessage: { type: 'string' },
      },
    },
  },
  {
    name: 'aegispay_paystream_create_plan',
    description:
      'Decompose any freelance or B2B project brief into penny-exact PayPal milestones and collaborator payout splits with zero rounding drift.',
    inputSchema: {
      type: 'object',
      properties: {
        naturalDescription: {
          type: 'string',
          description: 'Full natural-language project brief including budget and team members',
        },
        projectTitle: { type: 'string', description: 'Project title' },
        projectBrief: { type: 'string', description: 'Scope brief to decompose into milestones' },
        clientEmail: { type: 'string', description: 'Client PayPal billing email' },
        totalBudgetCents: { type: 'integer', description: 'Total project budget in integer cents' },
      },
    },
  },
  {
    name: 'aegispay_paystream_issue_invoice',
    description:
      'Issue and send a live PayPal Sandbox Invoice (INV2-...) for a specific milestone in a PayStream plan.',
    inputSchema: {
      type: 'object',
      properties: {
        planId: { type: 'string', description: 'PayStream Plan ID (e.g. PSTRM-...)' },
        milestoneId: { type: 'string', description: 'Milestone ID (e.g. MS-1)' },
      },
    },
  },
  {
    name: 'aegispay_dealforge_negotiate',
    description:
      'Negotiate a vendor quote against buyer/seller mandates (via natural language quote description or structured mandates) and generate a signed SHA-256 contract + PayPal deposit invoice.',
    inputSchema: {
      type: 'object',
      properties: {
        naturalDescription: {
          type: 'string',
          description:
            'Plain-English vendor quote & buyer budget (e.g. "Vendor quoted $1,400 for a pentest, our target is $950 and max is $1,150")',
        },
      },
    },
  },
  {
    name: 'aegispay_universal_ingest',
    description:
      '1-Click Universal Agentic Ingestion: pass any raw invoice, email, statement, failed payment log, damage claim, cancel email, SOW, or vendor quote and let AegisPay classify and execute the right action automatically.',
    inputSchema: {
      type: 'object',
      properties: {
        rawText: { type: 'string', description: 'Raw text from clipboard, file, or email' },
      },
      required: ['rawText'],
    },
  },
];

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

function sendJsonRpc(id, result, error) {
  const payload = error ? { jsonrpc: '2.0', id, error } : { jsonrpc: '2.0', id, result };
  process.stdout.write(JSON.stringify(payload) + '\n');
}

rl.on('line', async (line) => {
  if (!line.trim()) return;
  let req;
  try {
    req = JSON.parse(line);
  } catch {
    return;
  }

  const { id, method, params } = req;

  if (method === 'initialize') {
    sendJsonRpc(id, {
      protocolVersion: '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: { name: 'aegispay-paypal-mcp-server', version: '3.2.0' },
    });
    return;
  }

  if (method === 'ping') {
    sendJsonRpc(id, { ok: true, timestampIso: new Date().toISOString() });
    return;
  }

  if (method === 'tools/list') {
    sendJsonRpc(id, { tools: AEGISPAY_MCP_TOOLS });
    return;
  }

  if (method === 'tools/call') {
    try {
      const headers = await ensureAuthHeaders();
      const mcpRes = await fetch(`${API_BASE}/api/mcp`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id,
          method: 'tools/call',
          params,
        }),
      });
      const data = await mcpRes.json();
      if (data.error) {
        sendJsonRpc(id, null, data.error);
      } else {
        sendJsonRpc(id, data.result || data);
      }
    } catch (err) {
      sendJsonRpc(id, null, { code: -32000, message: String(err) });
    }
  }
});
