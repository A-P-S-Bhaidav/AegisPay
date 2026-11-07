import React from 'react';

export interface OperatorProfile {
  id: string;
  email: string;
  fullName: string;
  organization: string;
  role: 'PRINCIPAL_ARCHITECT' | 'TREASURY_OPERATOR' | 'SECURITY_AUDITOR' | 'DEMO_OPERATOR';
  authProvider: string;
  paypalMerchantId: string;
  authenticatedAtIso: string;
}

export interface WorkspaceState {
  system: {
    name: string;
    version: string;
    tagline: string;
    paypal: {
      hasLiveSandboxCredentials: boolean;
      publicClientId: string;
      clientIdPreview: string;
      appId: string;
      webhookVerificationConfigured: boolean;
      environment: 'sandbox' | 'live';
      activeMode: 'LIVE_PAYPAL_SANDBOX_API' | 'CRYPTOGRAPHIC_SANDBOX_EMULATOR';
      totalOrdersTracked: number;
      totalInvoicesTracked: number;
      totalVaultTokens: number;
      totalSubscriptionsTracked: number;
      totalWebhooksVerified: number;
    };
    gemini: {
      hasLiveGeminiKey: boolean;
      hasLiveGroqKey: boolean;
      primaryModel: string;
      failoverTextModel: string;
      failoverVisionModel: string;
      simulateRateLimit: boolean;
      activeMode: string;
      totalFailoversTriggered: number;
    };
    zapierConfigured: boolean;
    googleOAuth: {
      configured: boolean;
      clientIdPreview: string;
    };
    security: {
      rateLimits: Record<string, { tierName: string; windowMs: number; maxRequests: number }>;
      storage: {
        mode: string;
        vaultLocation: string;
        passwordKdf: string;
        sessionTransport: string;
        tenantIsolation: string;
        activeTenantId: string | null;
        registeredUsersCount: number;
        hotTenantsInLru: number;
        maxHotTenantsCap: number;
        maxAuditRowsPerTenant: number;
      };
    };
  };
  operator: OperatorProfile | null;
  workspace: {
    tenantId: string;
    tutorialCompleted: boolean;
  };
  kpis: {
    totalProtectedCents: number;
    zombieAnnualExposureCents: number;
    recoverableMonthlyCents: number;
    activeAgentPermits: number;
    heldOrdersPendingApproval: number;
    totalAuditRecords: number;
    livePayPalInvoicesCount: number;
    activeMilestonePlansCount: number;
    payreviveDecisionsCount: number;
  };
  lupa: {
    billingPermissions: Array<{
      agreementId: string;
      merchantName: string;
      category: string;
      monthlyCapCents: number;
      averageChargeCents: number;
      lastChargedDaysAgo: number;
      lastUserInteractionDaysAgo: number;
      status: string;
      source?: string;
      paypalApprovalUrl?: string;
    }>;
    zombieReport: {
      audits: Array<{
        agreementId: string;
        merchantName: string;
        isZombie: boolean;
        riskLevel: string;
        reasons: string[];
        recommendedAction: string;
        annualizedExposureCents: number;
      }>;
      totalZombieCount: number;
      totalAnnualExposureCents: number;
      recoverableMonthlyCents: number;
    };
    cashflowCommitments: Array<{
      id: string;
      name: string;
      amountCents: number;
      dueInDays: number;
      category: string;
      mandatory: boolean;
    }>;
    currentCheckingBalanceCents: number;
    minimumSafetyBufferCents: number;
    defaultAffordability: {
      itemTitle: string;
      proposedSpendCents: number;
      trueFreeCashflowCents: number;
      postPurchaseFreeCashflowCents: number;
      verdict: 'ALLOW' | 'HOLD' | 'BLOCK';
      recommendedAgentCapCents: number;
      deterministicExplanation: string;
    };
    agentPermits: Array<{
      permitId: string;
      agentId: string;
      agentName: string;
      maxSingleTransactionCents: number;
      dailyLimitCents: number;
      spentTodayCents: number;
      autoAllowMaxCents: number;
      minConfidenceScore: number;
      allowedCategories: string[];
      active: boolean;
    }>;
    vaultTokens: Array<{
      setupTokenId: string;
      agentName: string;
      maxSingleCents: number;
      status: string;
      approvalUrl: string;
      mode: string;
    }>;
    subscriptions: Array<{
      subscriptionId: string;
      planName: string;
      monthlyPriceCents: number;
      status: string;
      approvalUrl: string;
      mode: string;
    }>;
  };
  cliprefund: {
    merchantPolicy: {
      merchantName: string;
      returnShippingCostCents: number;
      tierRefundPercentages: Record<string, number>;
      minAuthenticityConfidence: number;
    };
  };
  paystream: {
    plans: Array<{
      planId: string;
      projectTitle: string;
      clientEmail: string;
      currency: string;
      totalBudgetCents: number;
      pennyExactVerified: boolean;
      planSha256: string;
      milestones: Array<{
        milestoneIndex: number;
        milestoneId: string;
        title: string;
        normalizedSharePct: number;
        amountCents: number;
        dueInDays: number;
        acceptanceCriteria: string[];
        status: string;
        paypalInvoiceId?: string;
        paypalInvoiceUrl?: string;
        collaboratorSplits: Array<{
          collaboratorName: string;
          paypalEmail: string;
          role: string;
          normalizedSharePct: number;
          payoutCents: number;
        }>;
      }>;
    }>;
    invoices: Array<{
      invoiceId: string;
      invoiceNumber: string;
      status: string;
      amountCents: number;
      recipientEmail: string;
      title: string;
      payerViewUrl: string;
      mode: string;
    }>;
  };
  payrevive: {
    modelCard?: {
      modelId: string;
      algorithm: string;
      numTrees: number;
      heldOutRocAuc: number;
      heldOutBrierScore: number;
      heldOutLogLoss: number;
      trainingSamples: number;
      heldOutTestSamples: number;
    };
    presets: Array<{
      presetId: string;
      title: string;
      subtitle: string;
      event: {
        eventId: string;
        customerEmail: string;
        merchantOrderRef: string;
        amountCents: number;
        currency: string;
        declineCode: string;
        daysUntilPayday: number;
        priorRetryCount30d: number;
        historicalCaptureRate: number;
        hasPayPalBackupFunding: boolean;
        issuerLatencyMs: number;
        accountTenureDays: number;
        customerOptedOutComms: boolean;
        localCustomerHour: number;
        hasOpenPayPalDispute: boolean;
      };
    }>;
    actionCatalog: Array<Record<string, unknown>>;
    decisions: Array<{
      decisionId: string;
      timestampIso: string;
      event: {
        eventId: string;
        customerEmail: string;
        merchantOrderRef: string;
        amountCents: number;
        declineCode: string;
      };
      diagnosis: {
        baseLogOdds: number;
        rawMarginLogOdds: number;
        recoverabilityProbability: number;
        additivityDelta: number;
        additivityVerified: boolean;
        predictedRootCause: string;
        rootCauseSummary: string;
        shapContributions: Array<{
          featureKey: string;
          featureLabel: string;
          featureValueDisplay: string;
          shapLogOdds: number;
          direction: string;
        }>;
      };
      selectedAction: string;
      selectedArmDetails: {
        actionId: string;
        actionLabel: string;
        customerActionTitle: string;
        paypalMechanism: string;
        actionCostCents: number;
        estimatedSuccessProbability: number;
        uncertaintyRadius: number;
        expectedGrossRecoveryCents: number;
        expectedNetGainCents: number;
        ucbScoreCents: number;
      };
      allArms: Array<{
        actionId: string;
        actionLabel: string;
        actionCostCents: number;
        estimatedSuccessProbability: number;
        uncertaintyRadius: number;
        expectedNetGainCents: number;
        ucbScoreCents: number;
        compliance: {
          allowed: boolean;
          ruleId: string;
          reason: string;
        };
      }>;
      verdict: 'EXECUTE_RECOVERY' | 'ABSTAIN_NOT_WORTH_COST' | 'BLOCKED_BY_COMPLIANCE';
      plainEnglishCause: string;
      plainEnglishRecommendation: string;
      deterministicRationale: string;
      settlementConfirmed: boolean;
      auditHash: string;
    }>;
    lastBenchmark: Record<string, any> | null;
  };
  orders: Array<{
    orderId: string;
    pillar?: string;
    buyerCheckoutReady?: boolean;
    intent: string;
    status: string;
    paypalServerStatus: string;
    settlementStage: string;
    amountCents: number;
    currency: string;
    merchantName: string;
    description: string;
    approvalUrl: string;
    mode: string;
    createdAtIso: string;
  }>;
  invoices: Array<{
    invoiceId: string;
    invoiceNumber: string;
    status: string;
    amountCents: number;
    recipientEmail: string;
    title: string;
    payerViewUrl: string;
    mode: string;
    createdAtIso: string;
  }>;
  webhooks: Array<{
    id: string;
    event_type: string;
    summary: string;
    transmission_id: string;
    transmission_sig: string;
    verified: boolean;
    verificationMethod: string;
    create_time: string;
  }>;
  auditLogs: Array<{
    id: string;
    timestampIso: string;
    pillar: string;
    actor: string;
    eventTitle: string;
    verdict: string;
    amountCents: number;
    savedOrProtectedCents: number;
    paypalRef: string;
    sha256Hash: string;
    deterministicRule: string;
  }>;
}

export function fmtUsd(cents: number): string {
  const safe = Number.isFinite(cents) ? cents : 0;
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(safe / 100);
}

export const formatUsd = fmtUsd;

/**
 * Secure API helper: uses HttpOnly session cookies (`credentials: 'include'`)
 * and sends `X-Requested-With: AegisPay-Client` for CSRF defense.
 * Zero session tokens are ever written to `localStorage`!
 */
export async function apiFetch<T = any>(
  url: string,
  options: RequestInit = {}
): Promise<T> {
  const headers = new Headers(options.headers || {});
  headers.set('X-Requested-With', 'AegisPay-Client');
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const res = await fetch(url, {
    ...options,
    headers,
    credentials: 'include',
  });

  const data = await res.json().catch(() => {
    if (res.ok) throw new Error('The server returned an unreadable response. Please try again.');
    return {};
  });
  if (!res.ok) {
    if (res.status === 401) window.dispatchEvent(new Event('aegispay:session-expired'));
    const err = new Error(data?.error || `Request failed (${res.status})`) as Error & {
      status?: number;
      data?: unknown;
    };
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data as T;
}

export const AegisBrandMark: React.FC<{ size?: number }> = ({ size = 34 }) =>
  React.createElement(
    'svg',
    {
      width: size,
      height: size,
      viewBox: '0 0 64 64',
      fill: 'none',
      xmlns: 'http://www.w3.org/2000/svg',
      'aria-hidden': 'true',
      className: 'shrink-0',
    },
    React.createElement('rect', {
      x: '3',
      y: '3',
      width: '58',
      height: '58',
      rx: '6',
      fill: '#050507',
      stroke: '#0047FF',
      strokeWidth: '3',
    }),
    React.createElement('path', {
      d: 'M32 11L50 19V33C50 43.8 42.3 51.6 32 55C21.7 51.6 14 43.8 14 33V19L32 11Z',
      fill: '#0047FF',
      fillOpacity: '0.22',
      stroke: '#0047FF',
      strokeWidth: '2.6',
    }),
    React.createElement('path', {
      d: 'M23 34L29.5 40.5L42 26',
      stroke: '#CCFF00',
      strokeWidth: '4.2',
      strokeLinecap: 'square',
    }),
    React.createElement('rect', {
      x: '6',
      y: '6',
      width: '6',
      height: '6',
      fill: '#CCFF00',
    })
  );

