import React, { useState } from 'react';
import {
  CheckCircle2,
  ClipboardPaste,
  ExternalLink,
  HeartHandshake,
  PackageCheck,
  RefreshCw,
  ShieldAlert,
  Sliders,
  Sparkles,
} from 'lucide-react';
import { apiFetch, fmtUsd, type WorkspaceState } from '../api';

interface MerchantRecoveryViewProps {
  state: WorkspaceState;
  onRefresh: () => Promise<void>;
}

const DEFECT_PRESETS = [
  {
    id: 'chipped_ceramic_mug',
    label: 'Minor Rim Chip on Stoneware Mug ($28.00)',
    title: 'Handcrafted Stoneware Espresso Mug',
    cents: 2800,
    note: 'Small cosmetic chip on the rim; mug still holds liquid fine.',
  },
  {
    id: 'scratched_alu_stand',
    label: 'Surface Scratch on Laptop Stand ($78.00)',
    title: 'Anodized Aluminum Desk Stand',
    cents: 7800,
    note: 'Visible scratch along the side panel from transit packaging.',
  },
  {
    id: 'shattered_glass_lamp',
    label: 'Shattered Glass Lamp ($120.00)',
    title: 'Blown-Glass Pendant Lamp',
    cents: 12000,
    note: 'Glass shade arrived completely shattered and unusable.',
  },
];

const CHURN_QUICK_SCENARIOS = [
  {
    id: 'budget',
    label: 'Price-Sensitive Subscriber ($99/mo, 32% Usage)',
    name: 'Jordan Vance',
    planUsd: '99',
    usage: 32,
    step: 1,
    msg: 'Our budget tightened this month and $99/mo feels steep—thinking about canceling.',
  },
  {
    id: 'power_user',
    label: 'Heavy Power User Bluff ($149/mo, 94% Usage)',
    name: 'Elena Rostova',
    planUsd: '149',
    usage: 94,
    step: 2,
    msg: 'Looking for a 50% discount even though our whole engineering team uses this daily.',
  },
  {
    id: 'legal_threat',
    label: 'Legal / Chargeback Threat (Circuit Breaker)',
    name: 'Marcus Sterling',
    planUsd: '199',
    usage: 45,
    step: 1,
    msg: 'Cancel immediately or I am contacting my lawyer and filing a chargeback with the CFPB for deceptive billing.',
  },
];

export const MerchantRecoveryView: React.FC<MerchantRecoveryViewProps> = ({ state, onRefresh }) => {
  // 1. Failed Payment Recovery (PayRevive) state
  const presets = state.payrevive.presets || [];
  const [selectedPresetId, setSelectedPresetId] = useState(
    presets[0]?.presetId || 'PAYDAY_LIQUIDITY'
  );
  const [naturalRecoveryInput, setNaturalRecoveryInput] = useState('');
  const [showCustomRecoveryForm, setShowCustomRecoveryForm] = useState(false);
  const [customCustomerEmail, setCustomCustomerEmail] = useState('maya.lin@acme-studio.io');
  const [customAmountUsd, setCustomAmountUsd] = useState('189.00');
  const [customDeclineCode, setCustomDeclineCode] = useState('INSUFFICIENT_FUNDS');
  const [customDaysToPayday, setCustomDaysToPayday] = useState('2');
  const [customPriorRetries, setCustomPriorRetries] = useState('0');
  const [customBackupLinked, setCustomBackupLinked] = useState(true);
  const [customOpenDispute, setCustomOpenDispute] = useState(false);
  const [customCommsOptOut, setCustomCommsOptOut] = useState(false);
  const [recovering, setRecovering] = useState(false);
  const [recoveryResult, setRecoveryResult] = useState<any>(null);
  const [settlementNote, setSettlementNote] = useState('');

  // 2. Instant Partial Refund (ClipRefund) state
  const [defectPreset, setDefectPreset] = useState(DEFECT_PRESETS[0]);
  const [naturalDamageClaim, setNaturalDamageClaim] = useState('');
  const [customItemTitle, setCustomItemTitle] = useState(DEFECT_PRESETS[0].title);
  const [customItemUsd, setCustomItemUsd] = useState(
    (DEFECT_PRESETS[0].cents / 100).toFixed(2)
  );
  const [customDamageNote, setCustomDamageNote] = useState(DEFECT_PRESETS[0].note);
  const [uploadedPhotoBase64, setUploadedPhotoBase64] = useState<string | undefined>(undefined);
  const [uploadedPhotoMime, setUploadedPhotoMime] = useState<string | undefined>(undefined);
  const [uploadedPhotoName, setUploadedPhotoName] = useState<string>('');
  const [showPolicyEditor, setShowPolicyEditor] = useState(false);
  const [minorRefundPct, setMinorRefundPct] = useState('15');
  const [moderateRefundPct, setModerateRefundPct] = useState('30');
  const [maxRefundCapPct, setMaxRefundCapPct] = useState('40');
  const [refundLoading, setRefundLoading] = useState(false);
  const [refundResult, setRefundResult] = useState<any>(null);

  // 3. Cancel-Flow Subscriber Saver (ChurnRescue) state
  const [naturalChurnInput, setNaturalChurnInput] = useState('');
  const [customerName, setCustomerName] = useState('Jordan Vance');
  const [planName, setPlanName] = useState('Pro Business Subscription');
  const [planUsd, setPlanUsd] = useState('99');
  const [usagePct, setUsagePct] = useState(32);
  const [cancelStep, setCancelStep] = useState(1);
  const [cancelMsg, setCancelMsg] = useState(
    'Our budget tightened this month and $99/mo feels steep—thinking about canceling.'
  );
  const [retentionLoading, setRetentionLoading] = useState(false);
  const [retentionResult, setRetentionResult] = useState<any>(null);

  const handleFindRecovery = async (overrideNatural?: string) => {
    setRecovering(true);
    setSettlementNote('');
    try {
      const nlText = (overrideNatural ?? naturalRecoveryInput).trim();
      let payload: Record<string, any>;

      if (nlText) {
        payload = {
          naturalDescription: nlText,
          executeLivePayPal: true,
        };
      } else if (showCustomRecoveryForm) {
        payload = {
          executeLivePayPal: true,
          event: {
            orderId: `ORD-CUST-${Date.now().toString(36).toUpperCase().slice(-5)}`,
            customerEmail: customCustomerEmail.trim() || 'buyer@example.com',
            amountCents: Math.max(500, Math.round(Number(customAmountUsd || '189') * 100)),
            currency: 'USD',
            declineCode: customDeclineCode,
            daysUntilPayday: Math.max(0, Math.min(14, Math.round(Number(customDaysToPayday || '2')))),
            priorRetryAttempts: Math.max(0, Math.round(Number(customPriorRetries || '0'))),
            historicalCustomerCaptureRate: 0.88,
            accountTenureMonths: 14,
            hasLinkedPayPalBackup: customBackupLinked,
            hasOpenDispute: customOpenDispute,
            customerOptedOutOfComms: customCommsOptOut,
          },
        };
      } else {
        payload = {
          presetId: selectedPresetId,
          executeLivePayPal: true,
        };
      }

      const res = await apiFetch<any>('/api/payrevive/recover', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      setRecoveryResult(res);
      await onRefresh();
    } finally {
      setRecovering(false);
    }
  };

  const handleOneClickPasteGatewayLog = async () => {
    try {
      let clip = '';
      if (navigator.clipboard && navigator.clipboard.readText) {
        clip = (await navigator.clipboard.readText()).trim();
      }
      if (!clip) {
        clip =
          'Customer Maya Lin (maya.lin@acme.io) had a $189.00 annual renewal fail with INSUFFICIENT_FUNDS 2 days before Friday payday. Verified PayPal backup wallet is linked.';
      }
      setNaturalRecoveryInput(clip);
      await handleFindRecovery(clip);
    } catch {
      const fallback =
        'Customer Maya Lin (maya.lin@acme.io) had a $189.00 annual renewal fail with INSUFFICIENT_FUNDS 2 days before Friday payday. Verified PayPal backup wallet is linked.';
      setNaturalRecoveryInput(fallback);
      await handleFindRecovery(fallback);
    }
  };

  const handleConfirmSettlement = async (settled: boolean) => {
    const decisionId = recoveryResult?.decision?.decisionId;
    if (!decisionId) return;
    await apiFetch('/api/payrevive/confirm-settlement', {
      method: 'POST',
      body: JSON.stringify({ decisionId, settled }),
    });
    setSettlementNote(
      settled
        ? 'Payment marked as paid — Disjoint LinUCB bandit weights updated.'
        : 'Marked unpaid — recovery arm weights updated.'
    );
    await onRefresh();
  };

  const handlePhotoUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadedPhotoName(file.name);
    const reader = new FileReader();
    reader.onload = () => {
      const str = String(reader.result || '');
      const comma = str.indexOf(',');
      if (comma > -1) {
        setUploadedPhotoBase64(str.slice(comma + 1));
        setUploadedPhotoMime(file.type || 'image/jpeg');
      }
    };
    reader.readAsDataURL(file);
  };

  const handleIssuePartialRefund = async (overrideNatural?: string) => {
    setRefundLoading(true);
    try {
      const nlClaim = (overrideNatural ?? naturalDamageClaim).trim();
      const cents = Math.max(100, Math.round(Number(customItemUsd || '28') * 100));
      const res = await apiFetch<any>('/api/cliprefund/evaluate-and-refund', {
        method: 'POST',
        body: JSON.stringify({
          naturalDescription: nlClaim || undefined,
          presetId: nlClaim ? undefined : defectPreset.id,
          itemTitle: customItemTitle,
          originalOrderCents: cents,
          customerNote: customDamageNote,
          imageBase64: uploadedPhotoBase64,
          imageMimeType: uploadedPhotoMime,
          policyOverride: showPolicyEditor
            ? {
                minorCosmeticRefundPct: Number(minorRefundPct) || 15,
                moderateFunctionalRefundPct: Number(moderateRefundPct) || 30,
                maxPartialRefundCapPct: Number(maxRefundCapPct) || 40,
              }
            : undefined,
        }),
      });
      setRefundResult(res);
      if (res.parsedNaturalInput) {
        setCustomItemTitle(res.parsedNaturalInput.itemTitle);
        setCustomItemUsd((res.parsedNaturalInput.originalOrderCents / 100).toFixed(2));
        setCustomDamageNote(res.parsedNaturalInput.customerNote);
      }
      await onRefresh();
    } finally {
      setRefundLoading(false);
    }
  };

  const handleRetentionCheck = async (e?: React.FormEvent, overrideNatural?: string) => {
    e?.preventDefault();
    setRetentionLoading(true);
    try {
      const nlText = (overrideNatural ?? naturalChurnInput).trim();
      const res = await apiFetch<any>('/api/churnrescue/intercept', {
        method: 'POST',
        body: JSON.stringify({
          naturalDescription: nlText || undefined,
          customerName,
          planName,
          currentPlanPriceCents: Math.max(1000, Math.round(Number(planUsd || '99') * 100)),
          featureUtilizationPct: usagePct,
          negotiationStep: cancelStep,
          customerMessage: cancelMsg,
          createDiscountedSubscription: true,
        }),
      });
      setRetentionResult(res);
      if (res.parsedNaturalInput) {
        setCustomerName(res.parsedNaturalInput.customerName);
        setPlanName(res.parsedNaturalInput.planName);
        setPlanUsd((res.parsedNaturalInput.currentPlanPriceCents / 100).toFixed(0));
        setUsagePct(res.parsedNaturalInput.featureUtilizationPct);
        setCancelStep(res.parsedNaturalInput.negotiationStep);
        setCancelMsg(res.parsedNaturalInput.customerMessage);
      }
      await onRefresh();
    } finally {
      setRetentionLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-view-enter">
      {/* Section 1: Failed Customer Payment Recovery (PayRevive) */}
      <div className="glass-brutal-panel corner-ticks p-6 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#1E293B] pb-4">
          <div>
            <div className="text-xs font-mono uppercase text-[#CCFF00]">
              Declined Checkout Recovery • Describe Any Failed Payment or Gateway Log
            </div>
            <h2 className="font-display text-xl sm:text-2xl font-bold text-white">
              Recover Failed Customer Payments
            </h2>
            <p className="text-xs sm:text-sm text-slate-300 mt-0.5">
              Describe any declined customer checkout in plain English, paste a gateway log from your clipboard, customize parameters, or pick a preset below.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              disabled={recovering}
              onClick={() => void handleOneClickPasteGatewayLog()}
              className="btn-cobalt px-3 py-1.5 text-xs flex items-center gap-1.5"
            >
              <ClipboardPaste className="w-3.5 h-3.5" />
              <span>1-Click Paste &amp; Recover Log</span>
            </button>
            <button
              type="button"
              onClick={() => setShowCustomRecoveryForm((v) => !v)}
              className="btn-ghost-brutal px-3 py-1.5 text-xs flex items-center gap-1.5"
            >
              <Sliders className="w-3.5 h-3.5 text-[#CCFF00]" />
              <span>{showCustomRecoveryForm ? 'Hide Custom Fields' : 'Customize All Parameters'}</span>
            </button>
          </div>
        </div>

        {/* Free-Form Natural Language / Gateway Log Bar */}
        <div className="p-4 bg-[#050507] border border-[#243049] space-y-2">
          <label className="block text-xs font-mono uppercase text-[#CCFF00]">
            Describe Any Failed Payment or Paste a Stripe / PayPal / Braintree Decline Log:
          </label>
          <div className="flex flex-col sm:flex-row gap-2">
            <input
              type="text"
              value={naturalRecoveryInput}
              onChange={(e) => setNaturalRecoveryInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  void handleFindRecovery();
                }
              }}
              placeholder="e.g. Customer Maya Lin ($189 annual plan) failed with INSUFFICIENT_FUNDS 2 days before Friday payday, has PayPal backup wallet..."
              className="input-brutal text-xs flex-1"
            />
            <button
              type="button"
              disabled={recovering}
              onClick={() => void handleFindRecovery()}
              className="btn-acid px-4 py-2 text-xs shrink-0 flex items-center gap-1.5"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>{recovering ? 'Running AI Recovery...' : 'Parse & Recover'}</span>
            </button>
          </div>
        </div>

        {/* Optional Custom Parameter Editor */}
        {showCustomRecoveryForm && (
          <div className="p-4 bg-[#050507] border border-[#0047FF] grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs">
            <div className="sm:col-span-2">
              <label className="block text-slate-400 mb-1">Customer Email</label>
              <input
                type="text"
                value={customCustomerEmail}
                onChange={(e) => setCustomCustomerEmail(e.target.value)}
                className="input-brutal text-xs"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Order Amount (USD)</label>
              <input
                type="number"
                step="0.01"
                value={customAmountUsd}
                onChange={(e) => setCustomAmountUsd(e.target.value)}
                className="input-brutal text-xs"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Gateway Decline Code</label>
              <select
                value={customDeclineCode}
                onChange={(e) => setCustomDeclineCode(e.target.value)}
                className="input-brutal text-xs"
              >
                <option value="INSUFFICIENT_FUNDS">INSUFFICIENT_FUNDS</option>
                <option value="DO_NOT_HONOR">DO_NOT_HONOR</option>
                <option value="EXPIRED_CARD">EXPIRED_CARD</option>
                <option value="SOFT_VELOCITY_LIMIT">SOFT_VELOCITY_LIMIT</option>
                <option value="STOLEN_CARD">STOLEN_CARD (Hard Block)</option>
                <option value="FRAUD_SUSPECTED">FRAUD_SUSPECTED (Hard Block)</option>
                <option value="INVALID_ACCOUNT">INVALID_ACCOUNT (Hard Block)</option>
              </select>
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Days Until Payday</label>
              <input
                type="number"
                min="0"
                max="14"
                value={customDaysToPayday}
                onChange={(e) => setCustomDaysToPayday(e.target.value)}
                className="input-brutal text-xs"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Prior Retries</label>
              <input
                type="number"
                min="0"
                max="6"
                value={customPriorRetries}
                onChange={(e) => setCustomPriorRetries(e.target.value)}
                className="input-brutal text-xs"
              />
            </div>
            <div className="sm:col-span-3 lg:col-span-6 flex flex-wrap items-center gap-5 pt-1">
              <label className="inline-flex items-center gap-2 text-slate-300">
                <input
                  type="checkbox"
                  checked={customBackupLinked}
                  onChange={(e) => setCustomBackupLinked(e.target.checked)}
                />
                <span>PayPal Backup Wallet Linked</span>
              </label>
              <label className="inline-flex items-center gap-2 text-slate-300">
                <input
                  type="checkbox"
                  checked={customOpenDispute}
                  onChange={(e) => setCustomOpenDispute(e.target.checked)}
                />
                <span>Has Open Chargeback Dispute</span>
              </label>
              <label className="inline-flex items-center gap-2 text-slate-300">
                <input
                  type="checkbox"
                  checked={customCommsOptOut}
                  onChange={(e) => setCustomCommsOptOut(e.target.checked)}
                />
                <span>Customer Opted Out of Outreach</span>
              </label>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left 5 Columns: Order Selector */}
          <div className="lg:col-span-5 space-y-3">
            <label className="block text-xs font-medium text-slate-300">
              Or Choose a Preset Declined Order Scenario
            </label>
            <div className="space-y-2">
              {presets.map((p) => {
                const active = p.presetId === selectedPresetId && !naturalRecoveryInput.trim();
                return (
                  <button
                    key={p.presetId}
                    type="button"
                    onClick={() => {
                      setNaturalRecoveryInput('');
                      setShowCustomRecoveryForm(false);
                      setSelectedPresetId(p.presetId);
                      setRecoveryResult(null);
                      setSettlementNote('');
                    }}
                    className={`w-full text-left p-3.5 border transition-colors ${
                      active
                        ? 'bg-[#0047FF]/20 border-[#CCFF00] text-white'
                        : 'bg-[#080B13] border-[#1B2234] text-slate-300 hover:border-[#0047FF]'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs sm:text-sm font-semibold">{p.title}</span>
                      <span className="text-xs font-mono text-[#CCFF00]">
                        {fmtUsd(p.event.amountCents)}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1">{p.subtitle}</p>
                  </button>
                );
              })}
            </div>

            <button
              type="button"
              onClick={() => void handleFindRecovery()}
              disabled={recovering}
              className="btn-acid w-full py-3 text-sm"
            >
              <RefreshCw className={`w-4 h-4 ${recovering ? 'animate-spin' : ''}`} />
              {recovering ? 'Analyzing Declined Payment...' : 'Find Best Recovery Step'}
            </button>
          </div>

          {/* Right 7 Columns: Plain-English Outcome, SHAP Factors & PayPal Action */}
          <div className="lg:col-span-7 bg-[#070A12] border border-[#1B2234] p-5 space-y-4 min-h-[260px]">
            {!recoveryResult ? (
              <div className="py-12 text-center space-y-2">
                <RefreshCw className="w-7 h-7 text-[#0047FF] mx-auto" />
                <div className="text-sm font-semibold text-white">
                  Describe any failed payment above or select a preset and click &ldquo;Find Best Recovery Step&rdquo;
                </div>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  AegisPay runs TreeSHAP root-cause diagnosis, checks hard compliance rules, and dispatches the highest-net-value PayPal recovery action.
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                <div
                  className={`p-4 border ${
                    recoveryResult.decision.verdict === 'EXECUTE_RECOVERY'
                      ? 'bg-emerald-950/30 border-[#CCFF00]'
                      : recoveryResult.decision.verdict === 'BLOCKED_BY_COMPLIANCE'
                        ? 'bg-red-950/40 border-red-500'
                        : 'bg-slate-900 border-slate-600'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-display font-bold text-base text-white flex items-center gap-2">
                      {recoveryResult.decision.verdict === 'EXECUTE_RECOVERY' ? (
                        <>
                          <CheckCircle2 className="w-5 h-5 text-[#CCFF00]" />
                          Recovery Action Sent:{' '}
                          {recoveryResult.decision.selectedArmDetails.actionLabel}
                        </>
                      ) : recoveryResult.decision.verdict === 'BLOCKED_BY_COMPLIANCE' ? (
                        <>
                          <ShieldAlert className="w-5 h-5 text-red-400" />
                          Do Not Retry — Blocked by Safety &amp; Compliance Rules
                        </>
                      ) : (
                        'Skipped Retry — Expected Return Is Below Retry Fee'
                      )}
                    </span>
                    <span className="text-xs font-mono px-2 py-0.5 bg-[#050507] text-[#CCFF00] border border-[#1E293B]">
                      Expected Net:{' '}
                      {fmtUsd(
                        Math.max(0, recoveryResult.decision.selectedArmDetails.expectedNetGainCents)
                      )}
                    </span>
                  </div>

                  <p className="text-xs sm:text-sm text-slate-200 mt-2.5 leading-relaxed">
                    <strong>Why it failed:</strong> {recoveryResult.decision.plainEnglishCause}
                  </p>
                  <p className="text-xs sm:text-sm text-slate-300 mt-1.5 leading-relaxed">
                    <strong>Recommended next step:</strong>{' '}
                    {recoveryResult.decision.plainEnglishRecommendation}
                  </p>
                </div>

                {/* Top TreeSHAP Root-Cause Factors */}
                {Array.isArray(recoveryResult.decision.shapExplanations) &&
                  recoveryResult.decision.shapExplanations.length > 0 && (
                    <div className="p-3 bg-[#050507] border border-[#1E293B] space-y-2">
                      <div className="text-[11px] font-mono uppercase text-slate-400">
                        Root-Cause Signal Attribution (Exact TreeSHAP Contributions)
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                        {recoveryResult.decision.shapExplanations.slice(0, 3).map((s: any) => (
                          <div
                            key={s.featureName}
                            className="p-2 bg-[#090C14] border border-[#1E293B] text-xs font-mono"
                          >
                            <div className="text-slate-300 truncate">{s.humanLabel}</div>
                            <div
                              className={`font-bold mt-0.5 ${
                                s.shapLogOddsDelta >= 0 ? 'text-[#CCFF00]' : 'text-amber-300'
                              }`}
                            >
                              {s.shapLogOddsDelta >= 0 ? '+' : ''}
                              {Number(s.shapLogOddsDelta).toFixed(2)} log-odds ({s.rawValueDisplay})
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                {(recoveryResult.paypalInvoice || recoveryResult.paypalOrder) && (
                  <div className="p-3.5 bg-[#0A1224] border border-[#0047FF] flex flex-wrap items-center justify-between gap-3">
                    <div className="text-xs">
                      <div className="font-semibold text-white">
                        {recoveryResult.paypalInvoice
                          ? `PayPal Recovery Invoice Sent (${recoveryResult.paypalInvoice.invoiceId})`
                          : `PayPal Retry Order Ready (${recoveryResult.paypalOrder.orderId})`}
                      </div>
                      <div className="text-slate-400 mt-0.5">
                        Share or inspect directly in PayPal
                      </div>
                    </div>
                    <a
                      href={
                        recoveryResult.paypalInvoice
                          ? recoveryResult.paypalInvoice.payerViewUrl
                          : recoveryResult.paypalOrder.approvalUrl
                      }
                      target="_blank"
                      rel="noreferrer"
                      className="btn-acid px-3.5 py-2 text-xs"
                    >
                      Open in PayPal
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  </div>
                )}

                {recoveryResult.decision.verdict === 'EXECUTE_RECOVERY' && (
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-[#1E293B] text-xs">
                    <span className="text-slate-400">Did the customer complete this payment?</span>
                    <div className="flex gap-2">
                      <button
                        type="button"
                        onClick={() => handleConfirmSettlement(true)}
                        className="btn-ghost-brutal px-3 py-1 text-xs"
                      >
                        Mark Paid
                      </button>
                      <button
                        type="button"
                        onClick={() => handleConfirmSettlement(false)}
                        className="btn-ghost-brutal px-3 py-1 text-xs"
                      >
                        Still Unpaid
                      </button>
                    </div>
                  </div>
                )}

                {settlementNote && (
                  <div className="text-xs font-mono text-[#CCFF00]">{settlementNote}</div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Symmetrical Bottom 2-Column Grid: Instant Partial Refunds + Subscriber Cancel-Flow Saver */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Keep-the-Item Instant Partial Refund (ClipRefund) */}
        <div className="glass-brutal-panel p-6 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#1E293B] pb-3">
            <div className="flex items-center gap-2">
              <PackageCheck className="w-5 h-5 text-[#CCFF00]" />
              <div>
                <h3 className="font-display text-lg font-bold text-white">
                  Instant Partial Refunds (Keep-the-Item)
                </h3>
                <p className="text-xs text-slate-400">
                  Describe any buyer damage claim, customize item &amp; price, or upload a photo.
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setShowPolicyEditor((v) => !v)}
              className="btn-ghost-brutal px-2.5 py-1 text-[11px] font-mono"
            >
              {showPolicyEditor ? 'Hide Policy %' : 'Edit Policy %'}
            </button>
          </div>

          {/* Natural-Language Damage Claim Input */}
          <div className="space-y-1.5">
            <label className="block text-xs font-mono text-[#CCFF00]">
              Describe Any Buyer Damage Claim in Plain English:
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={naturalDamageClaim}
                onChange={(e) => setNaturalDamageClaim(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    void handleIssuePartialRefund();
                  }
                }}
                placeholder="e.g. Customer received the $220 Espresso Grinder with a scratched hopper and dented side..."
                className="input-brutal text-xs flex-1"
              />
              <button
                type="button"
                disabled={refundLoading}
                onClick={() => void handleIssuePartialRefund()}
                className="btn-acid px-3 py-1.5 text-xs shrink-0"
              >
                Parse &amp; Refund
              </button>
            </div>
          </div>

          {/* Quick Presets */}
          <div className="flex flex-wrap gap-1.5">
            {DEFECT_PRESETS.map((dp) => (
              <button
                key={dp.id}
                type="button"
                onClick={() => {
                  setNaturalDamageClaim('');
                  setDefectPreset(dp);
                  setCustomItemTitle(dp.title);
                  setCustomItemUsd((dp.cents / 100).toFixed(2));
                  setCustomDamageNote(dp.note);
                  setRefundResult(null);
                }}
                className={`px-2.5 py-1 border text-[11px] font-mono ${
                  defectPreset.id === dp.id && !naturalDamageClaim
                    ? 'bg-[#0047FF]/20 border-[#CCFF00] text-white'
                    : 'bg-[#080B13] border-[#1B2234] text-slate-300'
                }`}
              >
                {dp.label}
              </button>
            ))}
          </div>

          {/* Editable Item, Price & Customer Note */}
          <div className="grid grid-cols-1 sm:grid-cols-12 gap-2.5">
            <div className="sm:col-span-8">
              <label className="block text-xs text-slate-300 mb-1">Item Name</label>
              <input
                type="text"
                value={customItemTitle}
                onChange={(e) => setCustomItemTitle(e.target.value)}
                className="input-brutal text-xs"
              />
            </div>
            <div className="sm:col-span-4">
              <label className="block text-xs text-slate-300 mb-1">Order Price (USD)</label>
              <input
                type="number"
                step="0.01"
                min="1"
                value={customItemUsd}
                onChange={(e) => setCustomItemUsd(e.target.value)}
                className="input-brutal text-xs"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs text-slate-300 mb-1">
              Customer Defect Description
            </label>
            <textarea
              rows={2}
              value={customDamageNote}
              onChange={(e) => setCustomDamageNote(e.target.value)}
              className="input-brutal text-xs"
            />
          </div>

          {showPolicyEditor && (
            <div className="p-3 bg-[#050507] border border-[#243049] grid grid-cols-3 gap-2 text-xs">
              <div>
                <label className="block text-[11px] text-slate-400 mb-1">Minor Cosmetic %</label>
                <input
                  type="number"
                  value={minorRefundPct}
                  onChange={(e) => setMinorRefundPct(e.target.value)}
                  className="input-brutal text-xs"
                />
              </div>
              <div>
                <label className="block text-[11px] text-slate-400 mb-1">Moderate Defect %</label>
                <input
                  type="number"
                  value={moderateRefundPct}
                  onChange={(e) => setModerateRefundPct(e.target.value)}
                  className="input-brutal text-xs"
                />
              </div>
              <div>
                <label className="block text-[11px] text-slate-400 mb-1">Max Partial Cap %</label>
                <input
                  type="number"
                  value={maxRefundCapPct}
                  onChange={(e) => setMaxRefundCapPct(e.target.value)}
                  className="input-brutal text-xs"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs text-slate-400 mb-1">
              Upload customer item photo {uploadedPhotoName ? `(${uploadedPhotoName})` : '(Optional)'}
            </label>
            <input
              type="file"
              accept="image/*"
              onChange={handlePhotoUpload}
              className="text-xs text-slate-300 file:mr-3 file:py-1.5 file:px-3 file:border-0 file:bg-[#0047FF] file:text-white file:font-semibold"
            />
          </div>

          <button
            type="button"
            onClick={() => void handleIssuePartialRefund()}
            disabled={refundLoading}
            className="btn-cobalt w-full py-2.5 text-xs sm:text-sm"
          >
            {refundLoading ? 'Calculating Fair Refund...' : 'Calculate & Issue Partial Refund'}
          </button>

          {refundResult?.calculation && (
            <div className="p-4 bg-[#080B13] border border-[#CCFF00]/60 space-y-2 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2 font-semibold text-white">
                <span>
                  {refundResult.calculation.approved
                    ? `Approved ${refundResult.calculation.appliedPercentage}% Refund (${fmtUsd(refundResult.calculation.refundCents)})`
                    : 'Claim Declined / Full Return Required'}
                </span>
                {refundResult.calculation.merchantNetSavedCents > 0 && (
                  <span className="text-[#CCFF00] font-mono">
                    Saved {fmtUsd(refundResult.calculation.merchantNetSavedCents)} vs. Return
                  </span>
                )}
              </div>
              {(refundResult.vision || refundResult.visionTelemetry) && (
                <div className="text-[11px] font-mono text-sky-300">
                  Vision Telemetry:{' '}
                  {refundResult.vision?.detectedItem ||
                    refundResult.visionTelemetry?.detectedItemCategory}{' '}
                  • Severity:{' '}
                  {refundResult.vision?.severity || refundResult.visionTelemetry?.severityTier} (
                  {Math.round(
                    ((refundResult.vision?.confidence ??
                      refundResult.visionTelemetry?.photoAuthenticityConfidence) ||
                      0.92) * 100
                  )}
                  % conf)
                </div>
              )}
              <p className="text-slate-300 leading-relaxed">
                {refundResult.calculation.explanation}
              </p>
            </div>
          )}
        </div>

        {/* Right: Subscriber Cancel-Flow Retention (ChurnRescue) */}
        <div className="glass-brutal-panel p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
            <div className="flex items-center gap-2">
              <HeartHandshake className="w-5 h-5 text-[#CCFF00]" />
              <div>
                <h3 className="font-display text-lg font-bold text-white">
                  Subscriber Cancel-Flow Saver
                </h3>
                <p className="text-xs text-slate-400">
                  Paste any cancellation email or describe the subscriber — AegisPay computes a fair loyalty discount or trips the legal circuit breaker.
                </p>
              </div>
            </div>
          </div>

          {/* Natural-Language Cancellation Parser */}
          <div className="space-y-1.5">
            <label className="block text-xs font-mono text-[#CCFF00]">
              Paste Any Cancellation Email or Describe Subscriber Scenario:
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={naturalChurnInput}
                onChange={(e) => setNaturalChurnInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    void handleRetentionCheck(undefined, naturalChurnInput);
                  }
                }}
                placeholder="e.g. Subscriber Sam Patel on Enterprise ($129/mo, 40% usage) says price is too high..."
                className="input-brutal text-xs flex-1"
              />
              <button
                type="button"
                disabled={retentionLoading}
                onClick={() => void handleRetentionCheck(undefined, naturalChurnInput)}
                className="btn-acid px-3 py-1.5 text-xs shrink-0"
              >
                Parse &amp; Save
              </button>
            </div>
          </div>

          {/* Quick Scenario Pills */}
          <div className="flex flex-wrap gap-1.5">
            {CHURN_QUICK_SCENARIOS.map((sc) => (
              <button
                key={sc.id}
                type="button"
                onClick={() => {
                  setNaturalChurnInput('');
                  setCustomerName(sc.name);
                  setPlanUsd(sc.planUsd);
                  setUsagePct(sc.usage);
                  setCancelStep(sc.step);
                  setCancelMsg(sc.msg);
                }}
                className="px-2.5 py-1 text-[11px] font-mono bg-[#080B13] border border-[#1B2234] hover:border-[#CCFF00] text-slate-300"
              >
                {sc.label}
              </button>
            ))}
          </div>

          <form onSubmit={(e) => void handleRetentionCheck(e)} className="space-y-3">
            <div className="grid grid-cols-3 gap-2.5">
              <div>
                <label className="block text-xs text-slate-300 mb-1">Subscriber</label>
                <input
                  type="text"
                  value={customerName}
                  onChange={(e) => setCustomerName(e.target.value)}
                  className="input-brutal text-xs"
                />
              </div>
              <div>
                <label className="block text-xs text-slate-300 mb-1">Plan ($/mo)</label>
                <input
                  type="number"
                  min="10"
                  value={planUsd}
                  onChange={(e) => setPlanUsd(e.target.value)}
                  className="input-brutal text-xs"
                />
              </div>
              <div>
                <label className="block text-xs text-slate-300 mb-1">Offer Step (1-3)</label>
                <select
                  value={cancelStep}
                  onChange={(e) => setCancelStep(Number(e.target.value))}
                  className="input-brutal text-xs"
                >
                  <option value={1}>Step 1 (20% Off)</option>
                  <option value={2}>Step 2 (35% Off)</option>
                  <option value={3}>Step 3 (50% Max)</option>
                </select>
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs text-slate-300 mb-1">
                <span>Monthly Product Usage</span>
                <span className="font-mono text-[#CCFF00]">{usagePct}%</span>
              </div>
              <input
                type="range"
                min={0}
                max={100}
                value={usagePct}
                onChange={(e) => setUsagePct(Number(e.target.value))}
                className="w-full"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-300 mb-1">
                Customer Cancellation Note
              </label>
              <textarea
                rows={2}
                value={cancelMsg}
                onChange={(e) => setCancelMsg(e.target.value)}
                className="input-brutal text-xs"
              />
            </div>

            <button
              type="submit"
              disabled={retentionLoading}
              className="btn-acid w-full py-2.5 text-xs sm:text-sm"
            >
              {retentionLoading ? 'Preparing Offer...' : 'Generate Retention Offer'}
            </button>
          </form>

          {retentionResult?.decision && (
            <div className="p-4 bg-[#080B13] border border-[#0047FF] space-y-2 text-xs">
              <div className="font-semibold text-white">
                {retentionResult.decision.circuitBreakerTripped
                  ? 'Paused Automated Discount — Routed to Human Support (Legal Circuit Breaker)'
                  : retentionResult.decision.utilizationGuardrailBlocked
                    ? 'Heavy Account Usage (>85%) — Offered Flexible Billing Date (0% Discount)'
                    : `Loyalty Rate Ready: ${retentionResult.decision.approvedDiscountPct}% Off (${fmtUsd(retentionResult.decision.finalOfferPriceCents)}/mo)`}
              </div>
              <p className="text-slate-300 leading-relaxed">{retentionResult.agentReply}</p>
              {retentionResult.paypalSubscription?.approvalUrl && (
                <a
                  href={retentionResult.paypalSubscription.approvalUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-[#CCFF00] font-semibold underline pt-1"
                >
                  Open Updated PayPal Subscription
                  <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
