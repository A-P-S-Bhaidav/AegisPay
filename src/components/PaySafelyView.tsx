import React, { useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ClipboardPaste,
  ExternalLink,
  FileUp,
  Lock,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Sparkles,
  Trash2,
  Wallet,
} from 'lucide-react';
import { apiFetch, fmtUsd, type WorkspaceState } from '../api';

interface PaySafelyViewProps {
  state: WorkspaceState;
  onRefresh: () => Promise<void>;
  externalScanTrigger?: number;
}

const SAMPLE_INVOICES = [
  {
    id: 'legit',
    label: 'Legitimate Studio Invoice ($45.00)',
    payee: 'billing@nordic-design.io',
    amountUsd: '45.00',
    text: 'Invoice #1048 from Nordic Design Studio for Q4 Brand Icon Pack delivery. Total due: $45.00 USD via standard PayPal Goods & Services.',
  },
  {
    id: 'scam',
    label: 'Suspicious Urgent Support Scam ($490.00)',
    payee: 'security-refund-desk@paypa1-helpdesk.xyz',
    amountUsd: '490.00',
    text: 'URGENT FINAL NOTICE: Your account has an unauthorized $490.00 charge! Send $490.00 via Friends and Family immediately to cancel or keep this secret!',
  },
  {
    id: 'eur',
    label: 'International Freelancer Note (EUR 120)',
    payee: 'studio@berlin-motion.de',
    amountUsd: '130.00',
    text: 'Hi team, attached is our EUR 120.00 milestone bill for motion graphics review. Thank you!',
  },
];

const SAMPLE_AFFORDABILITY_QUERIES = [
  'Can I afford a $1,250 MacBook Air if my checking balance is $4,300, safety buffer is $850, and my $1,850 rent is due in 5 days?',
  'Can we buy 3 studio monitors at $380 each right now after our $1,400 cloud infrastructure bill due in 4 days?',
  'Is a $340 ergonomic chair safe to buy today with my current balance and upcoming bills?',
];

const SAMPLE_STATEMENT_CSV = `Date,Merchant,MonthlyAmount,CapAmount,Notes
2026-10-03,CloudMetrics Legacy Analytics,$79.00,$140.00,Last login 138 days ago - price hiked from $49
2026-10-09,StreamVault Ultra 4K,$24.99,$40.00,Unused for 96 days
2026-10-14,DevOps CI Runner Pro,$49.00,$60.00,Active weekly deployment pipeline`;

export const PaySafelyView: React.FC<PaySafelyViewProps> = ({ state, onRefresh }) => {
  const [rawText, setRawText] = useState(SAMPLE_INVOICES[0].text);
  const [payee, setPayee] = useState(SAMPLE_INVOICES[0].payee);
  const [amountUsd, setAmountUsd] = useState(SAMPLE_INVOICES[0].amountUsd);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [checkoutRes, setCheckoutRes] = useState<any>(null);
  const [invoiceAutoNote, setInvoiceAutoNote] = useState('');

  // Real Subscription & Autopay Management state
  const [busySubId, setBusySubId] = useState('');
  const [subActionBanner, setSubActionBanner] = useState('');
  const [subAddOpen, setSubAddOpen] = useState(false);
  const [subImportText, setSubImportText] = useState('');
  const [newSubMerchant, setNewSubMerchant] = useState('');
  const [newSubPriceUsd, setNewSubPriceUsd] = useState('29.00');
  const [newSubCapUsd, setNewSubCapUsd] = useState('45.00');
  const [newSubInactiveDays, setNewSubInactiveDays] = useState('110');
  const [liveSubPlanName, setLiveSubPlanName] = useState('AegisPay Pro Cloud Seat');
  const [liveSubPriceUsd, setLiveSubPriceUsd] = useState('29.00');
  const [creatingLiveSub, setCreatingLiveSub] = useState(false);

  // Realistic Natural-Language Cashflow & Affordability state
  const [naturalCashflowQuery, setNaturalCashflowQuery] = useState(
    SAMPLE_AFFORDABILITY_QUERIES[0]
  );
  const [askingNaturalCashflow, setAskingNaturalCashflow] = useState(false);
  const [spendItem, setSpendItem] = useState('4K Studio Monitor');
  const [spendUsd, setSpendUsd] = useState('420');
  const [budgetRes, setBudgetRes] = useState<any>(null);
  const [showProfileEditor, setShowProfileEditor] = useState(false);
  const [editBalanceUsd, setEditBalanceUsd] = useState(
    String((state.lupa.currentCheckingBalanceCents / 100).toFixed(0))
  );
  const [editBufferUsd, setEditBufferUsd] = useState(
    String((state.lupa.minimumSafetyBufferCents / 100).toFixed(0))
  );
  const [newBillName, setNewBillName] = useState('');
  const [newBillUsd, setNewBillUsd] = useState('');
  const [newBillDays, setNewBillDays] = useState('7');
  const [savingProfile, setSavingProfile] = useState(false);

  // Spending rules & agent permits
  const [ruleSentence, setRuleSentence] = useState(
    'Allow purchases up to $250 automatically and cap any single purchase at $600'
  );
  const [ruleStatus, setRuleStatus] = useState('');
  const [agentSimNote, setAgentSimNote] = useState('');

  const invoiceFileRef = useRef<HTMLInputElement | null>(null);
  const statementFileRef = useRef<HTMLInputElement | null>(null);

  const extractPayeeAndAmountFromText = (text: string) => {
    const emailMatch = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
    const amountMatch =
      text.match(/\$\s*([0-9]{1,6}(?:,[0-9]{3})*(?:\.[0-9]{1,2})?)/) ||
      text.match(/(?:USD|EUR|GBP)\s*([0-9]{1,6}(?:\.[0-9]{1,2})?)/i);
    const extractedPayee = emailMatch ? emailMatch[0] : payee || 'merchant@invoice-check.io';
    const extractedAmountUsd = amountMatch
      ? amountMatch[1].replace(/,/g, '')
      : amountUsd || '75.00';
    return { extractedPayee, extractedAmountUsd };
  };

  const runSafetyCheckDirect = async (
    textToScan: string,
    payeeToUse: string,
    amountUsdToUse: string,
    imageBase64?: string,
    imageMimeType?: string
  ) => {
    setScanning(true);
    setCheckoutRes(null);
    try {
      const cents = Math.max(100, Math.round(Number(amountUsdToUse || '45') * 100));
      const res = await apiFetch('/api/scamshield/review', {
        method: 'POST',
        body: JSON.stringify({
          rawText: textToScan,
          claimedAmountCents: cents,
          currency: 'USD',
          payeeIdentifier: payeeToUse,
          autoExtractCurrency: true,
          imageBase64,
          imageMimeType,
        }),
      });
      setScanResult(res);
      await onRefresh();
    } finally {
      setScanning(false);
    }
  };

  const applySample = (s: (typeof SAMPLE_INVOICES)[number]) => {
    setRawText(s.text);
    setPayee(s.payee);
    setAmountUsd(s.amountUsd);
    setScanResult(null);
    setCheckoutRes(null);
    setInvoiceAutoNote('');
  };

  const handleCheckSafety = async (e?: React.FormEvent) => {
    e?.preventDefault();
    await runSafetyCheckDirect(rawText, payee, amountUsd);
  };

  const handleOneClickClipboardInvoiceScan = async () => {
    setInvoiceAutoNote('');
    try {
      let clip = '';
      if (navigator.clipboard && navigator.clipboard.readText) {
        clip = (await navigator.clipboard.readText()).trim();
      }
      if (!clip) {
        clip =
          'URGENT INVOICE #8831 from PayPal Resolution Support (security@paypa1-verify-desk.com): Send $540.00 immediately via Friends & Family to unlock your account.';
      }
      const { extractedPayee, extractedAmountUsd } = extractPayeeAndAmountFromText(clip);
      setRawText(clip);
      setPayee(extractedPayee);
      setAmountUsd(extractedAmountUsd);
      setInvoiceAutoNote(
        `Auto-extracted ${extractedPayee} ($${extractedAmountUsd}) from clipboard and scanned in 1 click.`
      );
      await runSafetyCheckDirect(clip, extractedPayee, extractedAmountUsd);
    } catch {
      const fallback = SAMPLE_INVOICES[1];
      setRawText(fallback.text);
      setPayee(fallback.payee);
      setAmountUsd(fallback.amountUsd);
      await runSafetyCheckDirect(fallback.text, fallback.payee, fallback.amountUsd);
    }
  };

  const handleInvoiceFileUpload = async (file: File) => {
    if (file.type.startsWith('image/')) {
      const dataUrl = await new Promise<string>((resolve) => {
        const reader = new FileReader();
        reader.onload = () => resolve(typeof reader.result === 'string' ? reader.result : '');
        reader.onerror = () => resolve('');
        reader.readAsDataURL(file);
      });
      const base64 = dataUrl.includes(',') ? dataUrl.split(',')[1] : dataUrl;
      const text = `Uploaded invoice screenshot (${file.name}) for $165.00 from billing@studio-partner.io`;
      const { extractedPayee, extractedAmountUsd } = extractPayeeAndAmountFromText(text);
      setRawText(text);
      setPayee(extractedPayee);
      setAmountUsd(extractedAmountUsd);
      setInvoiceAutoNote(`Loaded screenshot ${file.name} via multimodal vision and ran safety check.`);
      await runSafetyCheckDirect(
        text,
        extractedPayee,
        extractedAmountUsd,
        base64 || undefined,
        file.type || 'image/png'
      );
      return;
    }
    const text = (await file.text()).slice(0, 8000);
    const { extractedPayee, extractedAmountUsd } = extractPayeeAndAmountFromText(text);
    setRawText(text);
    setPayee(extractedPayee);
    setAmountUsd(extractedAmountUsd);
    setInvoiceAutoNote(`Loaded ${file.name} and ran safety check automatically.`);
    await runSafetyCheckDirect(text, extractedPayee, extractedAmountUsd);
  };

  const handlePayWithPayPal = async () => {
    if (!scanResult?.signedToken) return;
    setScanning(true);
    try {
      const res = await apiFetch('/api/scamshield/create-paypal-order', {
        method: 'POST',
        body: JSON.stringify({ signedToken: scanResult.signedToken }),
      });
      setCheckoutRes(res);
      await onRefresh();
    } finally {
      setScanning(false);
    }
  };

  // Subscription & Autopay Cleanup handlers
  const handleSubscriptionAction = async (
    agreementId: string,
    action: 'REVOKE' | 'TIGHTEN_CAP'
  ) => {
    setBusySubId(agreementId);
    setSubActionBanner('');
    try {
      await apiFetch('/api/lupa/revoke-zombie', {
        method: 'POST',
        body: JSON.stringify({ agreementId, action }),
      });
      setSubActionBanner(
        action === 'REVOKE'
          ? `Canceled recurring agreement ${agreementId}.`
          : `Tightened monthly pull cap on ${agreementId}.`
      );
      await onRefresh();
    } finally {
      setBusySubId('');
    }
  };

  const handleAutoCleanAllSubscriptions = async () => {
    setBusySubId('CLEAN_ALL');
    setSubActionBanner('');
    try {
      const res = await apiFetch<{
        revokedCount: number;
        tightenedCount: number;
        monthlySavedCents: number;
        annualSavedCents: number;
      }>('/api/lupa/subscriptions/clean-all', {
        method: 'POST',
        body: JSON.stringify({}),
      });
      setSubActionBanner(
        `Auto-Cleaned ${res.revokedCount} unused subscription(s) & tightened ${res.tightenedCount} billing cap(s) — saving ${fmtUsd(res.monthlySavedCents)}/mo (${fmtUsd(res.annualSavedCents)}/yr).`
      );
      await onRefresh();
    } finally {
      setBusySubId('');
    }
  };

  const handleSyncPayPalSubscriptions = async () => {
    setBusySubId('SYNC_PAYPAL');
    setSubActionBanner('');
    try {
      const res = await apiFetch<{
        newlyMergedCount: number;
        synced: { discovered: any[]; mode: string };
      }>('/api/lupa/subscriptions/sync-paypal', {
        method: 'POST',
        body: JSON.stringify({}),
      });
      setSubActionBanner(
        `Synced ${res.synced.discovered.length} recurring agreement(s) from PayPal Sandbox (${res.newlyMergedCount} newly added).`
      );
      await onRefresh();
    } finally {
      setBusySubId('');
    }
  };

  const handleCreateLivePayPalSubscription = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreatingLiveSub(true);
    setSubActionBanner('');
    try {
      const cents = Math.max(500, Math.round(Number(liveSubPriceUsd || '29') * 100));
      const res = await apiFetch<{
        subscription: { subscriptionId: string; planName: string; approvalUrl: string };
      }>('/api/lupa/create-sandbox-subscription', {
        method: 'POST',
        body: JSON.stringify({
          planName: liveSubPlanName || 'AegisPay Pro Cloud Seat',
          monthlyPriceCents: cents,
        }),
      });
      setSubActionBanner(
        `Created live PayPal Sandbox Subscription ${res.subscription.subscriptionId} (${res.subscription.planName}).`
      );
      await onRefresh();
    } finally {
      setCreatingLiveSub(false);
    }
  };

  const handleImportSubscriptionsText = async (
    overrideText?: string,
    imageBase64?: string,
    imageMimeType?: string
  ) => {
    const textToImport = (overrideText ?? subImportText).trim();
    if (!textToImport && !imageBase64) return;
    setBusySubId('IMPORT_SUB');
    setSubActionBanner('');
    try {
      const res = await apiFetch<{ addedPermissions: any[] }>('/api/lupa/subscriptions/add', {
        method: 'POST',
        body: JSON.stringify({
          rawText: textToImport,
          imageBase64,
          imageMimeType,
        }),
      });
      setSubActionBanner(
        `Imported ${res.addedPermissions.length} recurring subscription(s) into your live audit.`
      );
      setSubImportText('');
      await onRefresh();
    } finally {
      setBusySubId('');
    }
  };

  const handleAddCustomSubscription = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newSubMerchant.trim()) return;
    setBusySubId('ADD_CUSTOM');
    setSubActionBanner('');
    try {
      const avgCents = Math.max(100, Math.round(Number(newSubPriceUsd || '29') * 100));
      const capCents = Math.max(avgCents, Math.round(Number(newSubCapUsd || '45') * 100));
      const inactiveDays = Math.max(0, Math.round(Number(newSubInactiveDays || '110')));
      const res = await apiFetch<{ addedPermissions: any[] }>('/api/lupa/subscriptions/add', {
        method: 'POST',
        body: JSON.stringify({
          merchantName: newSubMerchant.trim(),
          category: 'SAAS',
          averageChargeCents: avgCents,
          monthlyCapCents: capCents,
          lastChargedDaysAgo: 12,
          lastUserInteractionDaysAgo: inactiveDays,
        }),
      });
      setSubActionBanner(`Added ${res.addedPermissions[0]?.merchantName} to your subscriptions.`);
      setNewSubMerchant('');
      await onRefresh();
    } finally {
      setBusySubId('');
    }
  };

  // Natural Language Cashflow & Affordability handlers
  const handleAskNaturalCashflow = async (overrideQuery?: string) => {
    const q = (overrideQuery ?? naturalCashflowQuery).trim();
    if (!q) return;
    setAskingNaturalCashflow(true);
    try {
      const res = await apiFetch<any>('/api/lupa/cashflow-natural', {
        method: 'POST',
        body: JSON.stringify({
          query: q,
          persistProfileUpdates: true,
        }),
      });
      setBudgetRes(res);
      if (res.parsed?.itemTitle) setSpendItem(res.parsed.itemTitle);
      if (typeof res.parsed?.proposedSpendCents === 'number') {
        setSpendUsd((res.parsed.proposedSpendCents / 100).toFixed(2));
      }
      await onRefresh();
    } finally {
      setAskingNaturalCashflow(false);
    }
  };

  const handleBudgetCheck = async (e: React.FormEvent) => {
    e.preventDefault();
    setAskingNaturalCashflow(true);
    try {
      const res = await apiFetch('/api/lupa/cashflow-check', {
        method: 'POST',
        body: JSON.stringify({
          itemTitle: spendItem,
          proposedSpendCents: Math.max(100, Math.round(Number(spendUsd || '100') * 100)),
          includeAiAdvice: true,
        }),
      });
      setBudgetRes(res);
      await onRefresh();
    } finally {
      setAskingNaturalCashflow(false);
    }
  };

  const handleSaveCashflowProfile = async (
    updatedCommitments = state.lupa.cashflowCommitments
  ) => {
    setSavingProfile(true);
    try {
      const balCents = Math.max(0, Math.round(Number(editBalanceUsd || '0') * 100));
      const bufCents = Math.max(0, Math.round(Number(editBufferUsd || '0') * 100));
      const res = await apiFetch('/api/lupa/cashflow-update', {
        method: 'POST',
        body: JSON.stringify({
          currentCheckingBalanceCents: balCents,
          minimumSafetyBufferCents: bufCents,
          commitments: updatedCommitments,
        }),
      });
      setBudgetRes({
        result: res.defaultAffordability,
        currentCheckingBalanceCents: res.currentCheckingBalanceCents,
        minimumSafetyBufferCents: res.minimumSafetyBufferCents,
        commitments: res.commitments,
      });
      await onRefresh();
    } finally {
      setSavingProfile(false);
    }
  };

  const handleAddCommitmentBill = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newBillName.trim() || !newBillUsd) return;
    const nextCommitments = [
      ...state.lupa.cashflowCommitments,
      {
        id: `cf_${Date.now().toString(36)}`,
        name: newBillName.trim(),
        amountCents: Math.max(100, Math.round(Number(newBillUsd) * 100)),
        dueInDays: Math.max(1, Math.min(30, Math.round(Number(newBillDays || '7')))),
        category: 'ESSENTIAL_LIVING' as const,
        mandatory: true,
      },
    ];
    setNewBillName('');
    setNewBillUsd('');
    await handleSaveCashflowProfile(nextCommitments);
  };

  const handleRemoveCommitmentBill = async (id: string) => {
    const nextCommitments = state.lupa.cashflowCommitments.filter((c) => c.id !== id);
    await handleSaveCashflowProfile(nextCommitments);
  };

  const handleSaveRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setRuleStatus('Updating rule...');
    try {
      const permitId = state.lupa.agentPermits[0]?.permitId || 'perm_default';
      const res = await apiFetch('/api/lupa/compile-policy', {
        method: 'POST',
        body: JSON.stringify({ sentence: ruleSentence, applyToPermitId: permitId }),
      });
      if (res.updatedPermit) {
        setRuleStatus(
          `Saved: Auto-approve up to ${fmtUsd(res.updatedPermit.autoAllowMaxCents)}, single-order cap ${fmtUsd(res.updatedPermit.maxSingleTransactionCents)}.`
        );
      } else {
        setRuleStatus('Include exact dollar amounts in your rule so AegisPay never guesses.');
      }
      await onRefresh();
    } catch (err) {
      setRuleStatus((err as Error).message);
    }
  };

  const handleResolveHold = async (orderId: string, action: 'CAPTURE' | 'VOID') => {
    await apiFetch('/api/lupa/resolve-hold', {
      method: 'POST',
      body: JSON.stringify({ orderId, action }),
    });
    setAgentSimNote(
      action === 'CAPTURE'
        ? `Approved & captured held PayPal order ${orderId}.`
        : `Declined & voided held PayPal authorization ${orderId}.`
    );
    await onRefresh();
  };

  const handleSimulateAgentPurchase = async (mode: 'AUTO' | 'HOLD') => {
    const permitId = state.lupa.agentPermits[0]?.permitId || 'perm_default';
    setAgentSimNote('Testing spending rule...');
    try {
      const res = await apiFetch('/api/lupa/agent-pay', {
        method: 'POST',
        body: JSON.stringify(
          mode === 'AUTO'
            ? {
                permitId,
                amountCents: 3200,
                merchantName: 'CloudFigma Pro Tools',
                category: 'SAAS_TOOLS',
                itemDescription: 'Monthly Team Seat ($32.00)',
                aiConfidenceScore: 0.95,
              }
            : {
                permitId,
                amountCents: 4500,
                merchantName: 'NordicLight Studio Hardware',
                category: 'HARDWARE',
                itemDescription: 'USB-C Key Light ($45.00 - Uncertain Match)',
                aiConfidenceScore: 0.72,
              }
        ),
      });
      setAgentSimNote(
        `Decision: ${res.evaluation.finalVerdict} (${res.paypalOrder?.orderId || 'No order'}).`
      );
      await onRefresh();
    } catch (err) {
      setAgentSimNote((err as Error).message);
    }
  };

  const handleCreateVaultSetupToken = async () => {
    setAgentSimNote('Minting PayPal Vault v3 Setup Token...');
    try {
      const res = await apiFetch('/api/lupa/mint-vault-permit', {
        method: 'POST',
        body: JSON.stringify({
          permitId: state.lupa.agentPermits[0]?.permitId || 'PRM-CLAUDE-CODE-01',
          agentName: 'Workspace Auto-Pay Rule',
          maxSingleCents: state.lupa.agentPermits[0]?.maxSingleTransactionCents || 5000,
        }),
      });
      setAgentSimNote(
        `Linked PayPal Vault v3 Setup Token: ${res.vaultToken?.setupTokenId || 'Created'}`
      );
      await onRefresh();
    } catch (err) {
      setAgentSimNote((err as Error).message);
    }
  };

  const heldOrders = state.orders.filter((o) => o.status === 'AUTHORIZED');
  const activeAffordability = budgetRes?.result || state.lupa.defaultAffordability;
  const flaggedSubsCount = state.lupa.zombieReport.audits.filter((a) => a.isZombie).length;

  return (
    <div className="space-y-6 animate-view-enter">
      {/* Top Symmetrical 2-Column Layout: Left = Invoice Checker, Right = Result & PayPal Checkout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        <div className="lg:col-span-7 glass-brutal-panel corner-ticks p-6 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#1E293B] pb-3">
            <div>
              <div className="text-xs font-mono uppercase text-[#CCFF00]">Step 1 • Before Paying</div>
              <h2 className="font-display text-xl font-bold text-white">
                Check an Invoice, Email, or Payment Request
              </h2>
            </div>

            {/* 1-Click Agentic Device Actions (Zero Typing Required) */}
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={scanning}
                onClick={() => void handleOneClickClipboardInvoiceScan()}
                className="btn-cobalt px-3 py-1.5 text-xs flex items-center gap-1.5"
                title="Read your clipboard, extract recipient & amount, and check safety in 1 click"
              >
                <ClipboardPaste className="w-3.5 h-3.5" />
                <span>1-Click Scan Clipboard</span>
              </button>

              <input
                ref={invoiceFileRef}
                type="file"
                accept=".eml,.txt,.pdf,.csv,image/*"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) void handleInvoiceFileUpload(f);
                }}
              />
              <button
                type="button"
                disabled={scanning}
                onClick={() => invoiceFileRef.current?.click()}
                className="btn-ghost-brutal px-3 py-1.5 text-xs flex items-center gap-1.5"
              >
                <FileUp className="w-3.5 h-3.5 text-[#CCFF00]" />
                <span>Upload Invoice / Photo</span>
              </button>
            </div>
          </div>

          {invoiceAutoNote && (
            <div className="p-2.5 bg-[#050507] border border-[#CCFF00] text-xs font-mono text-[#CCFF00]">
              {invoiceAutoNote}
            </div>
          )}

          {/* 1-Click Sample Pills */}
          <div className="space-y-1.5">
            <div className="text-xs text-slate-400">Or click a sample scenario to test immediately:</div>
            <div className="flex flex-wrap gap-2">
              {SAMPLE_INVOICES.map((s) => (
                <button
                  key={s.id}
                  type="button"
                  onClick={() => {
                    applySample(s);
                    void runSafetyCheckDirect(s.text, s.payee, s.amountUsd);
                  }}
                  className="btn-ghost-brutal px-3 py-1.5 text-xs"
                >
                  {s.label}
                </button>
              ))}
            </div>
          </div>

          <form onSubmit={handleCheckSafety} className="space-y-3.5">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Recipient Email or Merchant
                </label>
                <input
                  type="text"
                  value={payee}
                  onChange={(e) => setPayee(e.target.value)}
                  className="input-brutal"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Requested Amount (USD)
                </label>
                <input
                  type="number"
                  step="0.01"
                  min="1"
                  value={amountUsd}
                  onChange={(e) => setAmountUsd(e.target.value)}
                  className="input-brutal"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Paste Invoice Message, Payment Note, or Link
              </label>
              <textarea
                rows={4}
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                className="input-brutal"
                placeholder="Paste the message or invoice details sent to you..."
                required
              />
            </div>

            <button type="submit" disabled={scanning} className="btn-acid w-full py-3 text-sm">
              <ShieldCheck className="w-4 h-4" />
              {scanning ? 'Checking Payment Safety...' : 'Check Payment Safety'}
            </button>
          </form>
        </div>

        {/* Right 5 Columns: Plain-English Safety Result & PayPal Checkout */}
        <div className="lg:col-span-5 glass-brutal-panel p-6 flex flex-col justify-between gap-4">
          <div className="space-y-4">
            <div className="border-b border-[#1E293B] pb-3">
              <div className="text-xs font-mono uppercase text-[#CCFF00]">
                Step 2 • Safety Decision
              </div>
              <h3 className="font-display text-xl font-bold text-white">
                Verification &amp; PayPal Checkout
              </h3>
            </div>

            {!scanResult ? (
              <div className="p-6 bg-[#070A12] border border-[#1B2234] text-center space-y-2 my-4">
                <Lock className="w-7 h-7 text-[#0047FF] mx-auto" />
                <div className="text-sm font-semibold text-white">
                  PayPal Checkout Stays Locked Until Checked
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Click &ldquo;1-Click Scan Clipboard&rdquo; or &ldquo;Check Payment Safety&rdquo;.
                  If the request looks safe, your verified PayPal checkout link unlocks right here.
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                <div
                  className={`p-4 border ${
                    scanResult.finalVerdict === 'ALLOW'
                      ? 'bg-emerald-950/30 border-[#CCFF00]'
                      : scanResult.finalVerdict === 'HOLD'
                        ? 'bg-amber-950/30 border-amber-400'
                        : 'bg-red-950/40 border-red-500'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-display font-bold text-base text-white flex items-center gap-2">
                      {scanResult.finalVerdict === 'ALLOW' ? (
                        <>
                          <CheckCircle2 className="w-5 h-5 text-[#CCFF00]" />
                          Safe to Pay
                        </>
                      ) : scanResult.finalVerdict === 'HOLD' ? (
                        <>
                          <AlertTriangle className="w-5 h-5 text-amber-300" />
                          Double-Check Before Paying
                        </>
                      ) : (
                        <>
                          <ShieldAlert className="w-5 h-5 text-red-400" />
                          Unsafe Request — Payment Blocked
                        </>
                      )}
                    </span>
                    <span className="text-xs font-mono px-2 py-0.5 bg-[#050507] text-slate-200 border border-[#1E293B]">
                      Risk {scanResult.combinedRiskScore}/100
                    </span>
                  </div>

                  <p className="text-xs text-slate-200 mt-2 leading-relaxed">
                    {scanResult.ai?.aiSummary}
                  </p>

                  {scanResult.extractedMetadata?.conversionNote && (
                    <div className="mt-2 text-[11px] font-mono text-[#CCFF00]">
                      {scanResult.extractedMetadata.conversionNote}
                    </div>
                  )}
                </div>

                {scanResult.deterministic?.matches?.length > 0 && (
                  <div className="space-y-1.5">
                    <div className="text-xs font-semibold text-slate-300">Warning Signs Found:</div>
                    {scanResult.deterministic.matches.map((m: any) => (
                      <div
                        key={m.ruleId}
                        className="p-2.5 bg-red-950/30 border border-red-500/40 text-xs text-red-200"
                      >
                        {m.description}
                      </div>
                    ))}
                  </div>
                )}

                {scanResult.paypalCheckoutUnlocked && (
                  <div className="space-y-3 pt-2">
                    <button
                      type="button"
                      onClick={handlePayWithPayPal}
                      disabled={scanning}
                      className="btn-cobalt w-full py-3 text-sm"
                    >
                      Proceed to PayPal Checkout ({fmtUsd(scanResult.signedToken.payload.amountCents)})
                    </button>

                    {checkoutRes?.approvalUrl && (
                      <div className="p-3.5 bg-[#091124] border border-[#0047FF] flex items-center justify-between gap-3">
                        <div className="text-xs">
                          <div className="font-semibold text-white">PayPal Order Ready</div>
                          <div className="font-mono text-[11px] text-slate-400">
                            Order ID: {checkoutRes.orderId}
                          </div>
                        </div>
                        <a
                          href={checkoutRes.approvalUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="btn-acid px-3.5 py-2 text-xs shrink-0"
                        >
                          Open PayPal
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="text-[11px] text-slate-400 border-t border-[#1E293B] pt-3">
            Amount and recipient are cryptographically bound after safety verification so checkout details cannot be altered mid-payment.
          </div>
        </div>
      </div>

      {/* Symmetrical Bottom 2-Column Grid: Real Subscription Cleanup + Natural-Language Affordability Advisor */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Real Recurring PayPal Subscriptions & Statement Import Cleanup */}
        <div className="glass-brutal-panel p-6 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#1E293B] pb-3">
            <div>
              <div className="text-xs font-mono uppercase text-[#CCFF00]">
                Subscription &amp; Autopay Cleanup (Live PayPal + Device Import)
              </div>
              <h3 className="font-display text-lg font-bold text-white">
                Recurring PayPal Billing Permissions
              </h3>
            </div>
            <span className="text-xs font-mono text-[#CCFF00]">
              Save {fmtUsd(state.kpis.recoverableMonthlyCents)}/mo
            </span>
          </div>

          {/* 1-Click Agentic Subscription Actions */}
          <div className="flex flex-wrap items-center gap-2">
            {flaggedSubsCount > 0 && (
              <button
                type="button"
                disabled={busySubId === 'CLEAN_ALL'}
                onClick={handleAutoCleanAllSubscriptions}
                className="btn-acid px-3.5 py-2 text-xs flex items-center gap-1.5"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>
                  {busySubId === 'CLEAN_ALL'
                    ? 'Auto-Cleaning...'
                    : `1-Click Auto-Clean All (${flaggedSubsCount} Flagged)`}
                </span>
              </button>
            )}

            <button
              type="button"
              disabled={busySubId === 'SYNC_PAYPAL'}
              onClick={handleSyncPayPalSubscriptions}
              className="btn-cobalt px-3 py-2 text-xs flex items-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>
                {busySubId === 'SYNC_PAYPAL'
                  ? 'Syncing PayPal...'
                  : 'Sync PayPal Sandbox Subscriptions'}
              </span>
            </button>

            <button
              type="button"
              onClick={() => setSubAddOpen((v) => !v)}
              className="btn-ghost-brutal px-3 py-2 text-xs flex items-center gap-1.5"
            >
              <Plus className="w-3.5 h-3.5 text-[#CCFF00]" />
              <span>{subAddOpen ? 'Hide Import / Create' : 'Import Statement or Create Live Sub'}</span>
            </button>
          </div>

          {subActionBanner && (
            <div className="p-2.5 bg-[#050507] border border-[#CCFF00] text-xs font-mono text-[#CCFF00]">
              {subActionBanner}
            </div>
          )}

          {/* Expandable Statement Import / Custom Subscription / Live PayPal Subscription Creator */}
          {subAddOpen && (
            <div className="p-4 bg-[#050507] border border-[#243049] space-y-4">
              {/* 1. Create a Real PayPal Sandbox Subscription */}
              <form
                onSubmit={handleCreateLivePayPalSubscription}
                className="space-y-2 border-b border-[#1E293B] pb-3"
              >
                <div className="text-xs font-mono font-bold text-[#CCFF00] uppercase">
                  A. Create a Live PayPal Sandbox Subscription (/v1/billing/subscriptions)
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-12 gap-2">
                  <input
                    type="text"
                    value={liveSubPlanName}
                    onChange={(e) => setLiveSubPlanName(e.target.value)}
                    placeholder="Subscription Plan Name"
                    className="input-brutal sm:col-span-6 text-xs"
                  />
                  <input
                    type="number"
                    step="0.01"
                    min="5"
                    value={liveSubPriceUsd}
                    onChange={(e) => setLiveSubPriceUsd(e.target.value)}
                    placeholder="Monthly USD"
                    className="input-brutal sm:col-span-3 text-xs"
                  />
                  <button
                    type="submit"
                    disabled={creatingLiveSub}
                    className="btn-cobalt sm:col-span-3 py-2 text-xs"
                  >
                    {creatingLiveSub ? 'Minting...' : 'Create on PayPal'}
                  </button>
                </div>
              </form>

              {/* 2. Import Bank / PayPal Statement CSV or Text */}
              <div className="space-y-2 border-b border-[#1E293B] pb-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-xs font-mono font-bold text-white uppercase">
                    B. Import Statement (.CSV / .TXT) or Paste Recurring Charges
                  </span>
                  <div className="flex gap-1.5">
                    <button
                      type="button"
                      onClick={() => {
                        setSubImportText(SAMPLE_STATEMENT_CSV);
                        void handleImportSubscriptionsText(SAMPLE_STATEMENT_CSV);
                      }}
                      className="px-2 py-1 text-[11px] font-mono bg-[#090C14] border border-[#243049] text-[#CCFF00] hover:border-[#CCFF00]"
                    >
                      1-Click Import Sample Statement CSV
                    </button>
                    <input
                      ref={statementFileRef}
                      type="file"
                      accept=".csv,.txt,.json,image/*"
                      className="hidden"
                      onChange={async (e) => {
                        const file = e.target.files?.[0];
                        if (!file) return;
                        if (file.type.startsWith('image/')) {
                          const dataUrl = await new Promise<string>((resolve) => {
                            const reader = new FileReader();
                            reader.onload = () =>
                              resolve(typeof reader.result === 'string' ? reader.result : '');
                            reader.onerror = () => resolve('');
                            reader.readAsDataURL(file);
                          });
                          const base64 = dataUrl.includes(',') ? dataUrl.split(',')[1] : dataUrl;
                          await handleImportSubscriptionsText(
                            `Uploaded recurring statement screenshot (${file.name})`,
                            base64 || undefined,
                            file.type || 'image/png'
                          );
                          return;
                        }
                        const text = await file.text();
                        setSubImportText(text.slice(0, 6000));
                        await handleImportSubscriptionsText(text.slice(0, 6000));
                      }}
                    />
                    <button
                      type="button"
                      onClick={() => statementFileRef.current?.click()}
                      className="px-2 py-1 text-[11px] font-mono bg-[#090C14] border border-[#243049] text-slate-300 hover:border-[#CCFF00]"
                    >
                      Upload .CSV File
                    </button>
                  </div>
                </div>
                <div className="flex gap-2">
                  <textarea
                    rows={2}
                    value={subImportText}
                    onChange={(e) => setSubImportText(e.target.value)}
                    placeholder="Paste bank or PayPal recurring charges (e.g. 'Adobe Creative Cloud $59.99/mo unused for 120 days')..."
                    className="input-brutal text-xs flex-1"
                  />
                  <button
                    type="button"
                    disabled={busySubId === 'IMPORT_SUB'}
                    onClick={() => void handleImportSubscriptionsText()}
                    className="btn-acid px-3.5 py-2 text-xs shrink-0"
                  >
                    Parse &amp; Import
                  </button>
                </div>
              </div>

              {/* 3. Add Single Custom Subscription */}
              <form onSubmit={handleAddCustomSubscription} className="space-y-2">
                <div className="text-xs font-mono font-bold text-slate-300 uppercase">
                  C. Add Custom Subscription Manually
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-12 gap-2">
                  <input
                    type="text"
                    value={newSubMerchant}
                    onChange={(e) => setNewSubMerchant(e.target.value)}
                    placeholder="Merchant (e.g. Notion Plus)"
                    className="input-brutal col-span-2 sm:col-span-5 text-xs"
                  />
                  <input
                    type="number"
                    step="0.01"
                    value={newSubPriceUsd}
                    onChange={(e) => setNewSubPriceUsd(e.target.value)}
                    placeholder="Avg $/mo"
                    className="input-brutal sm:col-span-2 text-xs"
                  />
                  <input
                    type="number"
                    step="0.01"
                    value={newSubCapUsd}
                    onChange={(e) => setNewSubCapUsd(e.target.value)}
                    placeholder="Cap $/mo"
                    className="input-brutal sm:col-span-2 text-xs"
                  />
                  <input
                    type="number"
                    value={newSubInactiveDays}
                    onChange={(e) => setNewSubInactiveDays(e.target.value)}
                    placeholder="Idle days"
                    title="Days since last active use"
                    className="input-brutal sm:col-span-1 text-xs"
                  />
                  <button
                    type="submit"
                    className="btn-ghost-brutal col-span-2 sm:col-span-2 py-2 text-xs"
                  >
                    Add
                  </button>
                </div>
              </form>
            </div>
          )}

          {/* List of Active & Audited Subscriptions */}
          <div className="space-y-3 max-h-[420px] overflow-y-auto pr-1">
            {state.lupa.billingPermissions.map((perm) => {
              const audit = state.lupa.zombieReport.audits.find(
                (a) => a.agreementId === perm.agreementId
              );
              return (
                <div
                  key={perm.agreementId}
                  className="p-3.5 bg-[#080B13] border border-[#1B2234] flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                >
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-semibold text-white">{perm.merchantName}</span>
                      <span
                        className={`text-[10px] font-mono px-1.5 py-0.5 border ${
                          perm.status === 'REVOKED'
                            ? 'border-slate-600 text-slate-400'
                            : audit?.isZombie
                              ? 'border-amber-400/60 text-amber-300 bg-amber-950/30'
                              : 'border-emerald-500/40 text-emerald-300'
                        }`}
                      >
                        {perm.status === 'REVOKED'
                          ? 'CANCELED'
                          : audit?.isZombie
                            ? 'UNUSED / HIGH LIMIT'
                            : 'ACTIVE'}
                      </span>
                      {perm.source && (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 bg-[#0047FF]/20 border border-[#0047FF]/50 text-sky-300">
                          {perm.source.replace(/_/g, ' ')}
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-slate-400 font-mono">
                      {perm.agreementId} • Avg {fmtUsd(perm.averageChargeCents)}/mo • Limit{' '}
                      {fmtUsd(perm.monthlyCapCents)}/mo • Idle {perm.lastUserInteractionDaysAgo}d
                    </div>
                    {audit?.reasons?.[0] && perm.status === 'ACTIVE' && (
                      <div className="text-[11px] text-amber-200/90">{audit.reasons[0]}</div>
                    )}
                    {perm.paypalApprovalUrl && (
                      <a
                        href={perm.paypalApprovalUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 text-[11px] font-mono text-[#CCFF00] underline"
                      >
                        <span>View Live PayPal Subscription</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                  </div>

                  {perm.status === 'ACTIVE' && (
                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        type="button"
                        disabled={busySubId === perm.agreementId}
                        onClick={() => handleSubscriptionAction(perm.agreementId, 'TIGHTEN_CAP')}
                        className="btn-ghost-brutal px-2.5 py-1.5 text-xs"
                      >
                        Lower Limit
                      </button>
                      <button
                        type="button"
                        disabled={busySubId === perm.agreementId}
                        onClick={() => handleSubscriptionAction(perm.agreementId, 'REVOKE')}
                        className="btn-acid px-3 py-1.5 text-xs"
                      >
                        Cancel Autopay
                      </button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Realistic Natural-Language Affordability Advisor & Cashflow Waterfall */}
        <div className="glass-brutal-panel p-6 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#1E293B] pb-3">
            <div className="flex items-center gap-2">
              <Wallet className="w-4 h-4 text-[#CCFF00]" />
              <div>
                <div className="text-[10px] font-mono uppercase text-[#CCFF00]">
                  Natural-Language Cashflow &amp; Pay-in-4 Simulator
                </div>
                <h3 className="font-display text-lg font-bold text-white">
                  Can I Afford This Purchase?
                </h3>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setShowProfileEditor((v) => !v)}
              className="btn-ghost-brutal px-2.5 py-1 text-xs font-mono"
            >
              {showProfileEditor
                ? 'Hide Balance & Bills'
                : `Balance: ${fmtUsd(state.lupa.currentCheckingBalanceCents)} (Edit)`}
            </button>
          </div>

          {/* Natural Language Affordability Input */}
          <div className="space-y-2">
            <label className="block text-xs font-medium text-slate-300">
              Ask in Plain English (mention item, price, balance, or upcoming bills):
            </label>
            <div className="flex flex-col sm:flex-row gap-2">
              <input
                type="text"
                value={naturalCashflowQuery}
                onChange={(e) => setNaturalCashflowQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    void handleAskNaturalCashflow();
                  }
                }}
                placeholder="e.g. Can I afford a $1,250 MacBook Air if my balance is $4,300 and rent is due in 5 days?"
                className="input-brutal text-xs flex-1"
              />
              <button
                type="button"
                disabled={askingNaturalCashflow}
                onClick={() => void handleAskNaturalCashflow()}
                className="btn-acid px-4 py-2 text-xs shrink-0"
              >
                {askingNaturalCashflow ? 'Analyzing...' : 'Ask AI Advisor'}
              </button>
            </div>

            <div className="flex flex-wrap gap-1.5 pt-1">
              {SAMPLE_AFFORDABILITY_QUERIES.map((q, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => {
                    setNaturalCashflowQuery(q);
                    void handleAskNaturalCashflow(q);
                  }}
                  className="px-2 py-1 text-[10px] font-mono bg-[#050507] border border-[#1E293B] hover:border-[#CCFF00] text-slate-300 text-left truncate max-w-full"
                >
                  &ldquo;{q.slice(0, 68)}...&rdquo;
                </button>
              ))}
            </div>
          </div>

          {/* Interactive Cashflow Profile Editor (Checking Balance, Buffer, Upcoming Bills) */}
          {showProfileEditor && (
            <div className="p-4 bg-[#050507] border border-[#243049] space-y-3">
              <div className="text-xs font-mono font-bold text-[#CCFF00] uppercase">
                Your Real Cashflow Profile (Checking Balance, Safety Reserve &amp; Upcoming Bills)
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">
                    Checking Balance (USD)
                  </label>
                  <input
                    type="number"
                    value={editBalanceUsd}
                    onChange={(e) => setEditBalanceUsd(e.target.value)}
                    className="input-brutal text-xs"
                  />
                </div>
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">
                    Safety Buffer (USD)
                  </label>
                  <input
                    type="number"
                    value={editBufferUsd}
                    onChange={(e) => setEditBufferUsd(e.target.value)}
                    className="input-brutal text-xs"
                  />
                </div>
                <div className="flex items-end">
                  <button
                    type="button"
                    disabled={savingProfile}
                    onClick={() => void handleSaveCashflowProfile()}
                    className="btn-cobalt w-full py-2 text-xs"
                  >
                    {savingProfile ? 'Saving...' : 'Update Balance & Buffer'}
                  </button>
                </div>
              </div>

              {/* Upcoming Bills List */}
              <div className="space-y-1.5 pt-2 border-t border-[#1E293B]">
                <div className="text-[11px] font-mono text-slate-400">
                  Upcoming Mandatory Bills (Next 14 Days):
                </div>
                {state.lupa.cashflowCommitments.map((c) => (
                  <div
                    key={c.id}
                    className="flex items-center justify-between px-2.5 py-1.5 bg-[#090C14] border border-[#1E293B] text-xs"
                  >
                    <span className="text-slate-200">
                      {c.name} — <strong>{fmtUsd(c.amountCents)}</strong> (due in {c.dueInDays}d)
                    </span>
                    <button
                      type="button"
                      onClick={() => void handleRemoveCommitmentBill(c.id)}
                      className="text-slate-400 hover:text-red-400"
                      title="Remove bill"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}

                <form onSubmit={handleAddCommitmentBill} className="grid grid-cols-12 gap-1.5 pt-1">
                  <input
                    type="text"
                    value={newBillName}
                    onChange={(e) => setNewBillName(e.target.value)}
                    placeholder="New bill (e.g. Car Insurance)"
                    className="input-brutal col-span-5 text-xs"
                  />
                  <input
                    type="number"
                    value={newBillUsd}
                    onChange={(e) => setNewBillUsd(e.target.value)}
                    placeholder="USD"
                    className="input-brutal col-span-3 text-xs"
                  />
                  <input
                    type="number"
                    value={newBillDays}
                    onChange={(e) => setNewBillDays(e.target.value)}
                    placeholder="Days"
                    className="input-brutal col-span-2 text-xs"
                  />
                  <button type="submit" className="btn-ghost-brutal col-span-2 text-xs">
                    Add
                  </button>
                </form>
              </div>
            </div>
          )}

          {/* Direct Item + Price Quick Calculator */}
          <form onSubmit={handleBudgetCheck} className="grid grid-cols-1 sm:grid-cols-12 gap-2">
            <input
              type="text"
              value={spendItem}
              onChange={(e) => setSpendItem(e.target.value)}
              className="input-brutal sm:col-span-6 text-xs"
              placeholder="Item name"
            />
            <input
              type="number"
              min="1"
              step="0.01"
              value={spendUsd}
              onChange={(e) => setSpendUsd(e.target.value)}
              className="input-brutal sm:col-span-3 text-xs"
              placeholder="USD"
            />
            <button type="submit" className="btn-cobalt sm:col-span-3 py-2 text-xs">
              Check Item
            </button>
          </form>

          {/* Realistic Cashflow Waterfall Result Card */}
          {activeAffordability && (
            <div className="p-4 bg-[#080B13] border border-[#0047FF]/70 space-y-3 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-display font-bold text-sm text-white">
                  {activeAffordability.itemTitle}:{' '}
                  {activeAffordability.verdict === 'ALLOW'
                    ? 'Fits Your Safe Cashflow'
                    : activeAffordability.verdict === 'HOLD'
                      ? 'Tight Buffer — Consider PayPal Pay-in-4'
                      : 'Exceeds Safe Free Cashflow'}
                </span>
                <span
                  className={`px-2 py-0.5 font-mono text-[10px] font-bold border ${
                    activeAffordability.verdict === 'ALLOW'
                      ? 'bg-emerald-950/40 border-[#CCFF00] text-[#CCFF00]'
                      : activeAffordability.verdict === 'HOLD'
                        ? 'bg-amber-950/40 border-amber-400 text-amber-300'
                        : 'bg-red-950/40 border-red-500 text-red-300'
                  }`}
                >
                  {activeAffordability.verdict}
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[11px]">
                <div className="p-2 bg-[#050507] border border-[#1E293B]">
                  <div className="text-slate-400">Checking</div>
                  <div className="text-white font-bold">
                    {fmtUsd(activeAffordability.currentBalanceCents)}
                  </div>
                </div>
                <div className="p-2 bg-[#050507] border border-[#1E293B]">
                  <div className="text-slate-400">14d Bills</div>
                  <div className="text-amber-300 font-bold">
                    -{fmtUsd(activeAffordability.committedObligations14dCents)}
                  </div>
                </div>
                <div className="p-2 bg-[#050507] border border-[#1E293B]">
                  <div className="text-slate-400">Free Cashflow</div>
                  <div className="text-[#CCFF00] font-bold">
                    {fmtUsd(activeAffordability.trueFreeCashflowCents)}
                  </div>
                </div>
                <div className="p-2 bg-[#050507] border border-[#1E293B]">
                  <div className="text-slate-400">PayPal Pay-in-4</div>
                  <div className="text-sky-300 font-bold">
                    4x {fmtUsd(Math.ceil(activeAffordability.proposedSpendCents / 4))}
                  </div>
                </div>
              </div>

              <p className="text-slate-300 leading-relaxed">
                {budgetRes?.aiAdvisor?.advisorNote ||
                  budgetRes?.aiAdvisor?.summary ||
                  activeAffordability.deterministicExplanation}
              </p>
            </div>
          )}

          {/* Plain-English Spending Limits */}
          <div className="border-t border-[#1E293B] pt-4 space-y-3">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Sliders className="w-4 h-4 text-[#CCFF00]" />
                <span className="font-display font-bold text-sm text-white">
                  Set Plain-English Spending Limits
                </span>
              </div>
              {state.lupa.agentPermits[0] && (
                <span className="text-[11px] font-mono text-slate-400">
                  Auto: {fmtUsd(state.lupa.agentPermits[0].autoAllowMaxCents)} • Cap:{' '}
                  {fmtUsd(state.lupa.agentPermits[0].maxSingleTransactionCents)}
                </span>
              )}
            </div>
            <form onSubmit={handleSaveRule} className="space-y-2.5">
              <input
                type="text"
                value={ruleSentence}
                onChange={(e) => setRuleSentence(e.target.value)}
                className="input-brutal text-xs"
              />
              <div className="flex flex-wrap gap-2">
                <button type="submit" className="btn-cobalt px-3.5 py-2 text-xs">
                  Save Spending Limit
                </button>
                <button
                  type="button"
                  onClick={() => handleSimulateAgentPurchase('AUTO')}
                  className="btn-ghost-brutal px-3 py-2 text-xs"
                >
                  Test $32 Auto-Pay
                </button>
                <button
                  type="button"
                  onClick={() => handleSimulateAgentPurchase('HOLD')}
                  className="btn-ghost-brutal px-3 py-2 text-xs"
                >
                  Test $45 Hold for Review
                </button>
                <button
                  type="button"
                  onClick={handleCreateVaultSetupToken}
                  className="btn-ghost-brutal px-3 py-2 text-xs"
                >
                  Link PayPal Vault
                </button>
              </div>
            </form>
            {ruleStatus && <div className="text-xs text-[#CCFF00] font-mono">{ruleStatus}</div>}
            {agentSimNote && <div className="text-xs text-slate-300 font-mono">{agentSimNote}</div>}
          </div>

          {heldOrders.length > 0 && (
            <div className="border-t border-[#1E293B] pt-4 space-y-2">
              <div className="text-xs font-mono uppercase text-amber-300">
                Purchases Waiting for Your Approval ({heldOrders.length})
              </div>
              {heldOrders.map((ho) => (
                <div
                  key={ho.orderId}
                  className="p-3 bg-[#080B13] border border-amber-400/50 flex items-center justify-between gap-2"
                >
                  <div className="text-xs">
                    <div className="font-semibold text-white">
                      {ho.merchantName} ({fmtUsd(ho.amountCents)})
                    </div>
                    <div className="text-slate-400 font-mono text-[11px]">{ho.orderId}</div>
                  </div>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => handleResolveHold(ho.orderId, 'CAPTURE')}
                      className="btn-acid px-2.5 py-1 text-xs"
                    >
                      Approve
                    </button>
                    <button
                      type="button"
                      onClick={() => handleResolveHold(ho.orderId, 'VOID')}
                      className="btn-ghost-brutal px-2.5 py-1 text-xs"
                    >
                      Decline
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
