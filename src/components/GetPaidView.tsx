import React, { useRef, useState } from 'react';
import {
  CheckCircle2,
  ClipboardPaste,
  ExternalLink,
  FileText,
  FileUp,
  Handshake,
  Plus,
  Send,
  Sliders,
  Sparkles,
  Trash2,
  Users,
} from 'lucide-react';
import { apiFetch, fmtUsd, type WorkspaceState } from '../api';

interface GetPaidViewProps {
  state: WorkspaceState;
  onRefresh: () => Promise<void>;
}

interface EditableCollaborator {
  collaboratorName: string;
  paypalEmail: string;
  role: string;
  sharePct: number;
}

export const GetPaidView: React.FC<GetPaidViewProps> = ({ state, onRefresh }) => {
  const isDemo = state.operator?.role === 'DEMO_OPERATOR';
  const [actionError, setActionError] = useState('');
  // Milestone Invoicing (PayStream) state
  const [naturalProjectBrief, setNaturalProjectBrief] = useState('');
  const [projectTitle, setProjectTitle] = useState(isDemo ? 'E-Commerce Storefront & PayPal Redesign' : '');
  const [clientEmail, setClientEmail] = useState(isDemo ? 'client-accounts@personal.example.com' : '');
  const [budgetUsd, setBudgetUsd] = useState(isDemo ? '2450' : '');
  const [collaborators, setCollaborators] = useState<EditableCollaborator[]>(isDemo ? [
    {
      collaboratorName: 'Lead Developer',
      paypalEmail: 'lead-dev-sbx@personal.example.com',
      role: 'Engineering',
      sharePct: 70,
    },
    {
      collaboratorName: 'Product Designer',
      paypalEmail: 'designer-sbx@personal.example.com',
      role: 'Design',
      sharePct: 30,
    },
  ] : [{ collaboratorName: state.operator?.fullName || '', paypalEmail: state.operator?.email || '', role: 'Owner', sharePct: 100 }]);
  const [creatingPlan, setCreatingPlan] = useState(false);
  const [issuingMilestoneId, setIssuingMilestoneId] = useState('');
  const [proofLink, setProofLink] = useState(
    isDemo ? 'https://github.com/example/storefront/releases/tag/v1.0 — System architecture & UI approved' : ''
  );
  const [proofFeedback, setProofFeedback] = useState('');

  // Vendor Deal Assistant (DealForge) state
  const [naturalVendorQuote, setNaturalVendorQuote] = useState('');
  const [showAdvancedDealMandate, setShowAdvancedDealMandate] = useState(false);
  const [dealTitle, setDealTitle] = useState(isDemo ? 'Annual Cloud Security Review' : '');
  const [vendorName, setVendorName] = useState(isDemo ? 'Sentinel Security Partners' : '');
  const [targetUsd, setTargetUsd] = useState(isDemo ? '620' : '');
  const [maxUsd, setMaxUsd] = useState(isDemo ? '820' : '');
  const [vendorAskUsd, setVendorAskUsd] = useState(isDemo ? '980' : '');
  const [vendorFloorUsd, setVendorFloorUsd] = useState(isDemo ? '640' : '');
  const [maxDeliveryDays, setMaxDeliveryDays] = useState('7');
  const [minRevisions, setMinRevisions] = useState('2');
  const [maxDepositPct, setMaxDepositPct] = useState('40');
  const [manualOverrideUsd, setManualOverrideUsd] = useState('');
  const [negotiating, setNegotiating] = useState(false);
  const [dealResult, setDealResult] = useState<any>(null);

  const sowFileRef = useRef<HTMLInputElement | null>(null);

  const activePlan = state.paystream.plans[0] || null;

  const handleUpdateCollaborator = (
    idx: number,
    field: keyof EditableCollaborator,
    value: string | number
  ) => {
    setCollaborators((prev) =>
      prev.map((c, i) => (i === idx ? { ...c, [field]: value } : c))
    );
  };

  const handleAddCollaborator = () => {
    setCollaborators((prev) => [
      ...prev,
      {
        collaboratorName: `Collaborator ${prev.length + 1}`,
        paypalEmail: `member${prev.length + 1}-sbx@personal.example.com`,
        role: 'Specialist',
        sharePct: 20,
      },
    ]);
  };

  const handleRemoveCollaborator = (idx: number) => {
    if (collaborators.length <= 1) return;
    setCollaborators((prev) => prev.filter((_, i) => i !== idx));
  };

  const handleCreateMilestonePlan = async (e?: React.FormEvent, overrideBrief?: string) => {
    e?.preventDefault();
    setActionError('');
    setCreatingPlan(true);
    setProofFeedback('');
    try {
      const nlText = (overrideBrief ?? naturalProjectBrief).trim();
      const res = await apiFetch<any>('/api/paystream/create-plan', {
        method: 'POST',
        body: JSON.stringify({
          naturalDescription: nlText || undefined,
          projectTitle,
          clientEmail,
          totalBudgetCents: Math.max(1000, Math.round(Number(budgetUsd || '2450') * 100)),
          collaborators,
        }),
      });
      if (res.parsedNaturalInput) {
        setProjectTitle(res.parsedNaturalInput.projectTitle);
        setClientEmail(res.parsedNaturalInput.clientEmail);
        setBudgetUsd((res.parsedNaturalInput.totalBudgetCents / 100).toFixed(2));
        if (Array.isArray(res.parsedNaturalInput.collaborators)) {
          setCollaborators(res.parsedNaturalInput.collaborators);
        }
      }
      await onRefresh();
    } catch (err) {
      setActionError((err as Error).message || 'The request failed. Please try again.');
    } finally {
      setCreatingPlan(false);
    }
  };

  const handleOneClickPasteSow = async () => {
    setActionError('');
    try {
      if (!navigator.clipboard?.readText) throw new Error('Clipboard access is unavailable. Paste your project brief into the form.');
      const clip = (await navigator.clipboard.readText()).trim();
      if (!clip) throw new Error('Your clipboard is empty. Copy a project brief or enter the project details.');
      setNaturalProjectBrief(clip);
      await handleCreateMilestonePlan(undefined, clip);
    } catch (err) {
      setActionError((err as Error).message || 'Clipboard permission was denied. Paste your project brief manually.');
    }
  };

  const handleSendInvoice = async (planId: string, milestoneId: string) => {
    setActionError('');
    setIssuingMilestoneId(milestoneId);
    try {
      await apiFetch('/api/paystream/issue-invoice', {
        method: 'POST',
        body: JSON.stringify({ planId, milestoneId }),
      });
      await onRefresh();
    } catch (err) {
      setActionError((err as Error).message || 'The request failed. Please try again.');
    } finally {
      setIssuingMilestoneId('');
    }
  };

  const handleVerifyDeliverable = async (planId: string, milestoneId: string) => {
    setProofFeedback('Checking delivery link...');
    try {
      const res = await apiFetch('/api/paystream/verify-proof', {
        method: 'POST',
        body: JSON.stringify({
          planId,
          milestoneId,
          evidenceText: proofLink,
        }),
      });
      setProofFeedback(res.verification?.explanation || 'Deliverable reviewed.');
      await onRefresh();
    } catch (err) {
      setProofFeedback((err as Error).message);
    }
  };

  const handleRunDealAssistant = async (e?: React.FormEvent, overrideQuote?: string) => {
    e?.preventDefault();
    setActionError('');
    setNegotiating(true);
    try {
      const nlQuote = (overrideQuote ?? naturalVendorQuote).trim();
      const manualOverrideCents = manualOverrideUsd
        ? Math.round(Number(manualOverrideUsd) * 100)
        : undefined;

      const res = await apiFetch<any>('/api/dealforge/negotiate', {
        method: 'POST',
        body: JSON.stringify({
          naturalDescription: nlQuote || undefined,
          buyerMandate: nlQuote
            ? undefined
            : {
                buyerName: state.operator?.organization || 'Buyer Team',
                itemTitle: dealTitle,
                targetPriceCents: Math.round(Number(targetUsd || '620') * 100),
                maxPriceCents: Math.round(Number(maxUsd || '820') * 100),
                maxDeliveryDays: Math.max(1, Math.round(Number(maxDeliveryDays || '7'))),
                minRevisions: Math.max(0, Math.round(Number(minRevisions || '2'))),
                maxUpfrontDepositPct: Math.max(10, Math.min(80, Math.round(Number(maxDepositPct || '40')))),
              },
          sellerMandate: nlQuote
            ? undefined
            : {
                sellerName: vendorName || 'Verified Service Partner',
                listPriceCents: Math.round(Number(vendorAskUsd || '980') * 100),
                minPriceCents: Math.round(Number(vendorFloorUsd || '640') * 100),
                fastestDeliveryDays: 4,
                maxRevisionsAllowed: 3,
                minUpfrontDepositPct: 25,
              },
          humanCounterOfferCents: manualOverrideCents,
          issueLiveInvoice: true,
          buyerEmail: clientEmail,
        }),
      });
      setDealResult(res);
      if (res.parsedNaturalInput) {
        setDealTitle(res.parsedNaturalInput.dealTitle);
        setVendorName(res.parsedNaturalInput.sellerName);
        setTargetUsd((res.parsedNaturalInput.targetPriceCents / 100).toFixed(0));
        setMaxUsd((res.parsedNaturalInput.maxPriceCents / 100).toFixed(0));
        setVendorAskUsd((res.parsedNaturalInput.vendorAskCents / 100).toFixed(0));
        setVendorFloorUsd((res.parsedNaturalInput.vendorFloorCents / 100).toFixed(0));
      }
      await onRefresh();
    } catch (err) {
      setActionError((err as Error).message || 'The request failed. Please try again.');
    } finally {
      setNegotiating(false);
    }
  };

  return (
    <div className="space-y-6 animate-view-enter">
      {actionError && <div role="alert" className="border border-red-500/60 bg-red-950/40 p-4 text-sm text-red-200">{actionError}</div>}
      {/* Top Symmetrical 2-Column Milestone Planner & Live PayPal Invoices */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className="lg:col-span-5 glass-brutal-panel corner-ticks p-6 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#1E293B] pb-3">
            <div>
              <div className="text-xs font-mono uppercase text-[#CCFF00]">
                Client Projects &amp; Multi-Collaborator Splits
              </div>
              <h2 className="font-display text-xl font-bold text-white">
                Create Milestone Invoices &amp; Team Splits
              </h2>
            </div>

            <div className="flex items-center gap-1.5">
              <button
                type="button"
                disabled={creatingPlan}
                onClick={() => void handleOneClickPasteSow()}
                className="btn-cobalt px-2.5 py-1.5 text-xs flex items-center gap-1"
                title="Read SOW or project brief from clipboard and generate milestones in 1 click"
              >
                <ClipboardPaste className="w-3.5 h-3.5" />
                <span>1-Click Paste SOW</span>
              </button>
              <input
                ref={sowFileRef}
                type="file"
                accept=".txt,.md,.eml,.csv,.json"
                className="hidden"
                onChange={async (e) => {
                  const f = e.target.files?.[0];
                  if (!f) return;
                  try {
                    if (f.size > 1024 * 1024) throw new Error('Choose a project brief smaller than 1 MB.');
                    const text = (await f.text()).slice(0, 6000);
                    setNaturalProjectBrief(text);
                    await handleCreateMilestonePlan(undefined, text);
                  } catch (err) {
                    setActionError((err as Error).message);
                  }
                }}
              />
              <button
                type="button"
                onClick={() => sowFileRef.current?.click()}
                className="btn-ghost-brutal px-2.5 py-1.5 text-xs flex items-center gap-1"
              >
                <FileUp className="w-3.5 h-3.5 text-[#CCFF00]" />
                <span>Upload SOW</span>
              </button>
            </div>
          </div>

          {/* Natural-Language Project Brief Input */}
          <div className="space-y-1.5">
            <label className="block text-xs font-mono text-[#CCFF00]">
              Describe Any Project or Paste a Client SOW in Plain English:
            </label>
            <div className="flex gap-2">
              <input aria-label="Project brief"
                type="text"
                value={naturalProjectBrief}
                onChange={(e) => setNaturalProjectBrief(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    void handleCreateMilestonePlan();
                  }
                }}
                placeholder="e.g. Mobile App Redesign for client@acme.io, $3,600 budget, 60% Lead Dev, 25% Designer, 15% QA..."
                className="input-brutal text-xs flex-1"
              />
              <button
                type="button"
                disabled={creatingPlan}
                onClick={() => void handleCreateMilestonePlan()}
                className="btn-acid px-3 py-1.5 text-xs shrink-0"
              >
                Parse SOW
              </button>
            </div>
          </div>

          <form onSubmit={(e) => void handleCreateMilestonePlan(e)} className="space-y-3.5">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Project Title</label>
              <input aria-label="Project title"
                type="text"
                value={projectTitle}
                onChange={(e) => setProjectTitle(e.target.value)}
                className="input-brutal text-xs"
                required
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Client Billing Email
                </label>
                <input aria-label="Client billing email"
                  type="email"
                  value={clientEmail}
                  onChange={(e) => setClientEmail(e.target.value)}
                  className="input-brutal text-xs"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Total Project Budget (USD)
                </label>
                <input aria-label="Project budget in USD"
                  type="number"
                  min="50"
                  step="0.01"
                  value={budgetUsd}
                  onChange={(e) => setBudgetUsd(e.target.value)}
                  className="input-brutal text-xs"
                  required
                />
              </div>
            </div>

            {/* Dynamic Multi-Collaborator Editor */}
            <div className="space-y-2 border-t border-[#1E293B] pt-3">
              <div className="flex items-center justify-between text-xs">
                <span className="inline-flex items-center gap-1.5 font-semibold text-white">
                  <Users className="w-3.5 h-3.5 text-[#CCFF00]" />
                  Team Collaborator Splits ({collaborators.length} Members)
                </span>
                <button
                  type="button"
                  onClick={handleAddCollaborator}
                  className="px-2 py-1 text-[11px] font-mono bg-[#050507] border border-[#243049] text-[#CCFF00] hover:border-[#CCFF00] flex items-center gap-1"
                >
                  <Plus className="w-3 h-3" />
                  <span>Add Member</span>
                </button>
              </div>

              <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                {collaborators.map((c, idx) => (
                  <div
                    key={idx}
                    className="grid grid-cols-12 gap-1.5 items-center bg-[#050507] p-2 border border-[#1E293B]"
                  >
                    <input aria-label="Collaborator name"
                      type="text"
                      value={c.collaboratorName}
                      onChange={(e) =>
                        handleUpdateCollaborator(idx, 'collaboratorName', e.target.value)
                      }
                      placeholder="Name"
                      className="input-brutal col-span-4 text-[11px] py-1"
                    />
                    <input aria-label="Collaborator PayPal email"
                      type="email"
                      value={c.paypalEmail}
                      onChange={(e) =>
                        handleUpdateCollaborator(idx, 'paypalEmail', e.target.value)
                      }
                      placeholder="PayPal Email"
                      className="input-brutal col-span-4 text-[11px] py-1"
                    />
                    <input aria-label="Collaborator share percentage"
                      type="number"
                      min="1"
                      max="100"
                      value={c.sharePct}
                      onChange={(e) =>
                        handleUpdateCollaborator(idx, 'sharePct', Number(e.target.value) || 10)
                      }
                      title="Share %"
                      className="input-brutal col-span-3 text-[11px] py-1"
                    />
                    <button
                      type="button"
                      disabled={collaborators.length <= 1}
                      onClick={() => handleRemoveCollaborator(idx)}
                      className="col-span-1 text-slate-400 hover:text-red-400 flex justify-center"
                      title="Remove collaborator"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </div>

            <button
              type="submit"
              disabled={creatingPlan}
              className="btn-acid w-full py-3 text-sm"
            >
              <FileText className="w-4 h-4" />
              {creatingPlan ? 'Building Schedule...' : 'Create Milestone Schedule'}
            </button>
          </form>
        </div>

        {/* Right 7 Columns: Active Milestone Phases + Send PayPal Invoice */}
        <div className="lg:col-span-7 glass-brutal-panel p-6 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#1E293B] pb-3">
            <div>
              <div className="text-xs font-mono uppercase text-[#CCFF00]">
                Active Project Schedule
              </div>
              <h3 className="font-display text-xl font-bold text-white">
                {activePlan ? activePlan.projectTitle : 'No Milestone Schedule Yet'}
              </h3>
            </div>
            {activePlan && (
              <span className="text-xs font-mono px-2.5 py-1 bg-[#080B13] border border-[#CCFF00]/50 text-[#CCFF00]">
                Total: {fmtUsd(activePlan.totalBudgetCents)} (Exact to the Cent)
              </span>
            )}
          </div>

          {!activePlan ? (
            <div className="py-12 text-center text-xs text-slate-400">
              Click &ldquo;1-Click Paste SOW&rdquo; or &ldquo;Create Milestone Schedule&rdquo; on the left to split your project into PayPal invoices.
            </div>
          ) : (
            <div className="space-y-3">
              {activePlan.milestones.map((m) => (
                <div
                  key={m.milestoneId}
                  className="p-4 bg-[#080B13] border border-[#1B2234] space-y-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <div className="text-sm font-semibold text-white">{m.title}</div>
                      <div className="text-xs text-slate-400 mt-0.5">
                        Due in {m.dueInDays} days •{' '}
                        {m.collaboratorSplits
                          .map((c) => `${c.collaboratorName}: ${fmtUsd(c.payoutCents)}`)
                          .join(' + ')}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="font-display font-bold text-lg text-[#CCFF00] tabular-nums">
                        {fmtUsd(m.amountCents)}
                      </div>
                      <div className="text-[11px] font-mono text-slate-400">{m.status}</div>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-[#161E2E]">
                    <button
                      type="button"
                      disabled={Boolean(issuingMilestoneId) || Boolean(m.paypalInvoiceId)}
                      onClick={() => handleSendInvoice(activePlan.planId, m.milestoneId)}
                      className="btn-cobalt px-3.5 py-1.5 text-xs"
                    >
                      <Send className="w-3.5 h-3.5" />
                      {issuingMilestoneId === m.milestoneId
                        ? 'Sending...'
                        : m.paypalInvoiceId
                          ? 'Invoice Issued'
                          : 'Send PayPal Invoice'}
                    </button>

                    {m.paypalInvoiceUrl && (
                      <a
                        href={m.paypalInvoiceUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="btn-acid px-3 py-1.5 text-xs"
                      >
                        View PayPal Invoice
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                    )}

                    <button
                      type="button"
                      onClick={() => handleVerifyDeliverable(activePlan.planId, m.milestoneId)}
                      className="btn-ghost-brutal px-3 py-1.5 text-xs"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Verify Delivery Link
                    </button>
                  </div>
                </div>
              ))}

              <div className="pt-2 space-y-1.5">
                <label className="block text-xs text-slate-400">
                  Delivery link or completion summary (used when clicking Verify Delivery Link):
                </label>
                <div className="flex gap-2">
                  <input aria-label="Delivery link or completion summary"
                    type="text"
                    value={proofLink}
                    onChange={(e) => setProofLink(e.target.value)}
                    className="input-brutal text-xs flex-1"
                  />
                  <button
                    type="button"
                    onClick={async () => {
                      try {
                        if (!navigator.clipboard?.readText) throw new Error('Paste the delivery link manually.');
                        const clip = (await navigator.clipboard.readText()).trim();
                        if (clip) setProofLink(clip);
                        else setProofFeedback('Your clipboard is empty. Paste or enter a delivery link.');
                      } catch {
                        setProofFeedback('Clipboard permission was denied. Paste the delivery link manually.');
                      }
                    }}
                    className="btn-ghost-brutal px-3 py-1.5 text-xs shrink-0"
                  >
                    Paste Link
                  </button>
                </div>
                {proofFeedback && (
                  <div className="text-xs font-mono text-[#CCFF00] pt-1">{proofFeedback}</div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Bottom Section: Automated Vendor Deal & Deposit Agreement (DealForge) */}
      <div className="glass-brutal-panel p-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#1E293B] pb-3">
          <div className="flex items-center gap-2">
            <Handshake className="w-5 h-5 text-[#CCFF00]" />
            <div>
              <h3 className="font-display text-lg font-bold text-white">
                Vendor Quote &amp; Deposit Agreement Assistant
              </h3>
              <p className="text-xs text-slate-400">
                Paste any vendor quote in plain English or customize your negotiation mandate — AegisPay runs a 4-round Buyer vs. Vendor clearing protocol and issues the PayPal deposit invoice.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => setShowAdvancedDealMandate((v) => !v)}
            className="btn-ghost-brutal px-3 py-1.5 text-xs flex items-center gap-1.5"
          >
            <Sliders className="w-3.5 h-3.5 text-[#CCFF00]" />
            <span>
              {showAdvancedDealMandate ? 'Hide Advanced Mandate' : 'Advanced Mandate & Floor'}
            </span>
          </button>
        </div>

        {/* Natural-Language Vendor Quote Bar */}
        <div className="p-3.5 bg-[#050507] border border-[#243049] space-y-1.5">
          <label className="block text-xs font-mono uppercase text-[#CCFF00]">
            Describe Any Vendor Quote or Paste a Proposal Email:
          </label>
          <div className="flex flex-col sm:flex-row gap-2">
            <input aria-label="Vendor quote"
              type="text"
              value={naturalVendorQuote}
              onChange={(e) => setNaturalVendorQuote(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  void handleRunDealAssistant();
                }
              }}
              placeholder="e.g. Sentinel Security quoted $980 (floor $640) for SOC2 PenTest; our target is $660 (max $840), 6-day delivery, 2 revisions..."
              className="input-brutal text-xs flex-1"
            />
            <button
              type="button"
              disabled={negotiating}
              onClick={() => void handleRunDealAssistant()}
              className="btn-acid px-4 py-2 text-xs shrink-0 flex items-center gap-1.5"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>{negotiating ? 'Negotiating...' : 'Parse & Negotiate'}</span>
            </button>
          </div>
        </div>

        <form
          onSubmit={(e) => void handleRunDealAssistant(e)}
          className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3 items-end"
        >
          <div className="lg:col-span-2">
            <label className="block text-xs text-slate-300 mb-1">Service or Scope</label>
            <input aria-label="Service or scope"
              type="text"
              value={dealTitle}
              onChange={(e) => {
                setNaturalVendorQuote('');
                setDealTitle(e.target.value);
              }}
              className="input-brutal text-xs"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-300 mb-1">Your Target ($)</label>
            <input aria-label="Target price in USD"
              type="number"
              value={targetUsd}
              onChange={(e) => {
                setNaturalVendorQuote('');
                setTargetUsd(e.target.value);
              }}
              className="input-brutal text-xs"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-300 mb-1">Your Max Cap ($)</label>
            <input aria-label="Maximum price in USD"
              type="number"
              value={maxUsd}
              onChange={(e) => {
                setNaturalVendorQuote('');
                setMaxUsd(e.target.value);
              }}
              className="input-brutal text-xs"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-300 mb-1">Vendor Quote ($)</label>
            <input aria-label="Vendor asking price in USD"
              type="number"
              value={vendorAskUsd}
              onChange={(e) => {
                setNaturalVendorQuote('');
                setVendorAskUsd(e.target.value);
              }}
              className="input-brutal text-xs"
            />
          </div>
          <button type="submit" disabled={negotiating} className="btn-cobalt py-2.5 text-xs">
            {negotiating ? 'Matching Terms...' : 'Agree & Send Deposit'}
          </button>
        </form>

        {showAdvancedDealMandate && (
          <div className="p-4 bg-[#050507] border border-[#243049] grid grid-cols-2 sm:grid-cols-6 gap-3 text-xs">
            <div>
              <label className="block text-slate-400 mb-1">Vendor Name</label>
              <input aria-label="Vendor name"
                type="text"
                value={vendorName}
                onChange={(e) => setVendorName(e.target.value)}
                className="input-brutal text-xs"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Vendor Floor ($)</label>
              <input aria-label="Vendor minimum price in USD"
                type="number"
                value={vendorFloorUsd}
                onChange={(e) => setVendorFloorUsd(e.target.value)}
                className="input-brutal text-xs"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Max Delivery Days</label>
              <input aria-label="Maximum delivery days"
                type="number"
                value={maxDeliveryDays}
                onChange={(e) => setMaxDeliveryDays(e.target.value)}
                className="input-brutal text-xs"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Min Revisions</label>
              <input aria-label="Minimum revisions"
                type="number"
                value={minRevisions}
                onChange={(e) => setMinRevisions(e.target.value)}
                className="input-brutal text-xs"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Max Upfront Deposit %</label>
              <input aria-label="Maximum upfront deposit percentage"
                type="number"
                value={maxDepositPct}
                onChange={(e) => setMaxDepositPct(e.target.value)}
                className="input-brutal text-xs"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Manual Counter-Offer ($)</label>
              <input aria-label="Manual counteroffer in USD"
                type="number"
                value={manualOverrideUsd}
                onChange={(e) => setManualOverrideUsd(e.target.value)}
                placeholder="Optional override"
                className="input-brutal text-xs"
              />
            </div>
          </div>
        )}

        {dealResult && (
          <div className="p-4 bg-[#080B13] border border-[#0047FF] space-y-4 text-xs">
            {dealResult.dealReached ? (
              <>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="space-y-1">
                    <div className="text-sm font-semibold text-white">
                      Agreed at {fmtUsd(dealResult.contract.agreedTerms.priceCents)} (Saved{' '}
                      {fmtUsd(dealResult.contract.buyerSavedCents)} off vendor quote)
                    </div>
                    <div className="text-slate-300">
                      Upfront PayPal Deposit ({dealResult.contract.agreedTerms.upfrontDepositPct}%):{' '}
                      <strong>{fmtUsd(dealResult.contract.upfrontDepositCents)}</strong> • Remaining
                      on completion: {fmtUsd(dealResult.contract.escrowCompletionCents)} •{' '}
                      {dealResult.contract.agreedTerms.deliveryDays} days •{' '}
                      {dealResult.contract.agreedTerms.revisionsIncluded} revisions
                    </div>
                    <div className="font-mono text-[11px] text-[#CCFF00]">
                      Contract SHA-256: {String(dealResult.contract.contractHash).slice(0, 28)}...
                    </div>
                  </div>
                  {(dealResult.paypalInvoice?.payerViewUrl ||
                    dealResult.paypalOrder?.approvalUrl) && (
                    <a
                      href={
                        dealResult.paypalInvoice?.payerViewUrl ||
                        dealResult.paypalOrder?.approvalUrl
                      }
                      target="_blank"
                      rel="noreferrer"
                      className="btn-acid px-3.5 py-2 text-xs shrink-0"
                    >
                      Open Deposit in PayPal
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  )}
                </div>

                {/* Multi-Round Negotiation Transcript */}
                {Array.isArray(dealResult.rounds) && dealResult.rounds.length > 0 && (
                  <div className="border-t border-[#1E293B] pt-3 space-y-2">
                    <div className="text-[11px] font-mono uppercase text-slate-400">
                      Multi-Round Buyer vs. Vendor Negotiation Transcript
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2">
                      {dealResult.rounds.map((r: any) => (
                        <div
                          key={r.round}
                          className="p-2.5 bg-[#050507] border border-[#1E293B] space-y-1"
                        >
                          <div className="flex items-center justify-between font-mono text-[10px]">
                            <span className="text-[#CCFF00]">
                              Round {r.round} • {r.speaker}
                            </span>
                            <span className="text-white font-bold">
                              {fmtUsd(r.proposedTerms.priceCents)}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-300 line-clamp-3">{r.message}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="text-amber-300">{dealResult.reason}</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
