import React, { useCallback, useEffect, useState } from 'react';
import {
  ArrowRight,
  CheckCircle2,
  Compass,
  Cpu,
  Download,
  ExternalLink,
  FileText,
  Play,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Wallet,
} from 'lucide-react';
import { apiFetch, fmtUsd, type WorkspaceState } from '../api';
import type { WorkspaceSectionId } from '../webmcp';

interface AgentSuggestion {
  id: string;
  priority: 'HIGH' | 'MEDIUM' | 'LOW';
  badge: string;
  title: string;
  description: string;
  actionType:
    | 'CLEAN_SUBSCRIPTIONS'
    | 'RESOLVE_HELD_ORDER'
    | 'SEND_DRAFT_MILESTONE_INVOICE'
    | 'RECOVER_DECLINED_CHECKOUT';
  orderId?: string;
  planId?: string;
  milestoneId?: string;
  targetSection: WorkspaceSectionId;
}

interface WorkspaceOverviewProps {
  state: WorkspaceState;
  onNavigate: (section: WorkspaceSectionId) => void;
  onStartTour: () => void;
  onRefresh?: () => Promise<void>;
  onOpenMcpExtensionHub?: (tab: 'mcp' | 'extension') => void;
}

export const WorkspaceOverview: React.FC<WorkspaceOverviewProps> = ({
  state,
  onNavigate,
  onStartTour,
  onRefresh,
  onOpenMcpExtensionHub,
}) => {
  const freeBudgetCents = state.lupa.defaultAffordability.trueFreeCashflowCents;
  const unusedSubsCount = state.lupa.zombieReport.totalZombieCount;

  const [suggestions, setSuggestions] = useState<AgentSuggestion[]>([]);
  const [executingId, setExecutingId] = useState<string | null>(null);
  const [actionToast, setActionToast] = useState<string | null>(null);

  const loadSuggestions = useCallback(async () => {
    try {
      const res = await apiFetch<{ suggestions: AgentSuggestion[] }>('/api/agent/suggestions');
      if (Array.isArray(res.suggestions)) {
        setSuggestions(res.suggestions);
      }
    } catch {
      // Ignore transient fetch error
    }
  }, []);

  useEffect(() => {
    void loadSuggestions();
  }, [loadSuggestions, state.kpis.totalAuditRecords]);

  const handleExecuteSuggestion = async (sug: AgentSuggestion) => {
    setExecutingId(sug.id);
    setActionToast(null);
    try {
      if (sug.actionType === 'CLEAN_SUBSCRIPTIONS') {
        const res = await apiFetch<{
          revokedCount: number;
          tightenedCount: number;
          annualSavedCents: number;
        }>('/api/lupa/subscriptions/clean-all', { method: 'POST', body: JSON.stringify({}) });
        setActionToast(
          `Auto-cleaned ${res.revokedCount} unused subscription(s) & tightened ${res.tightenedCount} billing cap(s) — saving ${fmtUsd(res.annualSavedCents)}/yr.`
        );
      } else if (sug.actionType === 'RESOLVE_HELD_ORDER' && sug.orderId) {
        await apiFetch('/api/lupa/resolve-hold', {
          method: 'POST',
          body: JSON.stringify({ orderId: sug.orderId, action: 'CAPTURE' }),
        });
        setActionToast(`Captured held PayPal authorization for order ${sug.orderId}.`);
      } else if (
        sug.actionType === 'SEND_DRAFT_MILESTONE_INVOICE' &&
        sug.planId &&
        sug.milestoneId
      ) {
        const res = await apiFetch<{ invoice: { invoiceId: string } }>(
          '/api/paystream/issue-invoice',
          {
            method: 'POST',
            body: JSON.stringify({ planId: sug.planId, milestoneId: sug.milestoneId }),
          }
        );
        setActionToast(`Sent live PayPal milestone invoice ${res.invoice.invoiceId}.`);
      } else if (sug.actionType === 'RECOVER_DECLINED_CHECKOUT') {
        const res = await apiFetch<{
          decision: { selectedAction: string };
          paypalOrder?: { orderId: string };
        }>('/api/payrevive/recover', {
          method: 'POST',
          body: JSON.stringify({ presetId: 'PAYDAY_LIQUIDITY', executeLivePayPal: true }),
        });
        setActionToast(
          `Executed ${res.decision.selectedAction}${res.paypalOrder?.orderId ? ` (PayPal Order ${res.paypalOrder.orderId})` : ''}.`
        );
      }
      await onRefresh?.();
      await loadSuggestions();
    } catch (err) {
      setActionToast((err as Error).message || 'Action failed');
    } finally {
      setExecutingId(null);
    }
  };

  return (
    <div className="space-y-6 animate-view-enter">
      {/* Symmetrical Welcome & Guided Tour Banner */}
      <div className="glass-brutal-panel corner-ticks p-6 sm:p-7 flex flex-col lg:flex-row lg:items-center justify-between gap-5">
        <div className="space-y-1.5 max-w-2xl">
          <div className="text-xs font-mono uppercase tracking-wider text-[#CCFF00]">
            Welcome back, {state.operator?.fullName || 'Account Owner'}
          </div>
          <h1 className="font-display text-2xl sm:text-3xl font-bold text-white">
            What would you like to do with PayPal today?
          </h1>
          <p className="text-sm text-slate-300">
            Use the 1-Click Universal Device Agent above to check any invoice, bank statement, or
            claim directly from your clipboard or files — or launch any PayPal workflow below.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={() => onOpenMcpExtensionHub?.('extension')}
            className="btn-ghost-brutal px-4 py-2.5 text-xs sm:text-sm"
          >
            <Download className="w-4 h-4 text-[#CCFF00]" />
            Chrome Extension (.zip)
          </button>
          <button
            type="button"
            onClick={() => onOpenMcpExtensionHub?.('mcp')}
            className="btn-ghost-brutal px-4 py-2.5 text-xs sm:text-sm"
          >
            <Cpu className="w-4 h-4 text-[#CCFF00]" />
            Live MCP Server
          </button>
          <button
            type="button"
            onClick={onStartTour}
            className="btn-acid px-4 py-2.5 text-xs sm:text-sm"
          >
            <Compass className="w-4 h-4" />
            Interactive Tour
          </button>
        </div>
      </div>

      {/* Proactive Agentic Next-Best-Actions Strip */}
      {suggestions.length > 0 && (
        <div className="glass-brutal-panel p-5 border-l-4 border-l-[#CCFF00] space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-[#CCFF00]" />
              <h2 className="font-display font-bold text-sm sm:text-base text-white">
                Proactive AI Agent Recommendations (1-Click Execution)
              </h2>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              Scanned from your active subscriptions, held PayPal authorizations &amp; milestones
            </span>
          </div>

          {actionToast && (
            <div className="p-2.5 bg-[#050507] border border-[#CCFF00] text-xs font-mono text-[#CCFF00] flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>{actionToast}</span>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
            {suggestions.slice(0, 3).map((sug) => (
              <div
                key={sug.id}
                className="p-4 bg-[#050507] border border-[#243049] flex flex-col justify-between gap-3"
              >
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="px-2 py-0.5 bg-[#0047FF]/30 border border-[#0047FF] text-[10px] font-mono font-bold text-[#CCFF00]">
                      {sug.badge}
                    </span>
                    <button
                      type="button"
                      onClick={() => onNavigate(sug.targetSection)}
                      className="text-[11px] font-mono text-slate-400 hover:text-white underline"
                    >
                      Inspect
                    </button>
                  </div>
                  <div className="font-display font-bold text-xs sm:text-sm text-white">
                    {sug.title}
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{sug.description}</p>
                </div>

                <button
                  type="button"
                  disabled={executingId === sug.id}
                  onClick={() => void handleExecuteSuggestion(sug)}
                  className="btn-acid w-full py-2 text-xs flex items-center justify-center gap-1.5"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>
                    {executingId === sug.id ? 'Executing on PayPal...' : '1-Click Execute Now'}
                  </span>
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Symmetrical 4-Column Summary Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="glass-brutal-panel p-5 flex flex-col justify-between">
          <div className="text-xs text-slate-400">Available Safe Spending Budget</div>
          <div className="font-display text-2xl sm:text-3xl font-bold text-white tabular-nums mt-2">
            {fmtUsd(Math.max(0, freeBudgetCents))}
          </div>
          <div className="text-[11px] text-[#CCFF00] font-mono mt-2">
            After bills &amp; safety reserve
          </div>
        </div>

        <div className="glass-brutal-panel p-5 flex flex-col justify-between">
          <div className="text-xs text-slate-400">Unused Subscriptions Found</div>
          <div className="font-display text-2xl sm:text-3xl font-bold text-white tabular-nums mt-2">
            {unusedSubsCount}
          </div>
          <div className="text-[11px] text-[#CCFF00] font-mono mt-2">
            Save {fmtUsd(state.kpis.recoverableMonthlyCents)}/mo by canceling
          </div>
        </div>

        <div className="glass-brutal-panel p-5 flex flex-col justify-between">
          <div className="text-xs text-slate-400">Money Saved &amp; Protected</div>
          <div className="font-display text-2xl sm:text-3xl font-bold text-[#CCFF00] tabular-nums mt-2">
            {fmtUsd(state.kpis.totalProtectedCents)}
          </div>
          <div className="text-[11px] text-slate-400 font-mono mt-2">
            Across {state.kpis.totalAuditRecords} workspace actions
          </div>
        </div>

        <div className="glass-brutal-panel p-5 flex flex-col justify-between">
          <div className="text-xs text-slate-400">Active PayPal Invoices &amp; Orders</div>
          <div className="font-display text-2xl sm:text-3xl font-bold text-white tabular-nums mt-2">
            {state.orders.length + state.invoices.length}
          </div>
          <div className="text-[11px] text-[#CCFF00] font-mono mt-2">
            {state.system.paypal.hasLiveSandboxCredentials
              ? 'PayPal Sandbox Connected'
              : 'Local Sandbox Active'}
          </div>
        </div>
      </div>

      {/* Symmetrical 3-Card Primary Workflow Launcher */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="glass-brutal-panel corner-ticks p-6 flex flex-col justify-between gap-5">
          <div className="space-y-3">
            <div className="w-10 h-10 bg-[#0047FF]/20 border border-[#0047FF] flex items-center justify-center text-[#CCFF00]">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <h2 className="font-display text-lg font-bold text-white">1. Pay Safely</h2>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              Scan any invoice or payment link in 1 click from your clipboard or files, ask natural-language affordability questions, and clean up real PayPal subscriptions &amp; autopays.
            </p>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('protect')}
            className="btn-ghost-brutal w-full py-2.5 text-xs sm:text-sm"
          >
            Open Payment Protection
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>

        <div className="glass-brutal-panel corner-ticks p-6 flex flex-col justify-between gap-5">
          <div className="space-y-3">
            <div className="w-10 h-10 bg-[#0047FF]/20 border border-[#0047FF] flex items-center justify-center text-[#CCFF00]">
              <RefreshCw className="w-5 h-5" />
            </div>
            <h2 className="font-display text-lg font-bold text-white">2. Recover &amp; Retain</h2>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              Describe any declined checkout, damaged item claim, or canceling subscriber in plain English — AegisPay computes the optimal recovery, partial refund, or retention offer.
            </p>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('merchant')}
            className="btn-ghost-brutal w-full py-2.5 text-xs sm:text-sm"
          >
            Open Revenue Recovery
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>

        <div className="glass-brutal-panel corner-ticks p-6 flex flex-col justify-between gap-5">
          <div className="space-y-3">
            <div className="w-10 h-10 bg-[#0047FF]/20 border border-[#0047FF] flex items-center justify-center text-[#CCFF00]">
              <FileText className="w-5 h-5" />
            </div>
            <h2 className="font-display text-lg font-bold text-white">3. Get Paid</h2>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              Paste any project brief or SOW to generate multi-collaborator PayPal milestone invoices, or paste any vendor quote to run automated multi-round deal negotiation.
            </p>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('getpaid')}
            className="btn-ghost-brutal w-full py-2.5 text-xs sm:text-sm"
          >
            Open Milestone Invoicing
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Symmetrical 2-Column Recent PayPal Orders & Invoices */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="glass-brutal-panel p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
            <div className="flex items-center gap-2">
              <Wallet className="w-4 h-4 text-[#CCFF00]" />
              <h3 className="font-display font-bold text-base text-white">Recent PayPal Orders</h3>
            </div>
            <span className="text-xs font-mono text-slate-400">{state.orders.length} total</span>
          </div>

          {state.orders.length === 0 ? (
            <p className="text-xs text-slate-400 py-4">
              No PayPal orders created in this session yet. Try checking an invoice in{' '}
              <button
                type="button"
                onClick={() => onNavigate('protect')}
                className="text-[#CCFF00] underline"
              >
                Pay Safely
              </button>{' '}
              or recovering a declined sale in{' '}
              <button
                type="button"
                onClick={() => onNavigate('merchant')}
                className="text-[#CCFF00] underline"
              >
                Recover &amp; Retain
              </button>
              .
            </p>
          ) : (
            <div className="space-y-2.5 max-h-64 overflow-y-auto pr-1">
              {state.orders.slice(0, 6).map((o) => (
                <div
                  key={o.orderId}
                  className="p-3 bg-[#080B13] border border-[#1B2234] flex items-center justify-between gap-3"
                >
                  <div className="min-w-0">
                    <div className="text-xs font-semibold text-white truncate">
                      {o.merchantName} — {fmtUsd(o.amountCents)}
                    </div>
                    <div className="text-[11px] font-mono text-slate-400 truncate">
                      {o.orderId} • {o.status}
                    </div>
                  </div>
                  <a
                    href={o.approvalUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="btn-ghost-brutal px-2.5 py-1 text-[11px] shrink-0"
                  >
                    Open in PayPal
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="glass-brutal-panel p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-[#CCFF00]" />
              <h3 className="font-display font-bold text-base text-white">
                Recent PayPal Invoices
              </h3>
            </div>
            <span className="text-xs font-mono text-slate-400">{state.invoices.length} sent</span>
          </div>

          {state.invoices.length === 0 ? (
            <p className="text-xs text-slate-400 py-4">
              No PayPal invoices sent yet. Head to{' '}
              <button
                type="button"
                onClick={() => onNavigate('getpaid')}
                className="text-[#CCFF00] underline"
              >
                Get Paid
              </button>{' '}
              to create a milestone schedule and send a shareable PayPal invoice link.
            </p>
          ) : (
            <div className="space-y-2.5 max-h-64 overflow-y-auto pr-1">
              {state.invoices.slice(0, 6).map((inv) => (
                <div
                  key={inv.invoiceId}
                  className="p-3 bg-[#080B13] border border-[#1B2234] flex items-center justify-between gap-3"
                >
                  <div className="min-w-0">
                    <div className="text-xs font-semibold text-white truncate">
                      {inv.title} — {fmtUsd(inv.amountCents)}
                    </div>
                    <div className="text-[11px] font-mono text-slate-400 truncate">
                      {inv.invoiceId} • {inv.recipientEmail} • {inv.status}
                    </div>
                  </div>
                  <a
                    href={inv.payerViewUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="btn-ghost-brutal px-2.5 py-1 text-[11px] shrink-0"
                  >
                    View Invoice
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
