import React, { useMemo, useState } from 'react';
import { AllCommunityModule, ModuleRegistry, type ColDef } from 'ag-grid-community';
import { AgGridReact } from 'ag-grid-react';
import {
  Activity,
  ArrowLeft,
  Cpu,
  Download,
  FlaskConical,
  KeyRound,
  ShieldAlert,
  Terminal,
} from 'lucide-react';
import { apiFetch, fmtUsd, type WorkspaceState } from '../api';

ModuleRegistry.registerModules([AllCommunityModule]);

interface DiagnosticsLabProps {
  state: WorkspaceState;
  onRefresh: () => Promise<void>;
  onBackToProduct: () => void;
}

type LabTabId = 'payrevive-bench' | 'fuzzer-tamper' | 'ai-failover' | 'audit-ledger' | 'admin';

export const DiagnosticsLab: React.FC<DiagnosticsLabProps> = ({
  state,
  onRefresh,
  onBackToProduct,
}) => {
  const [labTab, setLabTab] = useState<LabTabId>('payrevive-bench');

  // 1. PayRevive 500-Batch Benchmark + TreeSHAP Inspector
  const [benchRunning, setBenchRunning] = useState(false);
  const [benchReport, setBenchReport] = useState<any>(state.payrevive.lastBenchmark);
  const [inspectPresetId, setInspectPresetId] = useState(
    state.payrevive.presets[0]?.presetId || 'PAYDAY_LIQUIDITY'
  );
  const [inspectedDecision, setInspectedDecision] = useState<any>(
    state.payrevive.decisions[0] || null
  );

  // 2. 1,000-Case Fuzzer + Tamper Lab
  const [fuzzRunning, setFuzzRunning] = useState(false);
  const [fuzzReport, setFuzzReport] = useState<any>(null);
  const [tamperLoading, setTamperLoading] = useState('');
  const [tamperResult, setTamperResult] = useState<any>(null);

  // 3. AI Failover
  const [failoverBusy, setFailoverBusy] = useState(false);
  const [failoverResult, setFailoverResult] = useState<any>(null);

  // 4. Admin Credentials (PRINCIPAL_ARCHITECT only)
  const [zapierUrlInput, setZapierUrlInput] = useState('');
  const [credStatus, setCredStatus] = useState('');

  const handleRun500Batch = async () => {
    setBenchRunning(true);
    try {
      const res = await apiFetch('/api/payrevive/benchmark', {
        method: 'POST',
        body: JSON.stringify({ batches: 500, batchSize: 20 }),
      });
      setBenchReport(res.report);
      await onRefresh();
    } finally {
      setBenchRunning(false);
    }
  };

  const handleInspectShap = async () => {
    const res = await apiFetch('/api/payrevive/recover', {
      method: 'POST',
      body: JSON.stringify({ presetId: inspectPresetId, executeLivePayPal: false }),
    });
    setInspectedDecision(res.decision);
    await onRefresh();
  };

  const handleRunFuzzer = async () => {
    setFuzzRunning(true);
    try {
      const res = await apiFetch('/api/security/fuzz', {
        method: 'POST',
        body: JSON.stringify({ iterations: 1000 }),
      });
      setFuzzReport(res.report);
      await onRefresh();
    } finally {
      setFuzzRunning(false);
    }
  };

  const handleRunTamper = async (scenario: string) => {
    setTamperLoading(scenario);
    try {
      if (scenario !== 'NEVER_REVIEWED') {
        await apiFetch('/api/scamshield/review', {
          method: 'POST',
          body: JSON.stringify({
            rawText: 'Verified Studio Invoice #901 for $45.00 USD',
            claimedAmountCents: 4500,
            currency: 'USD',
            payeeIdentifier: 'billing@verified-studio.io',
          }),
        });
      }
      const res = await apiFetch('/api/scamshield/capture', {
        method: 'POST',
        body: JSON.stringify({ tamperScenario: scenario }),
      });
      setTamperResult({ scenario, ...res });
      await onRefresh();
    } finally {
      setTamperLoading('');
    }
  };

  const handleToggleFailover = async (simulateRateLimit: boolean) => {
    setFailoverBusy(true);
    try {
      const res = await apiFetch('/api/ai/failover-test', {
        method: 'POST',
        body: JSON.stringify({ simulateRateLimit }),
      });
      setFailoverResult(res);
      await onRefresh();
    } finally {
      setFailoverBusy(false);
    }
  };

  const handleSaveAdminConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    setCredStatus('Validating & updating...');
    try {
      await apiFetch('/api/credentials', {
        method: 'POST',
        body: JSON.stringify({ zapierUrl: zapierUrlInput }),
      });
      setCredStatus('Updated server webhook endpoint.');
      await onRefresh();
    } catch (err) {
      setCredStatus((err as Error).message);
    }
  };

  const handleExportCsv = () => {
    const header = [
      'Timestamp',
      'Module',
      'Actor',
      'Verdict',
      'Amount_USD',
      'Protected_USD',
      'PayPal_Ref',
      'SHA256',
    ];
    const rows = state.auditLogs.map((r) => [
      r.timestampIso,
      r.pillar,
      `"${r.actor.replace(/"/g, '""')}"`,
      r.verdict,
      (r.amountCents / 100).toFixed(2),
      (r.savedOrProtectedCents / 100).toFixed(2),
      r.paypalRef,
      r.sha256Hash,
    ]);
    const csv = [header.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'aegispay-audit-ledger.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  const columnDefs = useMemo<ColDef[]>(
    () => [
      { field: 'timestampIso', headerName: 'Timestamp', width: 175 },
      { field: 'pillar', headerName: 'Subsystem', width: 125 },
      { field: 'verdict', headerName: 'Verdict', width: 120 },
      {
        field: 'amountCents',
        headerName: 'Amount',
        width: 110,
        valueFormatter: (p) => fmtUsd(Number(p.value || 0)),
      },
      { field: 'paypalRef', headerName: 'PayPal / Token Ref', width: 185 },
      { field: 'eventTitle', headerName: 'Event Summary', flex: 1, minWidth: 260 },
      { field: 'sha256Hash', headerName: 'SHA-256 Digest', width: 180 },
    ],
    []
  );

  const modelCard = state.payrevive.modelCard;

  return (
    <div className="space-y-6 animate-view-enter">
      {/* Separation Banner: Makes clear this is the isolated Engineering & Hackathon Test Lab */}
      <div className="glass-brutal-panel corner-ticks p-5 sm:p-6 border border-[#CCFF00]/60 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="inline-flex items-center gap-2 text-xs font-mono uppercase text-[#CCFF00]">
            <FlaskConical className="w-4 h-4" />
            Isolated Engineering &amp; Verification Lab (Hidden from Everyday End-Users)
          </div>
          <h1 className="font-display text-xl sm:text-2xl font-bold text-white">
            Simulation Benchmarks, Adversarial Fuzzing &amp; Cryptographic Audit Ledger
          </h1>
          <p className="text-xs text-slate-300">
            All internal evaluation suites, model diagnostics, attack simulations, and raw audit
            exports live exclusively in this separate lab so the customer product stays clean and
            simple.
          </p>
        </div>

        <button
          type="button"
          onClick={onBackToProduct}
          className="btn-acid px-4 py-2.5 text-xs sm:text-sm shrink-0"
        >
          <ArrowLeft className="w-4 h-4" />
          Return to Customer Workspace
        </button>
      </div>

      {/* Lab Sub-Navigation */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
        {[
          { id: 'payrevive-bench', label: '500-Batch ML & SHAP', icon: Activity },
          { id: 'fuzzer-tamper', label: '1,000-Case Fuzzer & Tamper', icon: ShieldAlert },
          { id: 'ai-failover', label: 'AI Failover Router', icon: Cpu },
          { id: 'audit-ledger', label: 'AG Grid Audit Ledger', icon: Terminal },
          { id: 'admin', label: 'Tools & Admin RBAC', icon: KeyRound },
        ].map((t) => {
          const Icon = t.icon;
          const active = labTab === t.id;
          return (
            <button
              key={t.id}
              type="button"
              onClick={() => setLabTab(t.id as LabTabId)}
              className={`p-3 border text-xs font-display font-bold flex items-center justify-center gap-2 transition-colors ${
                active
                  ? 'bg-[#0047FF] border-[#CCFF00] text-white'
                  : 'bg-[#080B13] border-[#1B2234] text-slate-300 hover:border-[#0047FF]'
              }`}
            >
              <Icon className="w-4 h-4 text-[#CCFF00] shrink-0" />
              <span className="truncate">{t.label}</span>
            </button>
          );
        })}
      </div>

      {/* TAB 1: PayRevive 500-Batch Benchmark + Trained Model Card + TreeSHAP + LinUCB */}
      {labTab === 'payrevive-bench' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-6 glass-brutal-panel p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
                <div>
                  <div className="text-xs font-mono uppercase text-[#CCFF00]">
                    Out-of-Sample Trained Ensemble + Bandit Simulation
                  </div>
                  <h2 className="font-display text-lg font-bold text-white">
                    500-Batch Non-Stationary Revenue Recovery Benchmark
                  </h2>
                </div>
                <button
                  type="button"
                  onClick={handleRun500Batch}
                  disabled={benchRunning}
                  className="btn-acid px-4 py-2 text-xs"
                >
                  {benchRunning ? 'Running 10,000 Cases...' : 'Run 500-Batch Test'}
                </button>
              </div>

              {modelCard && (
                <div className="grid grid-cols-3 gap-2.5 text-xs">
                  <div className="p-3 bg-[#080B13] border border-[#1B2234]">
                    <div className="text-slate-400">Held-Out ROC-AUC</div>
                    <div className="font-mono text-base font-bold text-[#CCFF00] mt-0.5">
                      {modelCard.heldOutRocAuc}
                    </div>
                  </div>
                  <div className="p-3 bg-[#080B13] border border-[#1B2234]">
                    <div className="text-slate-400">Held-Out Brier</div>
                    <div className="font-mono text-base font-bold text-white mt-0.5">
                      {modelCard.heldOutBrierScore}
                    </div>
                  </div>
                  <div className="p-3 bg-[#080B13] border border-[#1B2234]">
                    <div className="text-slate-400">Newton GBDT Trees</div>
                    <div className="font-mono text-base font-bold text-white mt-0.5">
                      {modelCard.numTrees} Trees
                    </div>
                  </div>
                </div>
              )}

              {benchReport ? (
                <div className="space-y-3 text-xs">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                    <div className="p-3 bg-[#080B13] border border-[#CCFF00]/50">
                      <div className="text-slate-400">Net Recovery Lift</div>
                      <div className="font-mono text-lg font-bold text-[#CCFF00]">
                        +{benchReport.netRecoveryLiftPercent}%
                      </div>
                    </div>
                    <div className="p-3 bg-[#080B13] border border-[#1B2234]">
                      <div className="text-slate-400">Bandit Net Recovered</div>
                      <div className="font-mono text-sm font-bold text-white">
                        {fmtUsd(benchReport.payRevive.netRecoveredCents)}
                      </div>
                    </div>
                    <div className="p-3 bg-[#080B13] border border-[#1B2234]">
                      <div className="text-slate-400">Rule Baseline Net</div>
                      <div className="font-mono text-sm font-bold text-slate-300">
                        {fmtUsd(benchReport.handWrittenRules.netRecoveredCents)}
                      </div>
                    </div>
                    <div className="p-3 bg-[#080B13] border border-[#1B2234]">
                      <div className="text-slate-400">Compliance Breaches</div>
                      <div className="font-mono text-lg font-bold text-[#CCFF00]">
                        {benchReport.payRevive.complianceViolations}
                      </div>
                    </div>
                  </div>
                  <div className="font-mono text-[11px] text-slate-400">
                    TreeSHAP Additivity Verified: {benchReport.shapAdditivityChecksPassed}/
                    {benchReport.totalFailedPaymentsEvaluated} • Duration: {benchReport.durationMs}
                    ms • Proof: {benchReport.benchmarkProofHash?.slice(0, 20)}...
                  </div>
                </div>
              ) : (
                <p className="text-xs text-slate-400 py-4">
                  Click &ldquo;Run 500-Batch Test&rdquo; to evaluate 10,000 simulated payment
                  declines against the static rule baseline.
                </p>
              )}
            </div>

            {/* Right 6 Columns: TreeSHAP Attribution + LinUCB Arm Inspector */}
            <div className="lg:col-span-6 glass-brutal-panel p-6 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#1E293B] pb-3">
                <h2 className="font-display text-lg font-bold text-white">
                  TreeSHAP Attribution &amp; Disjoint LinUCB Arms
                </h2>
                <div className="flex gap-2">
                  <select
                    value={inspectPresetId}
                    onChange={(e) => setInspectPresetId(e.target.value)}
                    className="input-brutal text-xs py-1 w-44"
                  >
                    {state.payrevive.presets.map((p) => (
                      <option key={p.presetId} value={p.presetId}>
                        {p.title}
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    onClick={handleInspectShap}
                    className="btn-cobalt px-3 py-1.5 text-xs shrink-0"
                  >
                    Inspect
                  </button>
                </div>
              </div>

              {!inspectedDecision ? (
                <p className="text-xs text-slate-400 py-6">
                  Select a preset and click &ldquo;Inspect&rdquo; to view exact TreeSHAP log-odds
                  attributions and LinUCB contextual upper-confidence bounds.
                </p>
              ) : (
                <div className="space-y-4 text-xs">
                  <div className="flex items-center justify-between font-mono text-[11px] text-slate-300">
                    <span>
                      Calibrated P(Recoverable):{' '}
                      <strong className="text-[#CCFF00]">
                        {((inspectedDecision.diagnosis?.recoverabilityProbability ?? 0) * 100).toFixed(1)}%
                      </strong>
                    </span>
                    <span>
                      SHAP Sum Check:{' '}
                      {inspectedDecision.diagnosis?.additivityVerified ? 'EXACT' : 'DRIFT'}
                    </span>
                  </div>

                  <div className="space-y-1.5">
                    {(inspectedDecision.diagnosis?.shapContributions || [])
                      .slice(0, 6)
                      .map((attr: any) => {
                        const widthPct = Math.min(100, Math.round(Math.abs(attr.shapLogOdds) * 55));
                        return (
                          <div key={attr.featureKey} className="space-y-0.5">
                            <div className="flex justify-between font-mono text-[11px] gap-2">
                              <span className="text-slate-300 truncate">
                                {attr.featureLabel} ({attr.featureValueDisplay})
                              </span>
                              <span
                                className={`shrink-0 ${
                                  attr.shapLogOdds >= 0 ? 'text-[#CCFF00]' : 'text-red-400'
                                }`}
                              >
                                {attr.shapLogOdds >= 0 ? '+' : ''}
                                {Number(attr.shapLogOdds).toFixed(3)}
                              </span>
                            </div>
                            <div className="h-1.5 bg-[#080B13] border border-[#1B2234]">
                              <div
                                className={`h-full animate-shap-bar ${
                                  attr.shapLogOdds >= 0 ? 'bg-[#CCFF00]' : 'bg-red-500'
                                }`}
                                style={{ width: `${Math.max(4, widthPct)}%` }}
                              />
                            </div>
                          </div>
                        );
                      })}
                  </div>

                  {Array.isArray(inspectedDecision.allArms) && (
                    <div className="pt-2 border-t border-[#1E293B] space-y-1.5">
                      <div className="text-[11px] font-mono uppercase text-slate-400">
                        Disjoint LinUCB Contextual Arms (Verdict: {inspectedDecision.verdict})
                      </div>
                      <div className="space-y-1 max-h-36 overflow-y-auto pr-1">
                        {inspectedDecision.allArms.map((arm: any) => (
                          <div
                            key={arm.actionId}
                            className={`px-2.5 py-1.5 border flex items-center justify-between gap-2 font-mono text-[11px] ${
                              arm.actionId === inspectedDecision.selectedAction
                                ? 'bg-[#0047FF]/20 border-[#CCFF00] text-white'
                                : 'bg-[#080B13] border-[#1B2234] text-slate-400'
                            }`}
                          >
                            <span className="truncate">{arm.actionLabel}</span>
                            <span className="shrink-0">
                              {arm.compliance?.allowed
                                ? `UCB $${(arm.ucbScoreCents / 100).toFixed(2)}`
                                : 'COMPLIANCE BLOCKED'}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: 1,000-Case Property Fuzzer & Checkout Token Tamper Lab */}
      {labTab === 'fuzzer-tamper' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="glass-brutal-panel p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
              <div>
                <h2 className="font-display text-lg font-bold text-white">
                  1,000-Case Property-Based Safety Verifier
                </h2>
                <p className="text-xs text-slate-400">
                  Verifies monotonicity, concession floor, circuit breakers, mandate ceilings, and
                  penny conservation.
                </p>
              </div>
              <button
                type="button"
                onClick={handleRunFuzzer}
                disabled={fuzzRunning}
                className="btn-acid px-4 py-2 text-xs shrink-0"
              >
                {fuzzRunning ? 'Fuzzing...' : 'Run 1,000 Cases'}
              </button>
            </div>

            {fuzzReport && (
              <div className="space-y-3 text-xs">
                <div className="p-3 bg-[#080B13] border border-[#CCFF00] flex items-center justify-between">
                  <span className="font-bold text-white">
                    Passed {fuzzReport.passedCases} / {fuzzReport.totalCasesRun} Adversarial Inputs
                  </span>
                  <span className="font-mono text-[#CCFF00]">{fuzzReport.durationMs}ms</span>
                </div>
                <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
                  {Object.entries(fuzzReport.invariantsVerified).map(([k, v]) => (
                    <div key={k} className="p-2 bg-[#080B13] border border-[#1B2234] flex justify-between">
                      <span className="truncate text-slate-300">{k}</span>
                      <span className={v ? 'text-[#CCFF00]' : 'text-red-400'}>
                        {v ? 'PASS' : 'FAIL'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="glass-brutal-panel p-6 space-y-4">
            <div className="border-b border-[#1E293B] pb-3">
              <h2 className="font-display text-lg font-bold text-white">
                Single-Use HMAC Checkout Token Tamper Lab
              </h2>
              <p className="text-xs text-slate-400">
                Simulate mid-flight checkout tampering attacks against the server capture gate.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {[
                { id: 'MUTATE_AMOUNT', label: '10x Amount Mutation Attack' },
                { id: 'PAYEE_SWAP', label: 'Swap Recipient Wallet Attack' },
                { id: 'FORGE_SIGNATURE', label: 'Forge HMAC Signature Attack' },
                { id: 'EXPIRED_TOKEN', label: 'Replay Expired Token Attack' },
                { id: 'NEVER_REVIEWED', label: 'Bypass Pre-Payment Scan Attack' },
              ].map((atk) => (
                <button
                  key={atk.id}
                  type="button"
                  disabled={Boolean(tamperLoading)}
                  onClick={() => handleRunTamper(atk.id)}
                  className="btn-ghost-brutal p-2.5 text-xs justify-start"
                >
                  {tamperLoading === atk.id ? 'Testing...' : atk.label}
                </button>
              ))}
            </div>

            {tamperResult && (
              <div className="p-3.5 bg-red-950/30 border border-red-500/60 text-xs space-y-1">
                <div className="font-mono font-bold text-[#CCFF00]">
                  Capture Blocked: {tamperResult.verification?.errorCode}
                </div>
                <p className="text-slate-200">{tamperResult.verification?.reason}</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: AI Failover Router */}
      {labTab === 'ai-failover' && (
        <div className="glass-brutal-panel p-6 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#1E293B] pb-3">
            <div>
              <h2 className="font-display text-lg font-bold text-white">
                Dual-Provider AI Resilience Router (Google Gemini -&gt; Groq)
              </h2>
              <p className="text-xs text-slate-400">
                Test automatic HTTP 429 rate-limit interception and instant failover.
              </p>
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                disabled={failoverBusy}
                onClick={() => handleToggleFailover(true)}
                className="btn-acid px-4 py-2 text-xs"
              >
                Simulate Gemini 429 -&gt; Failover to Groq
              </button>
              <button
                type="button"
                disabled={failoverBusy}
                onClick={() => handleToggleFailover(false)}
                className="btn-cobalt px-4 py-2 text-xs"
              >
                Restore Primary Gemini Route
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
            <div className="p-3 bg-[#080B13] border border-[#1B2234]">
              <div className="text-slate-400">Active AI Mode</div>
              <div className="text-[#CCFF00] font-bold mt-1">{state.system.gemini.activeMode}</div>
            </div>
            <div className="p-3 bg-[#080B13] border border-[#1B2234]">
              <div className="text-slate-400">Primary Model</div>
              <div className="text-white font-bold mt-1">{state.system.gemini.primaryModel}</div>
            </div>
            <div className="p-3 bg-[#080B13] border border-[#1B2234]">
              <div className="text-slate-400">Failovers Triggered</div>
              <div className="text-white font-bold mt-1">
                {state.system.gemini.totalFailoversTriggered}
              </div>
            </div>
          </div>

          {failoverResult?.telemetry && (
            <div className="p-4 bg-[#080B13] border border-[#0047FF] text-xs font-mono space-y-1">
              <div className="text-[#CCFF00]">
                Provider Used: {failoverResult.telemetry.activeProviderUsed} (
                {failoverResult.telemetry.latencyMs}ms)
              </div>
              <div className="text-slate-300">{failoverResult.telemetry.failoverReason}</div>
            </div>
          )}
        </div>
      )}

      {/* TAB 4: AG Grid Immutable Audit Ledger */}
      {labTab === 'audit-ledger' && (
        <div className="glass-brutal-panel p-6 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#1E293B] pb-3">
            <div>
              <h2 className="font-display text-lg font-bold text-white">
                Tenant-Isolated Cryptographic Audit Ledger ({state.auditLogs.length} Records)
              </h2>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={handleExportCsv}
                className="btn-ghost-brutal px-3 py-1.5 text-xs"
              >
                <Download className="w-3.5 h-3.5" />
                Export CSV
              </button>
              <a
                href="/api/export/elastic-ndjson"
                className="btn-cobalt px-3 py-1.5 text-xs"
              >
                <Download className="w-3.5 h-3.5" />
                Export Elastic NDJSON
              </a>
            </div>
          </div>

          <div className="ag-theme-quartz-dark w-full h-[380px]">
            <AgGridReact
              rowData={state.auditLogs}
              columnDefs={columnDefs}
              pagination={true}
              paginationPageSize={12}
            />
          </div>
        </div>
      )}

      {/* TAB 5: Developer Bundles & Principal Architect RBAC Config */}
      {labTab === 'admin' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="glass-brutal-panel p-6 space-y-4">
            <h2 className="font-display text-lg font-bold text-white border-b border-[#1E293B] pb-3">
              Developer &amp; Ecosystem Bundles
            </h2>
            <p className="text-xs text-slate-300">
              Download the Postman API Collection or the Chrome Manifest V3 Checkout Guard
              Extension.
            </p>
            <div className="flex flex-wrap gap-3">
              <a
                href="/api/download/postman"
                download="AegisPay_Postman_Collection.json"
                className="btn-acid px-4 py-2.5 text-xs"
              >
                <Download className="w-4 h-4" />
                Postman API Collection
              </a>
              <a
                href="/api/download/extension"
                download="aegispay-chrome-extension-mv3.zip"
                className="btn-cobalt px-4 py-2.5 text-xs"
              >
                <Download className="w-4 h-4" />
                Chrome Extension (MV3 .zip)
              </a>
            </div>
          </div>

          <div className="glass-brutal-panel p-6 space-y-4">
            <h2 className="font-display text-lg font-bold text-white border-b border-[#1E293B] pb-3">
              Gateway Webhook Endpoint (Role: {state.operator?.role})
            </h2>
            <form onSubmit={handleSaveAdminConfig} className="space-y-3">
              <div>
                <label className="block text-xs text-slate-300 mb-1">
                  HTTPS Support Escalation Webhook URL (SSRF-Protected, PRINCIPAL_ARCHITECT Only)
                </label>
                <input
                  type="url"
                  value={zapierUrlInput}
                  onChange={(e) => setZapierUrlInput(e.target.value)}
                  placeholder="https://hooks.zapier.com/hooks/catch/..."
                  className="input-brutal"
                />
              </div>
              <button type="submit" className="btn-ghost-brutal px-4 py-2 text-xs">
                Save Webhook URL
              </button>
              {credStatus && <div className="text-xs font-mono text-[#CCFF00]">{credStatus}</div>}
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default DiagnosticsLab;
