import React, { useState } from 'react';
import {
  ArrowRight,
  CheckCircle2,
  ClipboardPaste,
  Cpu,
  CreditCard,
  Download,
  FileText,
  Handshake,
  HeartHandshake,
  Lock,
  Mic,
  Play,
  Puzzle,
  RefreshCw,
  ShieldCheck,
  Sliders,
  Sparkles,
  Wallet,
} from 'lucide-react';
import { AegisBrandMark } from '../api';

interface LandingPageProps {
  onOpenAuth: (mode?: 'login' | 'register') => void;
  onLaunchDemo: () => Promise<void>;
  demoLoading: boolean;
}

const HERO_LIVE_PREVIEWS = [
  {
    id: 'device-agent',
    badge: '1-CLICK DEVICE AGENT',
    title: 'Clipboard, File Drop & Voice -> Instant PayPal Execution',
    items: [
      {
        step: '1. 1-Click Paste / Drop Any Artifact',
        detail: 'Invoice text, bank .CSV, damage photo, cancel email, or SOW',
        tag: 'Auto-Classified',
        tone: 'lime',
      },
      {
        step: '2. Hybrid AI + Deterministic Kernel',
        detail: 'Gemini 2.5 / Groq parses intent; hard math verifies safety & limits',
        tag: '100% Grounded',
        tone: 'cobalt',
      },
      {
        step: '3. Settled on PayPal Sandbox',
        detail: 'Orders v2, Invoicing v2, Captures Refund, Subscriptions & Vault v3',
        tag: 'SHA-256 Audited',
        tone: 'lime',
      },
    ],
  },
  {
    id: 'pay-safely',
    badge: 'PILLAR 01 • PAY SAFELY',
    title: 'ScamShield, Real Subscription Cleanup & Cashflow Advisor',
    items: [
      {
        step: '1. ScamShield Invoice & Link Scanner',
        detail: 'Blocks lookalike domains & urgent scams; mints single-use HMAC token',
        tag: 'Checkout Locked',
        tone: 'lime',
      },
      {
        step: '2. Subscription & Autopay Cleanup',
        detail: 'Live PayPal Sandbox sync + CSV/screenshot import + 1-click auto-clean',
        tag: 'Save $64+/mo',
        tone: 'cobalt',
      },
      {
        step: '3. Natural-Language Cashflow & Vault Permits',
        detail: 'Ask "Can I afford $580?" with Pay-in-4 math & plain-English agent caps',
        tag: 'Buffer Protected',
        tone: 'lime',
      },
    ],
  },
  {
    id: 'recover-retain',
    badge: 'PILLAR 02 • RECOVER & RETAIN',
    title: 'PayRevive GBDT+LinUCB, ClipRefund Vision & ChurnRescue',
    items: [
      {
        step: '1. PayRevive Failed Payment Recovery',
        detail: '25-tree Newton GBDT + Exact TreeSHAP + Disjoint LinUCB + Compliance Gate',
        tag: '0.858 ROC-AUC',
        tone: 'lime',
      },
      {
        step: '2. ClipRefund Keep-the-Item Refunds',
        detail: 'Multimodal defect grading + SHA-256 photo anti-replay + instant refund',
        tag: 'Saved Shipping',
        tone: 'cobalt',
      },
      {
        step: '3. ChurnRescue Cancel-Flow Saver',
        detail: 'Right-sized loyalty discount (<=50%) + legal/dispute circuit breaker',
        tag: 'Zero Leakage',
        tone: 'lime',
      },
    ],
  },
  {
    id: 'get-paid',
    badge: 'PILLAR 03 • GET PAID',
    title: 'PayStream Penny-Exact Milestones & DealForge Negotiation',
    items: [
      {
        step: '1. PayStream Milestone & Team Splits',
        detail: 'Plain-English SOW -> penny-exact phases & multi-collaborator splits',
        tag: 'INV2-... Live',
        tone: 'lime',
      },
      {
        step: '2. Deliverable Proof Verification',
        detail: 'Verifies GitHub/Figma delivery links before releasing milestone payouts',
        tag: 'Attested Hash',
        tone: 'cobalt',
      },
      {
        step: '3. DealForge 4-Round Vendor Clearing',
        detail: 'Buyer vs. Vendor mandate clamps + signed SHA-256 contract & deposit',
        tag: 'ZOPA Verified',
        tone: 'lime',
      },
    ],
  },
] as const;

export const LandingPage: React.FC<LandingPageProps> = ({
  onOpenAuth,
  onLaunchDemo,
  demoLoading,
}) => {
  const [tilt, setTilt] = useState({ x: 0, y: 0 });
  const [previewIdx, setPreviewIdx] = useState(0);

  const handleSpatialMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const nx = (e.clientX - rect.left) / rect.width - 0.5;
    const ny = (e.clientY - rect.top) / rect.height - 0.5;
    setTilt({ x: -ny * 7, y: nx * 7 });
  };

  const activePreview = HERO_LIVE_PREVIEWS[previewIdx] || HERO_LIVE_PREVIEWS[0];

  return (
    <div className="min-h-screen w-full bg-midnight-grid text-slate-100 flex flex-col">
      {/* Top Symmetrical Navigation Bar */}
      <header className="w-full border-b border-[#192030] bg-[#050507]/90 backdrop-blur-md sticky top-0 z-30">
        <div className="w-full px-4 sm:px-8 lg:px-12 h-16 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <AegisBrandMark size={34} />
            <div>
              <span className="font-display text-lg font-bold tracking-tight text-white">
                AegisPay
              </span>
              <span className="hidden sm:inline-block ml-2.5 text-[11px] font-mono uppercase tracking-widest px-2 py-0.5 bg-[#0047FF]/20 text-[#CCFF00] border border-[#0047FF]/50">
                Agentic PayPal Suite v3.2
              </span>
            </div>
          </div>

          <nav className="hidden lg:flex items-center gap-7 text-xs font-mono uppercase tracking-wider text-slate-300">
            <a href="#agentic-bar" className="hover:text-[#CCFF00] transition-colors">
              1-Click Device Agent
            </a>
            <a href="#features" className="hover:text-[#CCFF00] transition-colors">
              8 Core Workflows
            </a>
            <a href="#mcp-extension" className="hover:text-[#CCFF00] transition-colors">
              Chrome MV3 &amp; 13-Tool MCP
            </a>
            <a href="#how-it-works" className="hover:text-[#CCFF00] transition-colors">
              How It Works
            </a>
          </nav>

          <div className="flex items-center gap-2.5">
            <a
              href="/api/download/extension"
              download="aegispay-chrome-extension-mv3.zip"
              className="hidden sm:inline-flex btn-ghost-brutal px-3 py-2 text-xs items-center gap-1.5 border-[#0047FF]/70 text-slate-200"
              title="Download Chrome Manifest V3 Checkout Guard Extension (.zip)"
            >
              <Download className="w-3.5 h-3.5 text-[#CCFF00]" />
              <span>Extension (.zip)</span>
            </a>
            <button
              type="button"
              onClick={() => onOpenAuth('login')}
              className="btn-ghost-brutal px-3.5 py-2 text-xs sm:text-sm"
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => onOpenAuth('register')}
              className="btn-acid px-4 py-2 text-xs sm:text-sm"
            >
              Get Started
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      {/* Main Full-Width Brutalist + Minimalist + Spatial Hero */}
      <main className="flex-1 w-full px-4 sm:px-8 lg:px-12 py-10 lg:py-14 space-y-16">
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center">
          {/* Left 7 Columns: Clean Value Proposition */}
          <div className="lg:col-span-7 space-y-6">
            <div className="inline-flex flex-wrap items-center gap-2 px-3 py-1.5 border border-[#0047FF] bg-[#090D18] text-xs font-mono uppercase tracking-wider text-[#CCFF00]">
              <span className="w-2 h-2 bg-[#CCFF00] animate-beacon" />
              Agentic AI + Deterministic Safety Kernel • PayPal Sandbox Live
            </div>

            <h1 className="font-display text-3xl sm:text-5xl xl:text-6xl font-bold tracking-tight text-white leading-[1.06]">
              Pay safely, clean up autopays, recover failed sales, and bill milestones on{' '}
              <span className="text-[#CCFF00] underline decoration-[#0047FF] decoration-4 underline-offset-8">
                PayPal
              </span>
              .
            </h1>

            <p className="text-base sm:text-lg text-slate-300 max-w-2xl leading-relaxed">
              Paste from your clipboard, drop any invoice, bank statement <code className="text-[#CCFF00] font-mono text-sm">.CSV</code>, damaged-item photo, cancellation email, or client SOW, or speak by voice.{' '}
              <strong className="text-white">AegisPay</strong> pairs multimodal AI with a deterministic financial kernel so AI parses the context while tested code enforces every dollar limit on PayPal.
            </p>

            <div className="flex flex-wrap items-center gap-3.5 pt-1">
              <button
                type="button"
                onClick={onLaunchDemo}
                disabled={demoLoading}
                className="btn-acid px-6 py-3.5 text-sm sm:text-base"
              >
                <Play className="w-4 h-4 fill-current" />
                {demoLoading ? 'Opening Guided Workspace...' : 'Launch 1-Click Guided Workspace'}
              </button>

              <button
                type="button"
                onClick={() => onOpenAuth('login')}
                className="btn-cobalt px-6 py-3.5 text-sm sm:text-base"
              >
                <Lock className="w-4 h-4" />
                Sign In (Google or Email Unified)
              </button>
            </div>

            {/* Symmetrical 4-Metric Proof Strip */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-4 border-t border-[#192030]">
              <div className="p-3 bg-[#090B10] border border-[#192030]">
                <div className="text-xs font-mono text-[#CCFF00] uppercase">1-Click Agent Bar</div>
                <div className="text-sm font-semibold text-white mt-0.5">
                  Clipboard, Drop &amp; Voice
                </div>
              </div>
              <div className="p-3 bg-[#090B10] border border-[#192030]">
                <div className="text-xs font-mono text-[#CCFF00] uppercase">PayRevive ML</div>
                <div className="text-sm font-semibold text-white mt-0.5">
                  GBDT + TreeSHAP + LinUCB
                </div>
              </div>
              <div className="p-3 bg-[#090B10] border border-[#192030]">
                <div className="text-xs font-mono text-[#CCFF00] uppercase">Live MCP Server</div>
                <div className="text-sm font-semibold text-white mt-0.5">
                  13 Tools (HTTP + Stdio)
                </div>
              </div>
              <div className="p-3 bg-[#090B10] border border-[#192030]">
                <div className="text-xs font-mono text-[#CCFF00] uppercase">Safety Invariants</div>
                <div className="text-sm font-semibold text-white mt-0.5">
                  1,000-Case Fuzz Verified
                </div>
              </div>
            </div>
          </div>

          {/* Right 5 Columns: Interactive Spatial UI Live Preview Deck */}
          <div
            className="lg:col-span-5 spatial-stage"
            onMouseMove={handleSpatialMove}
            onMouseLeave={() => setTilt({ x: 0, y: 0 })}
          >
            <div
              className="spatial-deck brutalist-card corner-ticks p-6 sm:p-7 overflow-hidden bg-[#080B12]"
              style={{
                transform: `rotateX(${tilt.x}deg) rotateY(${tilt.y}deg)`,
              }}
            >
              <div className="scanline-beam" />
              <div className="flex items-center justify-between pb-3 border-b border-[#1B2234]">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-[#CCFF00]" />
                  <span className="font-display font-bold text-xs sm:text-sm uppercase tracking-wider text-white">
                    {activePreview.badge}
                  </span>
                </div>
                <span className="text-[11px] font-mono px-2 py-0.5 bg-[#CCFF00] text-[#050507] font-bold">
                  LIVE PREVIEW
                </span>
              </div>

              {/* Interactive Pillar Switcher inside Spatial Card */}
              <div className="grid grid-cols-4 gap-1.5 mt-3">
                {[
                  { label: 'Agent Bar', idx: 0 },
                  { label: 'Pay Safely', idx: 1 },
                  { label: 'Recover', idx: 2 },
                  { label: 'Get Paid', idx: 3 },
                ].map((tab) => (
                  <button
                    key={tab.label}
                    type="button"
                    onClick={() => setPreviewIdx(tab.idx)}
                    className={`py-1.5 px-2 text-[11px] font-mono border transition-colors ${
                      previewIdx === tab.idx
                        ? 'bg-[#0047FF] border-[#CCFF00] text-white font-bold'
                        : 'bg-[#050507] border-[#1E293B] text-slate-400 hover:text-white'
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              <div className="text-xs font-semibold text-slate-200 mt-3">
                {activePreview.title}
              </div>

              <div className="space-y-3 my-4">
                {activePreview.items.map((item) => (
                  <div
                    key={item.step}
                    className="p-3 bg-[#0D121F] border border-[#1E293B] flex items-center justify-between gap-3"
                  >
                    <div>
                      <div className="text-xs font-semibold text-white">{item.step}</div>
                      <div className="text-[11px] text-slate-400 mt-0.5">{item.detail}</div>
                    </div>
                    <span
                      className={`text-[11px] font-mono px-2 py-1 shrink-0 border ${
                        item.tone === 'lime'
                          ? 'bg-[#CCFF00]/15 text-[#CCFF00] border-[#CCFF00]/40'
                          : 'bg-[#0047FF]/25 text-white border-[#0047FF]'
                      }`}
                    >
                      {item.tag}
                    </span>
                  </div>
                ))}
              </div>

              <div className="pt-3 border-t border-[#1B2234] flex items-center justify-between text-xs text-slate-400">
                <span>First-sign-up guided tour • Zero repeat popups</span>
                <button
                  type="button"
                  onClick={onLaunchDemo}
                  className="text-[#CCFF00] font-semibold hover:underline inline-flex items-center gap-1"
                >
                  Open Live Workspace
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        </section>

        {/* NEW SECTION: 1-Click Universal Device Agent Bar Showcase */}
        <section
          id="agentic-bar"
          className="brutalist-card corner-ticks p-6 sm:p-8 bg-[#080B13] border border-[#0047FF]/70 space-y-6"
        >
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#192030] pb-5">
            <div className="space-y-1.5">
              <div className="inline-flex items-center gap-2 text-xs font-mono uppercase tracking-widest text-[#CCFF00]">
                <Sparkles className="w-4 h-4" />
                Zero-Barrier Device &amp; Browser Intelligence
              </div>
              <h2 className="font-display text-2xl sm:text-3xl font-bold text-white">
                1-Click Universal Device Agent Bar &amp; Proactive Recommendations
              </h2>
              <p className="text-sm text-slate-300 max-w-3xl">
                No manual form-filling required. Every screen in AegisPay includes a persistent Universal Device Agent that reads your clipboard, accepts dragged files or screenshots, listens via Web Speech dictation, and automatically routes &amp; executes the right PayPal workflow.
              </p>
            </div>
            <button
              type="button"
              onClick={onLaunchDemo}
              disabled={demoLoading}
              className="btn-acid px-5 py-3 text-xs sm:text-sm shrink-0"
            >
              <ClipboardPaste className="w-4 h-4" />
              Test 1-Click Agent Bar Live
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 bg-[#050507] border border-[#1E293B] space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-[#CCFF00] uppercase">01 • Clipboard</span>
                <ClipboardPaste className="w-4 h-4 text-[#CCFF00]" />
              </div>
              <h3 className="font-display text-base font-bold text-white">
                1-Click Paste &amp; Auto-Act
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                Copy any invoice email, vendor quote, decline log, or cancellation note on your device and click once—AegisPay extracts entities and runs the check immediately.
              </p>
            </div>

            <div className="p-4 bg-[#050507] border border-[#1E293B] space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-[#CCFF00] uppercase">02 • File &amp; Vision</span>
                <FileText className="w-4 h-4 text-[#CCFF00]" />
              </div>
              <h3 className="font-display text-base font-bold text-white">
                Drop .PDF, .CSV, .EML or Photos
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                Drag and drop bank statement CSVs to import subscriptions, invoice screenshots for multimodal scam scanning, or damaged product photos for instant partial refunds.
              </p>
            </div>

            <div className="p-4 bg-[#050507] border border-[#1E293B] space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-[#CCFF00] uppercase">03 • Voice Input</span>
                <Mic className="w-4 h-4 text-[#CCFF00]" />
              </div>
              <h3 className="font-display text-base font-bold text-white">
                Speak Plain-English Commands
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                Ask &ldquo;Can I afford a $580 monitor this week?&rdquo; or dictate a project SOW—AegisPay updates your live cashflow profile or creates penny-exact PayPal milestones.
              </p>
            </div>

            <div className="p-4 bg-[#050507] border border-[#1E293B] space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-[#CCFF00] uppercase">04 • Proactive AI</span>
                <Sparkles className="w-4 h-4 text-[#CCFF00]" />
              </div>
              <h3 className="font-display text-base font-bold text-white">
                Next-Best-Action Suggestions
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                Continuously monitors your workspace for unused autopays, held PayPal authorizations, unbilled milestones, and recoverable declined checkouts—actionable in 1 click.
              </p>
            </div>
          </div>
        </section>

        {/* Complete 8-Workflow Suite Across 3 Pillars */}
        <section id="features" className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3 border-b border-[#192030] pb-4">
            <div>
              <div className="text-xs font-mono uppercase tracking-widest text-[#CCFF00]">
                Complete 8-Workflow Product Suite
              </div>
              <h2 className="font-display text-2xl sm:text-3xl font-bold text-white mt-1">
                Every capability delivered end-to-end across three pillars
              </h2>
            </div>
            <p className="text-xs sm:text-sm text-slate-400 max-w-md">
              All 8 modules accept natural-language descriptions, uploaded files, or custom parameters and execute against PayPal Sandbox APIs with SHA-256 audit receipts.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
            {/* 1. ScamShield */}
            <div className="brutalist-card brutalist-card-lime p-5 space-y-3 flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="w-9 h-9 bg-[#0047FF]/20 border border-[#0047FF] flex items-center justify-center text-[#CCFF00]">
                    <ShieldCheck className="w-5 h-5" />
                  </div>
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 bg-[#090D18] border border-[#1E293B] text-[#CCFF00]">
                    Pay Safely • 01
                  </span>
                </div>
                <h3 className="font-display text-lg font-bold text-white">
                  ScamShield Invoice &amp; Link Scanner
                </h3>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Scans invoices, emails, and screenshots for lookalike domains, off-platform coercion, and prompt injection. Mints a single-use HMAC-SHA256 token that locks amount, currency, and payee before PayPal checkout.
                </p>
              </div>
              <div className="text-[11px] font-mono text-slate-400 pt-2 border-t border-[#192030]">
                PayPal Orders v2 + Single-Use HMAC Lock
              </div>
            </div>

            {/* 2. Real Subscription & Autopay Cleanup */}
            <div className="brutalist-card brutalist-card-lime p-5 space-y-3 flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="w-9 h-9 bg-[#0047FF]/20 border border-[#0047FF] flex items-center justify-center text-[#CCFF00]">
                    <Sliders className="w-5 h-5" />
                  </div>
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 bg-[#090D18] border border-[#1E293B] text-[#CCFF00]">
                    Pay Safely • 02
                  </span>
                </div>
                <h3 className="font-display text-lg font-bold text-white">
                  Real Subscription &amp; Autopay Cleanup
                </h3>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Sync live recurring billing agreements from PayPal Sandbox, import any bank/PayPal CSV or statement screenshot, create real sandbox subscriptions, and auto-clean unused or silently hiked autopays in 1 click.
                </p>
              </div>
              <div className="text-[11px] font-mono text-slate-400 pt-2 border-t border-[#192030]">
                PayPal Subscriptions v1 + CSV/Vision Import
              </div>
            </div>

            {/* 3. Conversational Cashflow & Affordability */}
            <div className="brutalist-card brutalist-card-lime p-5 space-y-3 flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="w-9 h-9 bg-[#0047FF]/20 border border-[#0047FF] flex items-center justify-center text-[#CCFF00]">
                    <Wallet className="w-5 h-5" />
                  </div>
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 bg-[#090D18] border border-[#1E293B] text-[#CCFF00]">
                    Pay Safely • 03
                  </span>
                </div>
                <h3 className="font-display text-lg font-bold text-white">
                  Conversational Cashflow &amp; Pay-in-4 Advisor
                </h3>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Ask in plain English (&ldquo;Can I afford a $650 lens if my balance is $3,400 and rent is $1,800?&rdquo;). Computes your post-bill safety buffer, simulates PayPal Pay-in-4 installments, and edits bills live.
                </p>
              </div>
              <div className="text-[11px] font-mono text-slate-400 pt-2 border-t border-[#192030]">
                Deterministic Waterfall + Pay-in-4 Simulator
              </div>
            </div>

            {/* 4. LupaPermit AI Spending Rules & Vault v3 */}
            <div className="brutalist-card brutalist-card-lime p-5 space-y-3 flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="w-9 h-9 bg-[#0047FF]/20 border border-[#0047FF] flex items-center justify-center text-[#CCFF00]">
                    <Lock className="w-5 h-5" />
                  </div>
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 bg-[#090D18] border border-[#1E293B] text-[#CCFF00]">
                    Pay Safely • 04
                  </span>
                </div>
                <h3 className="font-display text-lg font-bold text-white">
                  Plain-English Spending Rules &amp; Vault v3
                </h3>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Compile natural-language spending rules with strict numeric grounding verification. Enforces monotonic ALLOW (PayPal CAPTURE), HOLD (PayPal AUTHORIZE), or BLOCK verdicts and mints PayPal Vault v3 setup tokens.
                </p>
              </div>
              <div className="text-[11px] font-mono text-slate-400 pt-2 border-t border-[#192030]">
                PayPal Vault v3 + AUTHORIZE / CAPTURE Hold Gate
              </div>
            </div>

            {/* 5. PayRevive Failed Payment Recovery */}
            <div className="brutalist-card brutalist-card-lime p-5 space-y-3 flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="w-9 h-9 bg-[#0047FF]/20 border border-[#0047FF] flex items-center justify-center text-[#CCFF00]">
                    <RefreshCw className="w-5 h-5" />
                  </div>
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 bg-[#090D18] border border-[#1E293B] text-[#CCFF00]">
                    Recover &amp; Retain • 05
                  </span>
                </div>
                <h3 className="font-display text-lg font-bold text-white">
                  PayRevive Declined Checkout Recovery
                </h3>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Describe any failed checkout or pick from queue. Combines a 25-tree Newton GBDT ensemble, exact TreeSHAP attributions, and a Disjoint LinUCB contextual bandit with a zero-violation compliance gate.
                </p>
              </div>
              <div className="text-[11px] font-mono text-slate-400 pt-2 border-t border-[#192030]">
                Newton GBDT + TreeSHAP + LinUCB Bandit
              </div>
            </div>

            {/* 6. ClipRefund Keep-the-Item Partial Refunds */}
            <div className="brutalist-card brutalist-card-lime p-5 space-y-3 flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="w-9 h-9 bg-[#0047FF]/20 border border-[#0047FF] flex items-center justify-center text-[#CCFF00]">
                    <CreditCard className="w-5 h-5" />
                  </div>
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 bg-[#090D18] border border-[#1E293B] text-[#CCFF00]">
                    Recover &amp; Retain • 06
                  </span>
                </div>
                <h3 className="font-display text-lg font-bold text-white">
                  ClipRefund Keep-the-Item Partial Refunds
                </h3>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Upload a damaged delivery photo or describe the defect in plain English. Vision AI extracts non-monetary physical severity while your customizable merchant policy matrix issues an instant partial PayPal refund.
                </p>
              </div>
              <div className="text-[11px] font-mono text-slate-400 pt-2 border-t border-[#192030]">
                PayPal Captures Refund + SHA-256 Anti-Replay
              </div>
            </div>

            {/* 7. ChurnRescue Subscriber Retention */}
            <div className="brutalist-card brutalist-card-lime p-5 space-y-3 flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="w-9 h-9 bg-[#0047FF]/20 border border-[#0047FF] flex items-center justify-center text-[#CCFF00]">
                    <HeartHandshake className="w-5 h-5" />
                  </div>
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 bg-[#090D18] border border-[#1E293B] text-[#CCFF00]">
                    Recover &amp; Retain • 07
                  </span>
                </div>
                <h3 className="font-display text-lg font-bold text-white">
                  ChurnRescue Cancel-Flow Saver
                </h3>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Paste any cancellation email or subscriber scenario. Enforces a 20% -&gt; 35% -&gt; 50% max concession ladder, blocks discounts on heavy usage (&gt;85%), and trips a legal/chargeback circuit breaker to human support.
                </p>
              </div>
              <div className="text-[11px] font-mono text-slate-400 pt-2 border-t border-[#192030]">
                PayPal Loyalty Plan + Legal Circuit Breaker
              </div>
            </div>

            {/* 8. PayStream & DealForge */}
            <div className="brutalist-card brutalist-card-lime p-5 space-y-3 flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="w-9 h-9 bg-[#0047FF]/20 border border-[#0047FF] flex items-center justify-center text-[#CCFF00]">
                    <Handshake className="w-5 h-5" />
                  </div>
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 bg-[#090D18] border border-[#1E293B] text-[#CCFF00]">
                    Get Paid • 08
                  </span>
                </div>
                <h3 className="font-display text-lg font-bold text-white">
                  PayStream Milestones &amp; DealForge Deals
                </h3>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Turn any SOW into penny-exact PayPal invoices (<code className="text-[#CCFF00] font-mono">INV2-...</code>) with multi-collaborator splits &amp; proof verification, or run a 4-round Buyer vs. Vendor quote negotiation with SHA-256 contracts.
                </p>
              </div>
              <div className="text-[11px] font-mono text-slate-400 pt-2 border-t border-[#192030]">
                PayPal Invoicing v2 + 4-Round ZOPA Clearing
              </div>
            </div>
          </div>
        </section>

        {/* NEW SECTION: Chrome Extension (MV3), 13-Tool MCP Server & Postman Ecosystem */}
        <section id="mcp-extension" className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-6 brutalist-card corner-ticks p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-[#192030] pb-3">
              <div className="flex items-center gap-2.5">
                <Puzzle className="w-5 h-5 text-[#CCFF00]" />
                <div>
                  <div className="text-xs font-mono uppercase text-[#CCFF00]">
                    Browser Checkout Protection
                  </div>
                  <h3 className="font-display text-xl font-bold text-white">
                    Chrome Extension (Manifest V3) + In-App Simulator
                  </h3>
                </div>
              </div>
              <span className="text-[11px] font-mono px-2 py-0.5 bg-[#0047FF]/20 border border-[#0047FF] text-[#CCFF00]">
                MV3 READY
              </span>
            </div>

            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              Install the standalone Chrome Extension via <code className="text-[#CCFF00] font-mono">chrome://extensions</code> (Developer Mode -&gt; Load unpacked) or test it directly inside the workspace with zero installation using our built-in Browser Extension Side-Panel Simulator.
            </p>

            <ul className="space-y-1.5 text-xs text-slate-300 font-mono">
              <li>• Reads active tab invoice / checkout DOM in 1 click</li>
              <li>• Runs ScamShield + Cashflow Affordability check in popup</li>
              <li>• Generates verified PayPal Sandbox checkout link with HMAC lock</li>
            </ul>

            <div className="flex flex-wrap items-center gap-3 pt-2">
              <a
                href="/api/download/extension"
                download="aegispay-chrome-extension-mv3.zip"
                className="btn-acid px-4 py-2.5 text-xs flex items-center gap-2"
              >
                <Download className="w-4 h-4" />
                <span>Download Chrome Extension (.zip)</span>
              </a>
              <button
                type="button"
                onClick={onLaunchDemo}
                className="btn-ghost-brutal px-4 py-2.5 text-xs"
              >
                Try In-Browser Simulator
              </button>
            </div>
          </div>

          <div className="lg:col-span-6 brutalist-card corner-ticks p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-[#192030] pb-3">
              <div className="flex items-center gap-2.5">
                <Cpu className="w-5 h-5 text-[#CCFF00]" />
                <div>
                  <div className="text-xs font-mono uppercase text-[#CCFF00]">
                    Model Context Protocol (v2024-11-05)
                  </div>
                  <h3 className="font-display text-xl font-bold text-white">
                    Always-On 13-Tool MCP Server (HTTP, Stdio &amp; WebMCP)
                  </h3>
                </div>
              </div>
              <span className="text-[11px] font-mono px-2 py-0.5 bg-[#CCFF00]/15 border border-[#CCFF00]/50 text-[#CCFF00]">
                13 TOOLS LIVE
              </span>
            </div>

            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              Connect Claude Desktop, Cursor, or any MCP client via HTTP JSON-RPC 2.0 (<code className="text-[#CCFF00] font-mono">POST /api/mcp</code>), stdio (<code className="text-[#CCFF00] font-mono">npm run mcp</code>), or Chromium WebMCP (<code className="text-[#CCFF00] font-mono">navigator.modelContext</code>) to invoke all 13 AegisPay tools autonomously.
            </p>

            <div className="p-3 bg-[#050507] border border-[#1E293B] font-mono text-[11px] text-slate-300 space-y-1">
              <div className="text-[#CCFF00]">
                # Test Live MCP Tool Discovery or Execution:
              </div>
              <div className="truncate">
                POST /api/mcp &#123; &quot;jsonrpc&quot;: &quot;2.0&quot;, &quot;method&quot;: &quot;tools/list&quot;, &quot;id&quot;: 1 &#125;
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3 pt-1">
              <a
                href="/api/download/postman"
                download="AegisPay_Collection.json"
                className="btn-cobalt px-4 py-2.5 text-xs flex items-center gap-2"
              >
                <Download className="w-4 h-4" />
                <span>Download Postman Collection (.json)</span>
              </a>
              <button
                type="button"
                onClick={onLaunchDemo}
                className="btn-ghost-brutal px-4 py-2.5 text-xs"
              >
                Open Interactive MCP Console
              </button>
            </div>
          </div>
        </section>

        {/* Symmetrical 3-Step "How It Works" Banner */}
        <section id="how-it-works" className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3 border-b border-[#192030] pb-4">
            <div>
              <div className="text-xs font-mono uppercase tracking-widest text-[#CCFF00]">
                Simple 3-Step Architecture
              </div>
              <h2 className="font-display text-2xl sm:text-3xl font-bold text-white mt-1">
                How AegisPay keeps every autonomous action safe
              </h2>
            </div>
            <p className="text-sm text-slate-400 max-w-md">
              AI models never directly move money. Every workflow passes through deterministic math and cryptographic verification before touching PayPal.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {[
              {
                step: '01',
                title: '1-Click Ingest or Plain-English Input',
                desc: 'Paste from clipboard, drag-and-drop a file or screenshot, dictate by voice, or type any scenario in plain English.',
              },
              {
                step: '02',
                title: 'Deterministic Policy & Math Verification',
                desc: 'Our TypeScript kernel verifies grounded numbers, cashflow buffers, TreeSHAP + LinUCB EV, and mandate clamps with 1,000-case fuzz guarantees.',
              },
              {
                step: '03',
                title: 'Live PayPal Sandbox Execution & Audit',
                desc: 'Settle orders, issue partial refunds, cancel zombie autopays, or send PayPal invoices with an immutable SHA-256 audit row.',
              },
            ].map((item) => (
              <div key={item.step} className="brutalist-card corner-ticks p-6 flex flex-col justify-between">
                <div>
                  <div className="inline-block font-mono text-xs font-bold px-2.5 py-1 bg-[#0047FF] text-white mb-4">
                    STEP {item.step}
                  </div>
                  <h3 className="font-display text-lg font-bold text-white">{item.title}</h3>
                  <p className="text-sm text-slate-300 mt-2 leading-relaxed">{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Bottom CTA Banner */}
        <section
          id="who-its-for"
          className="brutalist-card corner-ticks p-6 sm:p-10 bg-gradient-to-r from-[#090D1A] via-[#070A12] to-[#0A1329] flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6"
        >
          <div className="space-y-2 max-w-2xl">
            <div className="inline-flex items-center gap-2 text-xs font-mono uppercase text-[#CCFF00]">
              <Sparkles className="w-4 h-4" />
              First-Sign-Up Guided Tour • Unified Google &amp; Email Accounts
            </div>
            <h2 className="font-display text-2xl sm:text-3xl font-bold text-white">
              Ready to explore the complete AegisPay v3.2 platform?
            </h2>
            <p className="text-sm text-slate-300">
              Sign in seamlessly with Google OAuth or Email/Password (automatically unified under one account), or launch the instant Guided Demo Workspace with an interactive walkthrough on your first visit.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={onLaunchDemo}
              disabled={demoLoading}
              className="btn-acid px-6 py-3 text-sm"
            >
              <CheckCircle2 className="w-4 h-4" />
              {demoLoading ? 'Launching...' : 'Start Guided Demo'}
            </button>
            <button
              type="button"
              onClick={() => onOpenAuth('register')}
              className="btn-ghost-brutal px-5 py-3 text-sm"
            >
              Create Account
            </button>
          </div>
        </section>
      </main>

      {/* Clean Minimal Footer */}
      <footer className="w-full border-t border-[#192030] py-6 px-4 sm:px-8 lg:px-12 text-xs text-slate-400 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <AegisBrandMark size={22} />
          <span className="font-semibold text-slate-200">AegisPay v3.2</span>
          <span>— Agentic Payment Safety, Revenue Recovery &amp; Milestone Billing on PayPal</span>
        </div>
        <div className="font-mono text-[11px] text-slate-400">
          Stateless HMAC Sessions • Isolated Multi-Tenant Workspaces • 13-Tool MCP Server • PayPal Sandbox Connected
        </div>
      </footer>
    </div>
  );
};
