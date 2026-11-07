import React, { useState } from 'react';
import {
  ArrowRight,
  CheckCircle2,
  CreditCard,
  FileText,
  Lock,
  Play,
  RefreshCw,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import { AegisBrandMark } from '../api';

interface LandingPageProps {
  onOpenAuth: (mode?: 'login' | 'register') => void;
  onLaunchDemo: () => Promise<void>;
  demoLoading: boolean;
}

export const LandingPage: React.FC<LandingPageProps> = ({
  onOpenAuth,
  onLaunchDemo,
  demoLoading,
}) => {
  const [tilt, setTilt] = useState({ x: 0, y: 0 });

  const handleSpatialMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const nx = (e.clientX - rect.left) / rect.width - 0.5;
    const ny = (e.clientY - rect.top) / rect.height - 0.5;
    setTilt({ x: -ny * 7, y: nx * 7 });
  };

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
                Built for PayPal
              </span>
            </div>
          </div>

          <nav className="hidden md:flex items-center gap-8 text-sm text-slate-300">
            <a href="#how-it-works" className="hover:text-[#CCFF00] transition-colors">
              How It Works
            </a>
            <a href="#features" className="hover:text-[#CCFF00] transition-colors">
              Features
            </a>
            <a href="#who-its-for" className="hover:text-[#CCFF00] transition-colors">
              Use Cases
            </a>
          </nav>

          <div className="flex items-center gap-2.5">
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
      <main className="flex-1 w-full px-4 sm:px-8 lg:px-12 py-10 lg:py-16 space-y-16">
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center">
          {/* Left 7 Columns: Clean Value Proposition */}
          <div className="lg:col-span-7 space-y-6">
            <div className="inline-flex items-center gap-2 px-3 py-1.5 border border-[#0047FF] bg-[#090D18] text-xs font-mono uppercase tracking-wider text-[#CCFF00]">
              <span className="w-2 h-2 bg-[#CCFF00] animate-beacon" />
              PayPal Payment Safety, Recovery &amp; Milestone Billing
            </div>

            <h1 className="font-display text-3xl sm:text-5xl xl:text-6xl font-bold tracking-tight text-white leading-[1.06]">
              Pay safely, recover declined sales, and bill clients cleanly on{' '}
              <span className="text-[#CCFF00] underline decoration-[#0047FF] decoration-4 underline-offset-8">
                PayPal
              </span>
              .
            </h1>

            <p className="text-base sm:text-lg text-slate-300 max-w-2xl leading-relaxed">
              One clear workspace for buyers, online stores, and agencies. Check suspicious
              invoices before paying, win back failed customer payments automatically, settle
              damaged-item partial refunds without return shipping, and split project milestones
              down to the exact cent.
            </p>

            <div className="flex flex-wrap items-center gap-3.5 pt-2">
              <button
                type="button"
                onClick={onLaunchDemo}
                disabled={demoLoading}
                className="btn-acid px-6 py-3.5 text-sm sm:text-base"
              >
                <Play className="w-4 h-4 fill-current" />
                {demoLoading ? 'Opening Guided Workspace...' : 'Try Interactive Guided Demo'}
              </button>

              <button
                type="button"
                onClick={() => onOpenAuth('login')}
                className="btn-cobalt px-6 py-3.5 text-sm sm:text-base"
              >
                <Lock className="w-4 h-4" />
                Sign In with Google or Email
              </button>
            </div>

            {/* Symmetrical 3-Pillar Trust Bar */}
            <div className="grid grid-cols-3 gap-3 pt-4 border-t border-[#192030]">
              <div className="p-3 bg-[#090B10] border border-[#192030]">
                <div className="text-xs font-mono text-[#CCFF00] uppercase">Before You Pay</div>
                <div className="text-sm font-semibold text-white mt-0.5">
                  Scam &amp; Subscription Guard
                </div>
              </div>
              <div className="p-3 bg-[#090B10] border border-[#192030]">
                <div className="text-xs font-mono text-[#CCFF00] uppercase">When Sales Fail</div>
                <div className="text-sm font-semibold text-white mt-0.5">
                  Smart Payment Recovery
                </div>
              </div>
              <div className="p-3 bg-[#090B10] border border-[#192030]">
                <div className="text-xs font-mono text-[#CCFF00] uppercase">Client Projects</div>
                <div className="text-sm font-semibold text-white mt-0.5">
                  Milestone PayPal Invoices
                </div>
              </div>
            </div>
          </div>

          {/* Right 5 Columns: Interactive Spatial UI Live Preview Card */}
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
              <div className="flex items-center justify-between pb-4 border-b border-[#1B2234]">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-[#CCFF00]" />
                  <span className="font-display font-bold text-sm uppercase tracking-wider text-white">
                    Live Payment Protection Preview
                  </span>
                </div>
                <span className="text-[11px] font-mono px-2 py-0.5 bg-[#CCFF00] text-[#050507] font-bold">
                  READY
                </span>
              </div>

              <div className="space-y-3.5 my-5">
                <div className="p-3.5 bg-[#0D121F] border border-[#0047FF]/60 flex items-center justify-between gap-3">
                  <div>
                    <div className="text-xs text-slate-400">1. Incoming Vendor Invoice</div>
                    <div className="text-sm font-semibold text-white">
                      Design Studio Retainer — $450.00
                    </div>
                  </div>
                  <span className="text-xs font-mono px-2 py-1 bg-[#CCFF00]/15 text-[#CCFF00] border border-[#CCFF00]/40">
                    Verified Safe
                  </span>
                </div>

                <div className="p-3.5 bg-[#0D121F] border border-[#1E293B] flex items-center justify-between gap-3">
                  <div>
                    <div className="text-xs text-slate-400">2. Declined Customer Order</div>
                    <div className="text-sm font-semibold text-white">
                      Card Expired — $189.00 Order
                    </div>
                  </div>
                  <span className="text-xs font-mono px-2 py-1 bg-[#0047FF]/25 text-white border border-[#0047FF]">
                    Backup Link Sent
                  </span>
                </div>

                <div className="p-3.5 bg-[#0D121F] border border-[#1E293B] flex items-center justify-between gap-3">
                  <div>
                    <div className="text-xs text-slate-400">3. Client Milestone Split</div>
                    <div className="text-sm font-semibold text-white">
                      Phase 1 Delivered — $1,250.00
                    </div>
                  </div>
                  <span className="text-xs font-mono px-2 py-1 bg-[#CCFF00]/15 text-[#CCFF00] border border-[#CCFF00]/40">
                    PayPal Invoiced
                  </span>
                </div>
              </div>

              <div className="pt-3 border-t border-[#1B2234] flex items-center justify-between text-xs text-slate-400">
                <span>Interactive 5-step tour included inside</span>
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

        {/* Symmetrical 3-Step "How It Works" Banner */}
        <section id="how-it-works" className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3 border-b border-[#192030] pb-4">
            <div>
              <div className="text-xs font-mono uppercase tracking-widest text-[#CCFF00]">
                Simple 3-Step Workflow
              </div>
              <h2 className="font-display text-2xl sm:text-3xl font-bold text-white mt-1">
                Know how to use AegisPay in 30 seconds
              </h2>
            </div>
            <p className="text-sm text-slate-400 max-w-md">
              Every tool follows the same clear pattern: review the situation, check your rules,
              and complete the action on PayPal.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {[
              {
                step: '01',
                title: 'Sign in & pick your task',
                desc: 'Choose whether you want to verify a bill before paying, recover a failed customer sale, or send a milestone invoice.',
              },
              {
                step: '02',
                title: 'Review the plain-English recommendation',
                desc: 'AegisPay checks your spending limits, refund rules, and payment safety before any money moves.',
              },
              {
                step: '03',
                title: 'Settle directly on PayPal',
                desc: 'Complete checkout, issue a partial refund, or send a shareable PayPal invoice link in a single click.',
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

        {/* Symmetrical 2x2 Feature Grid */}
        <section id="features" className="space-y-6">
          <div className="border-b border-[#192030] pb-4">
            <div className="text-xs font-mono uppercase tracking-widest text-[#CCFF00]">
              Core Product Suite
            </div>
            <h2 className="font-display text-2xl sm:text-3xl font-bold text-white mt-1">
              Four focused tools built around everyday PayPal moments
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div className="brutalist-card brutalist-card-lime p-6 space-y-3">
              <div className="w-10 h-10 bg-[#0047FF]/20 border border-[#0047FF] flex items-center justify-center text-[#CCFF00]">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <h3 className="font-display text-xl font-bold text-white">
                1. Pay Safely &amp; Clean Up Subscriptions
              </h3>
              <p className="text-sm text-slate-300 leading-relaxed">
                Paste any payment request or invoice before sending money to spot impersonation
                scams, cancel forgotten recurring subscriptions, and keep monthly spending within
                your safe budget.
              </p>
            </div>

            <div className="brutalist-card brutalist-card-lime p-6 space-y-3">
              <div className="w-10 h-10 bg-[#0047FF]/20 border border-[#0047FF] flex items-center justify-center text-[#CCFF00]">
                <RefreshCw className="w-5 h-5" />
              </div>
              <h3 className="font-display text-xl font-bold text-white">
                2. Recover Declined Customer Payments
              </h3>
              <p className="text-sm text-slate-300 leading-relaxed">
                When a customer checkout declines, understand why it failed in plain English and
                only trigger a PayPal retry or backup payment link when it is compliant and worth
                the fee.
              </p>
            </div>

            <div className="brutalist-card brutalist-card-lime p-6 space-y-3">
              <div className="w-10 h-10 bg-[#0047FF]/20 border border-[#0047FF] flex items-center justify-center text-[#CCFF00]">
                <CreditCard className="w-5 h-5" />
              </div>
              <h3 className="font-display text-xl font-bold text-white">
                3. Keep-the-Item Instant Partial Refunds
              </h3>
              <p className="text-sm text-slate-300 leading-relaxed">
                Turn costly damaged returns into instant partial PayPal refunds when an item has
                minor cosmetic wear—saving return shipping fees while keeping customers happy.
              </p>
            </div>

            <div className="brutalist-card brutalist-card-lime p-6 space-y-3">
              <div className="w-10 h-10 bg-[#0047FF]/20 border border-[#0047FF] flex items-center justify-center text-[#CCFF00]">
                <FileText className="w-5 h-5" />
              </div>
              <h3 className="font-display text-xl font-bold text-white">
                4. Milestone Invoicing &amp; Team Splits
              </h3>
              <p className="text-sm text-slate-300 leading-relaxed">
                Break client projects into clear PayPal invoices, split revenue across team members
                with zero rounding errors, and verify deliverables before releasing funds.
              </p>
            </div>
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
              Guided Interactive Onboarding Included
            </div>
            <h2 className="font-display text-2xl sm:text-3xl font-bold text-white">
              Ready to try AegisPay with step-by-step guidance?
            </h2>
            <p className="text-sm text-slate-300">
              Sign in with Google or Email, or open the interactive demo workspace with a built-in
              5-step walkthrough that shows you how every feature works.
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
          <span className="font-semibold text-slate-200">AegisPay</span>
          <span>— Safer Payments, Recovery &amp; Billing on PayPal</span>
        </div>
        <div className="font-mono text-[11px] text-slate-400">
          Encrypted Sessions • Isolated Workspaces • PayPal Sandbox Connected
        </div>
      </footer>
    </div>
  );
};
