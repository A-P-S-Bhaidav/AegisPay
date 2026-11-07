import React, { useEffect, useRef } from 'react';
import { ArrowLeft, ArrowRight, CheckCircle2, Compass, Sparkles, X } from 'lucide-react';
import type { WorkspaceSectionId } from '../webmcp';

export interface TourStepConfig {
  id: string;
  section: WorkspaceSectionId;
  badge: string;
  title: string;
  description: string;
  howToUse: string[];
  actionLabel?: string;
}

export const INTERACTIVE_TOUR_STEPS: TourStepConfig[] = [
  {
    id: 'welcome',
    section: 'overview',
    badge: 'Step 1 of 5 • Welcome',
    title: 'Your PayPal Safety & Revenue Workspace',
    description:
      'AegisPay organizes everything into four simple tabs at the top of your screen so you always know where to go.',
    howToUse: [
      'Overview shows your protected funds, active subscriptions, and recent PayPal links.',
      'Click any Quick-Start card on this screen to jump straight to a task.',
    ],
  },
  {
    id: 'pay-safely',
    section: 'protect',
    badge: 'Step 2 of 5 • Pay Safely',
    title: 'Check Any Invoice or Link Before You Pay',
    description:
      'Not sure if an email invoice or payment request is legitimate? Paste it here or click one of the sample bills before sending money.',
    howToUse: [
      'Pick a sample invoice or paste payment text into the checker.',
      'Click "Check Payment Safety" to get a clear Safe / Review / Unsafe decision.',
      'You can also cancel unused PayPal subscriptions right below.',
    ],
    actionLabel: 'Try Checking a Sample Invoice Now',
  },
  {
    id: 'recover-sales',
    section: 'merchant',
    badge: 'Step 3 of 5 • Recover & Retain',
    title: 'Win Back Declined Orders & Save Damaged Returns',
    description:
      'When a customer payment fails, AegisPay tells you why in plain English and sends a PayPal recovery link only when it is allowed and worth the fee.',
    howToUse: [
      'Choose a declined customer order and click "Find Best Recovery Step".',
      'Use "Instant Partial Refunds" next to it when an item arrives with a minor scratch so you save return shipping costs.',
    ],
    actionLabel: 'Run a Sample Failed-Payment Recovery',
  },
  {
    id: 'get-paid',
    section: 'getpaid',
    badge: 'Step 4 of 5 • Get Paid',
    title: 'Create Milestone Invoices & Split Team Payouts',
    description:
      'Doing client or agency work? Enter your project budget and team shares to generate exact-to-the-cent milestones and real PayPal invoices.',
    howToUse: [
      'Enter a project title, total budget, and client email.',
      'Click "Create Milestone Schedule" and then "Send PayPal Invoice" on Phase 1.',
    ],
    actionLabel: 'Create a Sample Milestone Plan',
  },
  {
    id: 'complete',
    section: 'overview',
    badge: 'Step 5 of 5 • Ready to Go',
    title: 'You Are Ready to Use AegisPay',
    description:
      'Every PayPal order or invoice you create includes a direct "Open in PayPal" link so you can inspect or complete it live.',
    howToUse: [
      'Need this walkthrough again? Click the "Guided Tour" button in the top bar anytime.',
      'Developers & evaluators can also open the separate "Verification Lab" from the top-right menu.',
    ],
  },
];

interface InteractiveTourProps {
  open: boolean;
  stepIndex: number;
  busyAction: boolean;
  onChangeStep: (nextIndex: number) => void;
  onRunSampleAction: (stepId: string) => Promise<void>;
  onFinishOrSkip: () => void;
}

export const InteractiveTour: React.FC<InteractiveTourProps> = ({
  open,
  stepIndex,
  busyAction,
  onChangeStep,
  onRunSampleAction,
  onFinishOrSkip,
}) => {
  const primaryBtnRef = useRef<HTMLButtonElement | null>(null);
  const step = INTERACTIVE_TOUR_STEPS[stepIndex] || INTERACTIVE_TOUR_STEPS[0];
  const isLast = stepIndex >= INTERACTIVE_TOUR_STEPS.length - 1;

  // Accessible focus management on step changes (per modern-web-guidance persistent-app-tours)
  useEffect(() => {
    if (open) {
      const id = window.requestAnimationFrame(() => {
        primaryBtnRef.current?.focus();
      });
      return () => window.cancelAnimationFrame(id);
    }
  }, [open, stepIndex]);

  // Escape key dismissal
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onFinishOrSkip();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onFinishOrSkip]);

  if (!open) return null;

  return (
    <div
      className="fixed bottom-4 right-4 left-4 sm:left-auto sm:w-[430px] z-50 animate-view-enter"
      role="dialog"
      aria-modal="false"
      aria-labelledby="aegis-tour-heading"
      aria-describedby="aegis-tour-desc"
    >
      <div className="glass-brutal-panel corner-ticks p-5 border-2 border-[#CCFF00] shadow-[0_24px_60px_rgba(0,0,0,0.9)] bg-[#070A12]/95">
        {/* Header & Progress */}
        <div className="flex items-center justify-between gap-2 pb-3 border-b border-[#1E293B]">
          <div className="inline-flex items-center gap-2 text-xs font-mono uppercase text-[#CCFF00]">
            <Compass className="w-4 h-4" />
            {step.badge}
          </div>
          <button
            type="button"
            onClick={onFinishOrSkip}
            aria-label="Close guided tour"
            className="text-slate-400 hover:text-white p-1"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Progress Bar */}
        <div className="grid grid-cols-5 gap-1.5 my-3" aria-hidden="true">
          {INTERACTIVE_TOUR_STEPS.map((s, idx) => (
            <div
              key={s.id}
              className={`h-1.5 transition-colors ${
                idx <= stepIndex ? 'bg-[#CCFF00]' : 'bg-[#1B2234]'
              }`}
            />
          ))}
        </div>

        {/* Body */}
        <div className="space-y-3">
          <h2 id="aegis-tour-heading" className="font-display text-lg font-bold text-white">
            {step.title}
          </h2>
          <p id="aegis-tour-desc" className="text-xs sm:text-sm text-slate-300 leading-relaxed">
            {step.description}
          </p>

          <ul className="space-y-1.5 bg-[#0B101D] border border-[#1B2234] p-3 text-xs text-slate-200">
            {step.howToUse.map((tip, i) => (
              <li key={i} className="flex items-start gap-2">
                <span className="text-[#CCFF00] font-mono font-bold mt-0.5">{i + 1}.</span>
                <span>{tip}</span>
              </li>
            ))}
          </ul>

          {step.actionLabel && (
            <button
              type="button"
              disabled={busyAction}
              onClick={() => onRunSampleAction(step.id)}
              className="btn-cobalt w-full py-2 text-xs"
            >
              <Sparkles className="w-3.5 h-3.5" />
              {busyAction ? 'Running Live Example...' : step.actionLabel}
            </button>
          )}
        </div>

        {/* Footer Controls */}
        <div className="flex items-center justify-between gap-2 pt-4 mt-4 border-t border-[#1E293B]">
          <button
            type="button"
            onClick={onFinishOrSkip}
            className="text-xs text-slate-400 hover:text-white underline underline-offset-4"
          >
            Skip Tour
          </button>

          <div className="flex items-center gap-2">
            {stepIndex > 0 && (
              <button
                type="button"
                onClick={() => onChangeStep(stepIndex - 1)}
                className="btn-ghost-brutal px-3 py-1.5 text-xs"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                Back
              </button>
            )}

            <button
              ref={primaryBtnRef}
              type="button"
              onClick={() => {
                if (isLast) {
                  onFinishOrSkip();
                } else {
                  onChangeStep(stepIndex + 1);
                }
              }}
              className="btn-acid px-4 py-1.5 text-xs"
            >
              {isLast ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Finish Tour
                </>
              ) : (
                <>
                  Next Step
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
