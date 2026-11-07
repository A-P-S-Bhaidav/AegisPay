import React, { Suspense, useCallback, useEffect, useState } from 'react';
import {
  Compass,
  Cpu,
  FileText,
  FlaskConical,
  LayoutGrid,
  LogOut,
  RefreshCw,
  ShieldCheck,
} from 'lucide-react';
import { AegisBrandMark, apiFetch, type WorkspaceState } from './api';
import { AgenticCommandHub } from './components/AgenticCommandHub';
import { AuthGate } from './components/AuthGate';
import { GetPaidView } from './components/GetPaidView';
import { INTERACTIVE_TOUR_STEPS, InteractiveTour } from './components/InteractiveTour';
import { LandingPage } from './components/LandingPage';
import { MerchantRecoveryView } from './components/MerchantRecoveryView';
import { PaySafelyView } from './components/PaySafelyView';
import { WorkspaceOverview } from './components/WorkspaceOverview';
import { registerAegisWebMcpTools, type WorkspaceSectionId } from './webmcp';

const DiagnosticsLab = React.lazy(() => import('./components/DiagnosticsLab'));

export function App() {
  const [booting, setBooting] = useState(true);
  const [screen, setScreen] = useState<'landing' | 'auth' | 'workspace'>('landing');
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [authErrorBanner, setAuthErrorBanner] = useState('');
  const [demoLoading, setDemoLoading] = useState(false);
  const [practiceEnabled, setPracticeEnabled] = useState(false);
  const [appError, setAppError] = useState('');
  const [tourFeedback, setTourFeedback] = useState('');

  const [state, setState] = useState<WorkspaceState | null>(null);
  const [section, setSection] = useState<WorkspaceSectionId>('overview');
  const [inVerificationLab, setInVerificationLab] = useState(false);
  const [mcpHubOpen, setMcpHubOpen] = useState(false);
  const [mcpHubTab, setMcpHubTab] = useState<'mcp' | 'extension'>('mcp');

  // Interactive Onboarding Tour state
  const [tourOpen, setTourOpen] = useState(false);
  const [tourStep, setTourStep] = useState(0);
  const [tourBusy, setTourBusy] = useState(false);

  const loadWorkspaceState = useCallback(async () => {
    const ws = await apiFetch<WorkspaceState>('/api/state');
    setState(ws);
    return ws;
  }, []);

  const hasSeenTourLocally = useCallback((operatorId?: string, email?: string) => {
    try {
      if (operatorId && localStorage.getItem(`aegispay_tour_seen_${operatorId}`) === '1') {
        return true;
      }
      if (email && localStorage.getItem(`aegispay_tour_seen_${email.toLowerCase()}`) === '1') {
        return true;
      }
    } catch {
      // Ignore storage access restrictions
    }
    return false;
  }, []);

  const markTourSeen = useCallback((operatorId?: string, email?: string) => {
    try {
      if (operatorId) localStorage.setItem(`aegispay_tour_seen_${operatorId}`, '1');
      if (email) localStorage.setItem(`aegispay_tour_seen_${email.toLowerCase()}`, '1');
    } catch {
      // Ignore storage access restrictions
    }
    void apiFetch('/api/workspace/tutorial', {
      method: 'POST',
      body: JSON.stringify({ completed: true }),
    }).catch(() => {});
  }, []);

  // Initial session check (strictly HttpOnly cookie — zero localStorage tokens)
  useEffect(() => {
    void apiFetch<{ demoSandboxEnabled: boolean }>('/api/health')
      .then((health) => setPracticeEnabled(health.demoSandboxEnabled))
      .catch(() => {});
    const params = new URLSearchParams(window.location.search);
    const errParam = params.get('auth_error');
    const readyParam = params.get('auth_ready');
    const isFirstOAuthSignup = params.get('first_signup') === '1';

    if (errParam || readyParam || isFirstOAuthSignup) {
      window.history.replaceState({}, '', window.location.pathname);
    }
    if (errParam) {
      setAuthErrorBanner('Google Sign-In could not be verified. Please try again or use Email.');
      setScreen('auth');
    }

    (async () => {
      try {
        await apiFetch('/api/auth/me');
        const ws = await loadWorkspaceState();
        setScreen('workspace');
        // Strictly show tutorial ONLY on first-time OAuth sign-up, never on returning logins or reloads
        if (
          isFirstOAuthSignup &&
          !ws.workspace.tutorialCompleted &&
          !hasSeenTourLocally(ws.operator?.id, ws.operator?.email)
        ) {
          setTourStep(0);
          setTourOpen(true);
        }
      } catch {
        // Unauthenticated visitor stays on landing or auth screen
      } finally {
        setBooting(false);
      }
    })();
  }, [hasSeenTourLocally, loadWorkspaceState, markTourSeen]);

  useEffect(() => {
    if (screen !== 'workspace') return;
    const expireSession = () => {
      setState(null);
      setTourOpen(false);
      setMcpHubOpen(false);
      setAuthErrorBanner('Your session expired. Sign in again to continue.');
      setScreen('auth');
    };
    window.addEventListener('aegispay:session-expired', expireSession);
    return () => window.removeEventListener('aegispay:session-expired', expireSession);
  }, [screen]);

  // Register progressive Chromium WebMCP tools when authenticated
  useEffect(() => {
    if (screen !== 'workspace') return;
    return registerAegisWebMcpTools(
      (target) => {
        if (target === 'diagnostics') {
          setInVerificationLab(true);
        } else {
          setInVerificationLab(false);
          setSection(target);
        }
      },
      () => apiFetch('/api/security/fuzz', { method: 'POST', body: JSON.stringify({ iterations: 1000 }) })
    );
  }, [screen]);

  const handleAuthenticated = async (meta?: { isNewAccount?: boolean }) => {
    const ws = await loadWorkspaceState();
    setInVerificationLab(false);
    setSection('overview');
    setScreen('workspace');
    // Strictly show tutorial ONLY on first sign-up (isNewAccount === true), never on returning logins
    if (
      meta?.isNewAccount &&
      !ws.workspace.tutorialCompleted &&
      !hasSeenTourLocally(ws.operator?.id, ws.operator?.email)
    ) {
      setTourStep(0);
      setTourOpen(true);
    }
  };

  const handleLaunchDemo = async () => {
    setDemoLoading(true);
    setAppError('');
    try {
      const demoAuth = await apiFetch<{ isNewAccount?: boolean }>('/api/auth/demo', {
        method: 'POST',
      });
      const ws = await loadWorkspaceState();
      setInVerificationLab(false);
      setSection('overview');
      setScreen('workspace');
      // Show guided tour only on the very first demo visit (never annoyingly repeat)
      if (
        demoAuth.isNewAccount !== false &&
        !ws.workspace.tutorialCompleted &&
        !hasSeenTourLocally(ws.operator?.id, ws.operator?.email)
      ) {
        setTourStep(0);
        setTourOpen(true);
        }
    } catch (err) {
      setAppError((err as Error).message || 'Could not open the demo. Please try again.');
      throw err;
    } finally {
      setDemoLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await apiFetch('/api/auth/logout', { method: 'POST' });
    } catch {
      // Ignore logout network error
    }
    setState(null);
    setTourOpen(false);
    setInVerificationLab(false);
    setScreen('landing');
  };

  const handleChangeTourStep = (nextIndex: number) => {
    const clamped = Math.max(0, Math.min(INTERACTIVE_TOUR_STEPS.length - 1, nextIndex));
    setTourStep(clamped);
    setInVerificationLab(false);
    setSection(INTERACTIVE_TOUR_STEPS[clamped].section);
  };

  const handleFinishOrSkipTour = async () => {
    setTourOpen(false);
    markTourSeen(state?.operator?.id, state?.operator?.email);
  };

  const handleRunTourSampleAction = async (stepId: string) => {
    setTourBusy(true);
    setTourFeedback('');
    try {
      if (stepId === 'pay-safely') {
        await apiFetch('/api/scamshield/review', {
          method: 'POST',
          body: JSON.stringify({
            rawText: 'Invoice #1048 from Nordic Design Studio for Brand Icon Pack: $45.00 USD',
            claimedAmountCents: 4500,
            currency: 'USD',
            payeeIdentifier: 'billing@nordic-design.io',
          }),
        });
      } else if (stepId === 'recover-sales') {
        await apiFetch('/api/payrevive/recover', {
          method: 'POST',
          body: JSON.stringify({ presetId: 'PAYDAY_LIQUIDITY', executeLivePayPal: true }),
        });
      } else if (stepId === 'get-paid') {
        await apiFetch('/api/paystream/create-plan', {
          method: 'POST',
          body: JSON.stringify({
            projectTitle: 'Guided Demo Client Project',
            clientEmail: 'client-demo@personal.example.com',
            totalBudgetCents: 185000,
          }),
        });
      }
      await loadWorkspaceState();
      setTourFeedback('Sample completed. The workspace has been updated.');
    } catch (err) {
      setTourFeedback((err as Error).message || 'The sample could not complete. Please try again.');
    } finally {
      setTourBusy(false);
    }
  };

  if (booting) {
    return (
      <div className="min-h-screen w-full bg-midnight-grid flex items-center justify-center text-slate-300 font-mono text-xs">
        <div className="flex items-center gap-3">
          <AegisBrandMark size={28} />
          <span>Loading AegisPay Workspace...</span>
        </div>
      </div>
    );
  }

  if (screen === 'landing') {
    return (
      <LandingPage
        onOpenAuth={(mode = 'login') => {
          setAuthMode(mode);
          setAuthErrorBanner('');
          setScreen('auth');
        }}
        onLaunchDemo={practiceEnabled ? () => handleLaunchDemo().catch(() => {}) : undefined}
        error={appError}
        demoLoading={demoLoading}
      />
    );
  }

  if (screen === 'auth' || !state) {
    return (
      <AuthGate
        initialMode={authMode}
        authErrorBanner={authErrorBanner}
        onAuthenticated={handleAuthenticated}
        onBackToLanding={() => setScreen('landing')}
        onLaunchDemo={practiceEnabled ? handleLaunchDemo : undefined}
      />
    );
  }

  const activeTourTarget = tourOpen ? INTERACTIVE_TOUR_STEPS[tourStep]?.section : null;

  const navItems: Array<{
    id: WorkspaceSectionId;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
  }> = [
    { id: 'overview', label: 'Overview', icon: LayoutGrid },
    { id: 'protect', label: 'Pay Safely', icon: ShieldCheck },
    { id: 'merchant', label: 'Recover & Retain', icon: RefreshCw },
    { id: 'getpaid', label: 'Get Paid', icon: FileText },
  ];

  return (
    <div className="min-h-screen w-full bg-dashboard-spatial text-slate-100 flex flex-col">
      <a href="#workspace-main" className="skip-link">Skip to workspace content</a>
      {/* Sticky Full-Width Symmetrical Command Bar */}
      <header className="glass-command-bar sticky top-0 z-40 w-full">
        <div className="w-full px-4 sm:px-8 lg:px-12 py-3 flex flex-wrap items-center justify-between gap-3">
          {/* Brand */}
          <button
            type="button"
            onClick={() => {
              setInVerificationLab(false);
              setSection('overview');
            }}
            className="flex items-center gap-2.5 text-left"
          >
            <AegisBrandMark size={30} />
            <div>
              <div className="font-display font-bold text-base text-white leading-none">
                AegisPay
              </div>
              <div className="text-[10px] font-mono text-[#CCFF00] mt-0.5">
                {state.operator?.organization || 'PayPal Workspace'}
              </div>
            </div>
          </button>

          {/* Center Symmetrical Customer Navigation Tabs */}
          <nav
            aria-label="Workspace Sections"
            className="order-3 lg:order-2 w-full lg:w-auto grid grid-cols-2 sm:grid-cols-4 gap-1.5"
          >
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = !inVerificationLab && section === item.id;
              const isTourTarget = !inVerificationLab && activeTourTarget === item.id;
              return (
                <button
                  aria-current={isActive ? 'page' : undefined}
                  key={item.id}
                  type="button"
                  onClick={() => {
                    setInVerificationLab(false);
                    setSection(item.id);
                  }}
                  className={`px-3.5 py-2 text-xs sm:text-sm font-display font-bold border flex items-center justify-center gap-2 transition-all ${
                    isActive
                      ? 'bg-[#0047FF] border-[#CCFF00] text-white shadow-[2px_2px_0px_#CCFF00]'
                      : 'bg-[#090C14]/90 border-[#1E293B] text-slate-300 hover:border-[#0047FF] hover:text-white'
                  } ${isTourTarget ? 'tour-spotlight-target' : ''}`}
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Right Actions: MCP & Extension Hub + Guided Tour + Separate Verification Lab + Sign Out */}
          <div className="order-2 lg:order-3 flex items-center gap-2">
            <button
              type="button"
              onClick={() => {
                setInVerificationLab(false);
                setMcpHubTab('mcp');
                setMcpHubOpen(true);
              }}
              className="btn-ghost-brutal px-3 py-1.5 text-xs border-[#CCFF00]/60 text-[#CCFF00]"
              aria-label="Open MCP and extension hub"
              title="Open Live MCP Server & Chrome Extension Command Hub"
            >
              <Cpu className="w-3.5 h-3.5 text-[#CCFF00]" />
              <span className="hidden sm:inline">MCP &amp; Extension</span>
            </button>

            <button
              type="button"
              onClick={() => {
                setInVerificationLab(false);
                setTourStep(0);
                setSection('overview');
                setTourOpen(true);
              }}
              className="btn-ghost-brutal px-3 py-1.5 text-xs"
              aria-label="Launch guided tour"
              title="Launch step-by-step interactive walkthrough"
            >
              <Compass className="w-3.5 h-3.5 text-[#CCFF00]" />
              <span className="hidden sm:inline">Guided Tour</span>
            </button>

            <button
              type="button"
              onClick={() => setInVerificationLab((v) => !v)}
              className={`px-3 py-1.5 text-xs font-mono border flex items-center gap-1.5 transition-colors ${
                inVerificationLab
                  ? 'bg-[#CCFF00] text-[#050507] border-[#CCFF00] font-bold'
                  : 'bg-[#090C14] text-slate-300 border-[#243049] hover:border-[#CCFF00] hover:text-[#CCFF00]'
              }`}
              aria-label={inVerificationLab ? 'Exit verification lab' : 'Open verification lab'}
              aria-pressed={inVerificationLab}
              title="Open isolated engineering & verification lab"
            >
              <FlaskConical className="w-3.5 h-3.5" />
              <span className="hidden md:inline">
                {inVerificationLab ? 'Exit Lab' : 'Verification Lab'}
              </span>
            </button>

            <button
              type="button"
              onClick={handleLogout}
              className="btn-ghost-brutal px-2.5 py-1.5 text-xs"
              aria-label="Sign out"
              title={`Sign out (${state.operator?.email})`}
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </header>

      <div role="status" className="px-4 sm:px-8 lg:px-12 pt-3 text-xs text-slate-300">
        {state.operator?.role === 'DEMO_OPERATOR' ? 'Guest demo with seeded examples. ' : 'Private account workspace. '}
        {state.system.paypal.hasLiveSandboxCredentials ? 'PayPal sandbox API configured; test funds only.' : 'PayPal simulated mode; no funds move.'}
        {' '}{state.system.gemini.hasLiveGeminiKey || state.system.gemini.hasLiveGroqKey ? 'AI provider configured.' : 'AI uses local fallback analysis.'}
      </div>
      {appError && <div role="alert" className="mx-4 mt-3 border border-red-500/60 bg-red-950/40 p-3 text-sm text-red-200">{appError}</div>}
      {/* Main Full-Width Responsive Content Stage */}
      <main id="workspace-main" tabIndex={-1} className="flex-1 w-full px-4 sm:px-8 lg:px-12 py-6 sm:py-8">
        {inVerificationLab ? (
          <Suspense
            fallback={
              <div className="glass-brutal-panel p-10 text-center font-mono text-xs text-[#CCFF00]">
                Loading Isolated Verification &amp; Benchmark Lab...
              </div>
            }
          >
            <DiagnosticsLab
              state={state}
              onRefresh={async () => {
                await loadWorkspaceState();
              }}
              onBackToProduct={() => setInVerificationLab(false)}
            />
          </Suspense>
        ) : (
          <>
            <AgenticCommandHub
              onNavigate={(next) => setSection(next)}
              onRefresh={async () => {
                await loadWorkspaceState();
              }}
              externalHubOpen={mcpHubOpen}
              externalHubTab={mcpHubTab}
              onCloseExternalHub={() => setMcpHubOpen(false)}
            />
            {section === 'overview' && (
              <WorkspaceOverview
                state={state}
                onNavigate={(next) => setSection(next)}
                onStartTour={() => {
                  setTourStep(0);
                  setTourOpen(true);
                }}
                onRefresh={async () => {
                  await loadWorkspaceState();
                }}
                onOpenMcpExtensionHub={(tab) => {
                  setMcpHubTab(tab);
                  setMcpHubOpen(true);
                }}
              />
            )}
            {section === 'protect' && (
              <PaySafelyView
                state={state}
                onRefresh={async () => {
                  await loadWorkspaceState();
                }}
              />
            )}
            {section === 'merchant' && (
              <MerchantRecoveryView
                state={state}
                onRefresh={async () => {
                  await loadWorkspaceState();
                }}
              />
            )}
            {section === 'getpaid' && (
              <GetPaidView
                state={state}
                onRefresh={async () => {
                  await loadWorkspaceState();
                }}
              />
            )}
          </>
        )}
      </main>

      {/* Persistent Interactive Onboarding Tour */}
      <InteractiveTour
        open={tourOpen && !inVerificationLab}
        stepIndex={tourStep}
        busyAction={tourBusy}
        actionFeedback={tourFeedback}
        onChangeStep={handleChangeTourStep}
        onRunSampleAction={handleRunTourSampleAction}
        onFinishOrSkip={handleFinishOrSkipTour}
      />
    </div>
  );
}

export default App;
