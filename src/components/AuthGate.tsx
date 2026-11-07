import React, { useState } from 'react';
import {
  ArrowLeft,
  ArrowRight,
  Building2,
  Eye,
  EyeOff,
  Lock,
  Mail,
  Play,
  ShieldCheck,
  User,
} from 'lucide-react';
import { AegisBrandMark, apiFetch } from '../api';

interface AuthGateProps {
  initialMode?: 'login' | 'register';
  authErrorBanner?: string;
  onAuthenticated: (meta?: { isNewAccount?: boolean }) => Promise<void>;
  onBackToLanding: () => void;
  onLaunchDemo: () => Promise<void>;
}

export const AuthGate: React.FC<AuthGateProps> = ({
  initialMode = 'login',
  authErrorBanner,
  onAuthenticated,
  onBackToLanding,
  onLaunchDemo,
}) => {
  const [mode, setMode] = useState<'login' | 'register'>(initialMode);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [fullName, setFullName] = useState('');
  const [organization, setOrganization] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(authErrorBanner || '');

  const handleGoogleSignIn = async () => {
    setError('');
    setLoading(true);
    try {
      const data = await apiFetch<{
        liveGoogleOAuthConfigured: boolean;
        authUrl?: string;
        message?: string;
      }>('/api/auth/google/url');
      if (data.liveGoogleOAuthConfigured && data.authUrl) {
        window.location.href = data.authUrl;
        return;
      }
      setError(
        data.message ||
          'Google Sign-In is not configured on this local server. Please sign in with Email or open the Guided Demo Workspace below.'
      );
    } catch (err) {
      setError((err as Error).message || 'Could not start Google Sign-In.');
    } finally {
      setLoading(false);
    }
  };

  const handleEmailSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      if (mode === 'register') {
        try {
          const regRes = await apiFetch<{ isNewAccount?: boolean }>('/api/auth/register', {
            method: 'POST',
            body: JSON.stringify({ email, password, fullName, organization }),
          });
          await onAuthenticated({ isNewAccount: Boolean(regRes.isNewAccount) });
          return;
        } catch (regErr: any) {
          // If an email+password account already exists, seamlessly try signing in with the entered credentials
          if (regErr?.status === 409 && regErr?.data?.code === 'EMAIL_PASSWORD_ALREADY_REGISTERED') {
            try {
              await apiFetch('/api/auth/login', {
                method: 'POST',
                body: JSON.stringify({ email, password }),
              });
              await onAuthenticated({ isNewAccount: false });
              return;
            } catch {
              setMode('login');
              setError(
                'Welcome back — an account with this email already exists. Enter your existing password to sign in, or click Continue with Google.'
              );
              return;
            }
          }
          throw regErr;
        }
      } else {
        await apiFetch('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify({ email, password }),
        });
        await onAuthenticated({ isNewAccount: false });
      }
    } catch (err) {
      setError((err as Error).message || 'Authentication failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleOperatorQuickLogin = async () => {
    setError('');
    setEmail('operator@aegispay.io');
    setPassword('AegisPay2026!');
    setLoading(true);
    try {
      await apiFetch('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          email: 'operator@aegispay.io',
          password: 'AegisPay2026!',
        }),
      });
      await onAuthenticated({ isNewAccount: false });
    } catch (err) {
      setError((err as Error).message || 'Quick operator login failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickDemo = async () => {
    setError('');
    setLoading(true);
    try {
      await onLaunchDemo();
    } catch (err) {
      setError((err as Error).message || 'Could not launch demo workspace.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full bg-midnight-grid text-slate-100 flex flex-col justify-between px-4 sm:px-8 py-8">
      <div className="w-full max-w-5xl mx-auto flex items-center justify-between">
        <button
          type="button"
          onClick={onBackToLanding}
          className="btn-ghost-brutal px-3.5 py-2 text-xs sm:text-sm"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Home
        </button>

        <div className="flex items-center gap-2.5">
          <AegisBrandMark size={28} />
          <span className="font-display font-bold text-white">AegisPay</span>
        </div>
      </div>

      <div className="w-full max-w-5xl mx-auto my-8 grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Left 5 Columns: Clear Context & Guided Demo Option */}
        <div className="lg:col-span-5 glass-brutal-panel corner-ticks p-6 sm:p-8 flex flex-col justify-between gap-6">
          <div className="space-y-4">
            <div className="inline-flex items-center gap-2 text-xs font-mono uppercase text-[#CCFF00] px-2.5 py-1 bg-[#0047FF]/20 border border-[#0047FF]/60">
              <ShieldCheck className="w-4 h-4 shrink-0" />
              Private Account Workspace
            </div>
            <h1 className="font-display text-2xl sm:text-3xl font-bold text-white leading-tight">
              Sign in to manage your PayPal safety &amp; billing
            </h1>
            <p className="text-sm text-slate-300 leading-relaxed">
              Use Google or Email interchangeably with the same address—your isolated workspace,
              invoice checks, subscription limits, and milestone plans stay synced.
            </p>
          </div>

          <div className="p-4 bg-[#070A12] border border-[#1E293B] space-y-3">
            <div className="text-xs font-mono uppercase text-[#CCFF00]">
              Want to explore right away?
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Open an isolated guest workspace pre-loaded with sample orders and an optional
              guided walkthrough.
            </p>
            <button
              type="button"
              onClick={handleQuickDemo}
              disabled={loading}
              className="btn-acid w-full py-2.5 text-xs sm:text-sm"
            >
              <Play className="w-4 h-4 fill-current shrink-0" />
              Launch Guided Demo Workspace
            </button>
          </div>
        </div>

        {/* Right 7 Columns: Google OAuth + Email Sign In / Register */}
        <div className="lg:col-span-7 glass-brutal-panel p-6 sm:p-8 space-y-5">
          <div className="grid grid-cols-2 gap-2 p-1 bg-[#07090F] border border-[#1B2234]">
            <button
              type="button"
              onClick={() => {
                setMode('login');
                setError('');
              }}
              className={`py-2 text-xs sm:text-sm font-display font-bold transition-colors ${
                mode === 'login'
                  ? 'bg-[#0047FF] text-white'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => {
                setMode('register');
                setError('');
              }}
              className={`py-2 text-xs sm:text-sm font-display font-bold transition-colors ${
                mode === 'register'
                  ? 'bg-[#0047FF] text-white'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Create Account
            </button>
          </div>

          {error && (
            <div
              role="alert"
              aria-live="polite"
              className="p-3.5 bg-red-950/50 border border-red-500/60 text-xs text-red-200 leading-relaxed space-y-2"
            >
              <div>{error}</div>
              {mode === 'login' && email.includes('@') && password.length >= 8 && (
                <button
                  type="button"
                  disabled={loading}
                  onClick={async () => {
                    setError('');
                    setLoading(true);
                    try {
                      const regRes = await apiFetch<{ isNewAccount?: boolean }>('/api/auth/register', {
                        method: 'POST',
                        body: JSON.stringify({
                          email,
                          password,
                          fullName: fullName || email.split('@')[0],
                          organization: organization || 'PayPal Workspace',
                        }),
                      });
                      await onAuthenticated({ isNewAccount: Boolean(regRes.isNewAccount) });
                    } catch (regErr) {
                      setError((regErr as Error).message || 'Could not create account.');
                    } finally {
                      setLoading(false);
                    }
                  }}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1.5 bg-[#0047FF] text-white font-mono text-[11px] uppercase hover:bg-[#195BFF] transition-colors"
                >
                  <span>New account? Create Account with {email} &rarr;</span>
                </button>
              )}
            </div>
          )}

          {/* Google OAuth Button */}
          <button
            type="button"
            onClick={handleGoogleSignIn}
            disabled={loading}
            className="w-full py-3 px-4 bg-white text-[#050507] font-display font-bold text-sm border-2 border-white hover:bg-slate-100 transition-all flex items-center justify-center gap-3 shadow-[3px_3px_0px_#0047FF]"
          >
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              aria-hidden="true"
              className="shrink-0"
            >
              <path
                fill="#4285F4"
                d="M23.49 12.27c0-.79-.07-1.54-.2-2.27H12v4.51h6.47c-.29 1.48-1.14 2.73-2.4 3.58v3h3.86c2.26-2.09 3.56-5.17 3.56-8.82z"
              />
              <path
                fill="#34A853"
                d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.86-3c-1.08.72-2.45 1.16-4.07 1.16-3.13 0-5.78-2.11-6.73-4.96H1.29v3.09C3.26 21.3 7.31 24 12 24z"
              />
              <path
                fill="#FBBC05"
                d="M5.27 14.29c-.25-.72-.38-1.49-.38-2.29s.13-1.57.38-2.29V6.62H1.29C.47 8.24 0 10.06 0 12s.47 3.76 1.29 5.38l3.98-3.09z"
              />
              <path
                fill="#EA4335"
                d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.31 0 3.26 2.7 1.29 6.62l3.98 3.09c.95-2.85 3.6-4.96 6.73-4.96z"
              />
            </svg>
            <span>Continue with Google</span>
          </button>

          <div className="relative flex items-center py-1">
            <div className="flex-grow border-t border-[#1B2234]" />
            <span className="px-3 text-[11px] font-mono uppercase text-slate-400">
              Or continue with email
            </span>
            <div className="flex-grow border-t border-[#1B2234]" />
          </div>

          <form onSubmit={handleEmailSubmit} method="post" className="space-y-4">
            {mode === 'register' && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                <div>
                  <label
                    htmlFor="auth-full-name"
                    className="block text-xs font-medium text-slate-300 mb-1.5"
                  >
                    Full Name
                  </label>
                  <div className="auth-input-shell">
                    <span className="auth-input-icon" aria-hidden="true">
                      <User className="w-4 h-4 shrink-0" />
                    </span>
                    <input
                      id="auth-full-name"
                      name="name"
                      type="text"
                      required
                      autoComplete="name"
                      value={fullName}
                      onChange={(e) => {
                        setFullName(e.target.value);
                        if (error) setError('');
                      }}
                      placeholder="Alex Morgan"
                      className="auth-input-control"
                    />
                  </div>
                </div>
                <div>
                  <label
                    htmlFor="auth-organization"
                    className="block text-xs font-medium text-slate-300 mb-1.5"
                  >
                    Business or Team Name
                  </label>
                  <div className="auth-input-shell">
                    <span className="auth-input-icon" aria-hidden="true">
                      <Building2 className="w-4 h-4 shrink-0" />
                    </span>
                    <input
                      id="auth-organization"
                      name="organization"
                      type="text"
                      autoComplete="organization"
                      value={organization}
                      onChange={(e) => {
                        setOrganization(e.target.value);
                        if (error) setError('');
                      }}
                      placeholder="Morgan Design Studio"
                      className="auth-input-control"
                    />
                  </div>
                </div>
              </div>
            )}

            <div>
              <label
                htmlFor="auth-email"
                className="block text-xs font-medium text-slate-300 mb-1.5"
              >
                Email Address
              </label>
              <div className="auth-input-shell">
                <span className="auth-input-icon" aria-hidden="true">
                  <Mail className="w-4 h-4 shrink-0" />
                </span>
                <input
                  id="auth-email"
                  name="email"
                  type="email"
                  required
                  autoComplete="username"
                  spellCheck={false}
                  enterKeyHint="next"
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    if (error) setError('');
                  }}
                  placeholder="you@company.com"
                  className="auth-input-control"
                />
              </div>
            </div>

            <div>
              <label
                htmlFor="auth-password"
                className="block text-xs font-medium text-slate-300 mb-1.5"
              >
                Password {mode === 'register' && '(minimum 8 characters)'}
              </label>
              <div className="auth-input-shell">
                <span className="auth-input-icon" aria-hidden="true">
                  <Lock className="w-4 h-4 shrink-0" />
                </span>
                <input
                  id="auth-password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  required
                  minLength={8}
                  autoComplete={mode === 'register' ? 'new-password' : 'current-password'}
                  enterKeyHint="done"
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (error) setError('');
                  }}
                  placeholder={
                    mode === 'register' ? 'Create an 8+ character password' : 'Enter your password'
                  }
                  className="auth-input-control"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  aria-pressed={showPassword}
                  className="auth-input-toggle"
                >
                  {showPassword ? (
                    <EyeOff className="w-4 h-4 shrink-0" />
                  ) : (
                    <Eye className="w-4 h-4 shrink-0" />
                  )}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-cobalt w-full py-3 text-sm mt-2"
            >
              <span>
                {loading
                  ? 'Signing In...'
                  : mode === 'register'
                    ? 'Create Account & Open Workspace'
                    : 'Sign In to Workspace'}
              </span>
              <ArrowRight className="w-4 h-4 shrink-0" />
            </button>

            <div className="pt-1 flex items-center justify-between gap-2 text-[11px] text-slate-400">
              <span>Testing with default sandbox operator?</span>
              <button
                type="button"
                disabled={loading}
                onClick={handleOperatorQuickLogin}
                className="font-mono text-[#CCFF00] hover:underline"
              >
                1-Click Sign In (operator@aegispay.io)
              </button>
            </div>
          </form>
        </div>
      </div>

      <div className="text-center text-xs text-slate-500 font-mono">
        Protected by encrypted HttpOnly session cookies &amp; per-account workspace isolation.
      </div>
    </div>
  );
};
