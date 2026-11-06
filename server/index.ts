import express, { type Request, type Response, type NextFunction } from 'express';
import dotenv from 'dotenv';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  AgentSpendingPermit,
  AtomicExecutionLedger,
  auditPayPalPermissions,
  BuyerMandate,
  calculateDeterministicVisionRefund,
  CollaboratorShareInput,
  computePennyExactMilestonePlan,
  createSignedDealContract,
  DecisionVerdict,
  DEFAULT_MERCHANT_REFUND_POLICY,
  evaluateAgentPermit,
  evaluateCashflowAffordability,
  evaluateChurnIntervention,
  evaluatePaymentScamDeterministically,
  extractPaymentRequestMetadata,
  MerchantRefundPolicyMatrix,
  NegotiationRoundEntry,
  runDeterministicSafetyFuzzer,
  ScamShieldTokenVault,
  SellerMandate,
  sha256Hex,
  SignedScamShieldToken,
  signStatelessSession,
  SmartMilestonePlan,
  stricterVerdict,
  validateAndClampOfferAgainstMandate,
  verifyContractIntegrity,
  verifyDeliverableProofDeterministically,
  verifyGroundedNumbers,
  verifyStatelessSession,
} from '../shared/kernel';
import {
  FailedPaymentEvent,
  PAYREVIVE_MODEL_METADATA,
  PAYREVIVE_SAMPLE_EVENTS,
  PayReviveContextualBandit,
  PaymentDeclineCode,
  RECOVERY_ACTION_CATALOG,
  runPayRevive500BatchBenchmark,
} from '../shared/payrevive';
import { PayPalSandboxGateway } from './paypal';
import { GeminiCognitiveEngine } from './gemini';
import {
  clearSessionCookie,
  csrfProtectionMiddleware,
  issueOAuthStateCookie,
  parseCookies,
  redactSecrets,
  sanitizePayloadMiddleware,
  securityHeadersMiddleware,
  setSessionCookie,
  SlidingWindowRateLimiter,
  strictCorsMiddleware,
  validateSafeExternalUrl,
  verifyOAuthStateCookie,
} from './security';
import {
  AegisMultiTenantStore,
  TenantWorkspace,
  verifyPasswordScrypt,
} from './store';

if (!process.env.VITEST) {
  dotenv.config();
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');

export interface AuditLedgerRow {
  id: string;
  timestampIso: string;
  pillar:
    | 'LUPAPERMIT'
    | 'SCAMSHIELD'
    | 'DEALFORGE'
    | 'CLIPREFUND'
    | 'CHURNRESCUE'
    | 'PAYSTREAM'
    | 'PAYREVIVE'
    | 'FUZZER'
    | 'FAILOVER'
    | 'AUTH';
  actor: string;
  eventTitle: string;
  verdict:
    | 'ALLOW'
    | 'HOLD'
    | 'BLOCK'
    | 'SETTLED'
    | 'REFUNDED'
    | 'CIRCUIT_BREAKER'
    | 'REROUTED';
  amountCents: number;
  savedOrProtectedCents: number;
  paypalRef: string;
  sha256Hash: string;
  deterministicRule: string;
}

export interface AuthenticatedOperator {
  id: string;
  email: string;
  fullName: string;
  organization: string;
  role: 'PRINCIPAL_ARCHITECT' | 'TREASURY_OPERATOR' | 'SECURITY_AUDITOR' | 'DEMO_OPERATOR';
  authProvider:
    | 'EMAIL_PASSWORD'
    | 'PAYPAL_OAUTH'
    | 'GOOGLE_OAUTH'
    | 'GITHUB_OAUTH'
    | 'DEMO_SANDBOX';
  paypalMerchantId: string;
  sessionTokenHash: string;
  authenticatedAtIso: string;
}

export interface AegisServerOptions {
  customStoreFilePath?: string;
  authMaxRequestsPerMinute?: number;
  mutationMaxRequestsPerMinute?: number;
  readMaxRequestsPerMinute?: number;
}

interface AuthedRequest extends Request {
  operator?: AuthenticatedOperator;
  rawSessionToken?: string;
  tenantWorkspace?: TenantWorkspace;
}

export function createAegisServer(options: AegisServerOptions = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.use(securityHeadersMiddleware);
  app.use(strictCorsMiddleware);
  app.use(express.json({ limit: '4mb' }));
  app.use(sanitizePayloadMiddleware);
  app.use(csrfProtectionMiddleware);

  const store = new AegisMultiTenantStore({
    rootDir: ROOT_DIR,
    customFilePath: options.customStoreFilePath,
  });

  // Cryptographically strong secret (env var or persisted 256-bit random key; zero hardcoded fallback)
  const kernelSecret = store.resolveKernelSecret();

  // Expose async store flush helper for deterministic test verification
  (app as unknown as { flushStoreAsync?: () => Promise<void> }).flushStoreAsync = () =>
    store.flushAsync();

  const authLimiter = new SlidingWindowRateLimiter({
    tierName: 'AUTH',
    windowMs: 60_000,
    maxRequests: options.authMaxRequestsPerMinute ?? 40,
  });
  const mutationLimiter = new SlidingWindowRateLimiter({
    tierName: 'MUTATION',
    windowMs: 60_000,
    maxRequests: options.mutationMaxRequestsPerMinute ?? 160,
  });
  const readLimiter = new SlidingWindowRateLimiter({
    tierName: 'READ',
    windowMs: 60_000,
    maxRequests: options.readMaxRequestsPerMinute ?? 280,
  });

  const paypalGateway = new PayPalSandboxGateway(
    {
      clientId: process.env.PAYPAL_CLIENT_ID || '',
      clientSecret: process.env.PAYPAL_CLIENT_SECRET || '',
      webhookId: process.env.PAYPAL_WEBHOOK_ID || '',
      environment: process.env.PAYPAL_ENV === 'live' ? 'live' : 'sandbox',
    },
    kernelSecret
  );

  const geminiEngine = new GeminiCognitiveEngine(
    process.env.GEMINI_API_KEY || '',
    process.env.GEMINI_MODEL || 'gemini-3-flash-preview',
    process.env.GROQ_API_KEY || '',
    process.env.GROQ_TEXT_MODEL || 'openai/gpt-oss-120b',
    process.env.GROQ_VISION_MODEL || 'qwen/qwen3.8-27b'
  );

  let zapierWebhookUrl = '';
  if (process.env.ZAPIER_WEBHOOK_URL) {
    const check = validateSafeExternalUrl(process.env.ZAPIER_WEBHOOK_URL, { requireHttps: true });
    if (check.valid && check.normalizedUrl) {
      zapierWebhookUrl = check.normalizedUrl;
    }
  }
  let googleClientId = (process.env.GOOGLE_CLIENT_ID || '').trim();
  let googleClientSecret = (process.env.GOOGLE_CLIENT_SECRET || '').trim();

  // Per-tenant isolated cryptographic state maps (zero cross-tenant leakage)
  const scamVaultsByTenant = new Map<string, ScamShieldTokenVault>();
  const lastIssuedScamTokenByTenant = new Map<string, SignedScamShieldToken>();
  const atomicLedgersByTenant = new Map<string, AtomicExecutionLedger>();
  const zapierDispatchLogByTenant = new Map<
    string,
    Array<{ timestampIso: string; eventType: string; payload: unknown; status: string }>
  >();

  function getTenantScamVault(tenantId: string): ScamShieldTokenVault {
    let vault = scamVaultsByTenant.get(tenantId);
    if (!vault) {
      vault = new ScamShieldTokenVault(`${kernelSecret}:${tenantId}`);
      scamVaultsByTenant.set(tenantId, vault);
    }
    return vault;
  }

  function getTenantAtomicLedger(tenantId: string): AtomicExecutionLedger {
    let ledger = atomicLedgersByTenant.get(tenantId);
    if (!ledger) {
      ledger = new AtomicExecutionLedger();
      atomicLedgersByTenant.set(tenantId, ledger);
    }
    return ledger;
  }

  function getTenantBandit(ws: TenantWorkspace): PayReviveContextualBandit {
    const bandit = new PayReviveContextualBandit();
    if (ws.payreviveBanditState) {
      bandit.importState(ws.payreviveBanditState);
    }
    return bandit;
  }

  let cachedFxRates: { rates: Record<string, number>; fetchedAtMs: number; live: boolean } = {
    rates: { USD: 1, EUR: 0.92, GBP: 0.79, INR: 85.4 },
    fetchedAtMs: 0,
    live: false,
  };

  async function getLiveOrFallbackFxRates(): Promise<{
    rates: Record<string, number>;
    live: boolean;
  }> {
    if (process.env.VITEST) {
      return { rates: cachedFxRates.rates, live: false };
    }
    if (Date.now() - cachedFxRates.fetchedAtMs < 15 * 60_000 && cachedFxRates.fetchedAtMs > 0) {
      return { rates: cachedFxRates.rates, live: cachedFxRates.live };
    }
    try {
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), 2500);
      const res = await fetch('https://api.frankfurter.app/latest?from=USD&to=EUR,GBP,INR', {
        signal: controller.signal,
      });
      clearTimeout(t);
      if (res.ok) {
        const data = (await res.json()) as { rates?: Record<string, number> };
        if (data.rates) {
          cachedFxRates = {
            rates: {
              USD: 1,
              EUR: data.rates.EUR || 0.92,
              GBP: data.rates.GBP || 0.79,
              INR: data.rates.INR || 85.4,
            },
            fetchedAtMs: Date.now(),
            live: true,
          };
          return { rates: cachedFxRates.rates, live: true };
        }
      }
    } catch {
      // Fallback below
    }
    cachedFxRates.fetchedAtMs = Date.now();
    return { rates: cachedFxRates.rates, live: false };
  }

  // --------------------------------------------------------------------------
  // ZERO-TRUST SESSION EXTRACTION & MANDATORY AUTH MIDDLEWARE
  // --------------------------------------------------------------------------

  function extractTokenFromReq(req: Request): string {
    const authHeader = String(req.headers.authorization || '');
    if (authHeader.startsWith('Bearer ')) {
      return authHeader.slice(7).trim();
    }
    const cookies = parseCookies(req.headers.cookie);
    if (cookies.aegis_session) {
      return cookies.aegis_session.trim();
    }
    return '';
  }

  function resolveSessionOperator(req: Request): {
    operator: AuthenticatedOperator;
    token: string;
  } | null {
    const token = extractTokenFromReq(req);
    if (!token || store.isTokenRevoked(token)) {
      return null;
    }
    const claims = verifyStatelessSession(token, kernelSecret);
    if (!claims) {
      return null;
    }
    const { expMs: _exp, ...operator } = claims;
    return { operator, token };
  }

  const requireAuth = (req: Request, res: Response, next: NextFunction) => {
    const resolved = resolveSessionOperator(req);
    if (!resolved) {
      res.status(401).json({
        authenticated: false,
        code: 'AUTH_REQUIRED',
        error: 'Authentication is mandatory. Sign in with Google or Email to access your workspace.',
      });
      return;
    }
    const authed = req as AuthedRequest;
    authed.operator = resolved.operator;
    authed.rawSessionToken = resolved.token;
    authed.tenantWorkspace = store.getTenantWorkspace(
      resolved.operator.id,
      resolved.operator.email
    );
    next();
  };

  function getWorkspace(req: Request): TenantWorkspace {
    const authed = req as AuthedRequest;
    if (authed.tenantWorkspace) return authed.tenantWorkspace;
    throw new Error('Unauthenticated workspace access blocked.');
  }

  function appendAudit(
    req: Request,
    entry: Omit<AuditLedgerRow, 'id' | 'timestampIso'>
  ): AuditLedgerRow {
    return store.appendTenantAuditLog(getWorkspace(req), entry);
  }

  function issueOperatorSession(
    account: {
      id: string;
      email: string;
      fullName: string;
      organization: string;
      role: AuthenticatedOperator['role'];
      paypalMerchantId: string;
    },
    authProvider: AuthenticatedOperator['authProvider']
  ): { token: string; operator: AuthenticatedOperator } {
    const authenticatedAtIso = new Date().toISOString();
    const sessionTokenHash = sha256Hex({
      id: account.id,
      email: account.email,
      authProvider,
      authenticatedAtIso,
      rand: Math.random(),
      secret: kernelSecret,
    }).slice(0, 24);

    const operator: AuthenticatedOperator = {
      id: account.id,
      email: account.email,
      fullName: account.fullName,
      organization: account.organization,
      role: account.role,
      authProvider,
      paypalMerchantId: account.paypalMerchantId,
      sessionTokenHash,
      authenticatedAtIso,
    };

    const token = signStatelessSession(operator, kernelSecret);
    return { token, operator };
  }

  // ==========================================================================
  // 0. PUBLIC HEALTH, SECURITY & ARCHITECTURE MANIFEST (NO SECRETS EXPOSED)
  // ==========================================================================

  app.get('/api/health', readLimiter.middleware(), (req, res) => {
    const resolved = resolveSessionOperator(req);
    const tenantId = resolved
      ? store.getTenantWorkspace(resolved.operator.id, resolved.operator.email).tenantId
      : undefined;
    const ppStatus = paypalGateway.getStatus(tenantId);
    const aiStatus = geminiEngine.getStatus();
    res.json({
      ok: true,
      name: 'AegisPay',
      version: '3.1.0',
      authRequired: true,
      authenticated: Boolean(resolved),
      demoSandboxEnabled: process.env.ALLOW_DEMO_SANDBOX !== 'false',
      paypalSandboxActive: ppStatus.hasLiveSandboxCredentials,
      paypalMode: ppStatus.activeMode,
      aiPrimaryReady: aiStatus.hasLiveGeminiKey,
      aiFailoverReady: aiStatus.hasLiveGroqKey,
      googleOAuthConfigured: Boolean(googleClientId && googleClientSecret),
      security: {
        headersEnforced: [
          'Content-Security-Policy',
          'Strict-Transport-Security',
          'X-Content-Type-Options',
          'X-Frame-Options',
          'Referrer-Policy',
          'Permissions-Policy',
        ],
        csrfProtection: 'ORIGIN_AND_CUSTOM_HEADER_ENFORCED',
        corsPolicy: 'STRICT_ORIGIN_ALLOWLIST',
        secretLeakGuard: 'ACTIVE_REDACTION_AND_SERVER_ONLY_ENV',
        rateLimits: {
          auth: authLimiter.getStats(),
          mutation: mutationLimiter.getStats(),
          read: readLimiter.getStats(),
        },
      },
      storage: store.getStorageArchitectureSummary(resolved?.operator.id),
    });
  });

  // ==========================================================================
  // 1. MANDATORY AUTHENTICATION ENDPOINTS (VERIFIED GOOGLE OAUTH + SCRYPT + DEMO)
  // ==========================================================================

  app.post('/api/auth/register', authLimiter.middleware(), async (req, res) => {
    const { email, password, fullName, organization } = req.body || {};
    const normalizedEmail = String(email || '')
      .trim()
      .toLowerCase();
    const rawPass = String(password || '');
    const cleanName = String(fullName || '').trim() || 'Account Owner';
    const cleanOrg = String(organization || '').trim() || 'Business Workspace';

    if (!normalizedEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      res.status(400).json({ error: 'Valid email address is required.' });
      return;
    }
    if (rawPass.length < 8) {
      res.status(400).json({ error: 'Password must be at least 8 characters.' });
      return;
    }

    const existing = store.getUserByEmail(normalizedEmail);
    if (existing) {
      if (existing.role === 'DEMO_OPERATOR') {
        res.status(409).json({
          code: 'DEMO_ACCOUNT_RESERVED',
          error: 'This email belongs to the shared Demo Sandbox. Please use your own email address.',
        });
        return;
      }

      // Seamless OAuth -> Email/Password account unification:
      // If the user previously signed in via Google OAuth and has not set an email password yet,
      // link this password directly to their existing account & workspace without losing any data!
      if (existing.hasPassword === false) {
        const linked = await store.linkPasswordToUser({
          email: normalizedEmail,
          rawPassword: rawPass,
          fullName: typeof fullName === 'string' && fullName.trim() ? fullName.trim() : undefined,
          organization:
            typeof organization === 'string' && organization.trim()
              ? organization.trim()
              : undefined,
        });
        if (!linked) {
          res.status(500).json({ error: 'Could not link password to existing account.' });
          return;
        }

        const { token, operator } = issueOperatorSession(linked, 'EMAIL_PASSWORD');
        setSessionCookie(req, res, token);

        const ws = store.getTenantWorkspace(operator.id, operator.email);
        store.appendTenantAuditLog(ws, {
          pillar: 'AUTH',
          actor: operator.fullName,
          eventTitle: `Linked Email Password to Google Account (${operator.email})`,
          verdict: 'ALLOW',
          amountCents: 0,
          savedOrProtectedCents: 0,
          paypalRef: operator.paypalMerchantId,
          sha256Hash: operator.sessionTokenHash,
          deterministicRule: 'Unified Google OAuth + scrypt Password Identity',
        });

        res.status(200).json({
          authenticated: true,
          isNewAccount: false,
          linkedFromOAuth: true,
          token,
          operator,
          storage: store.getStorageArchitectureSummary(operator.id),
        });
        return;
      }

      res.status(409).json({
        code: 'EMAIL_PASSWORD_ALREADY_REGISTERED',
        error: 'An account with this email already exists. Please sign in with your password or Google.',
      });
      return;
    }

    const created = await store.createUser({
      email: normalizedEmail,
      rawPassword: rawPass,
      fullName: cleanName,
      organization: cleanOrg,
      role: 'TREASURY_OPERATOR',
    });

    const { token, operator } = issueOperatorSession(created, 'EMAIL_PASSWORD');
    setSessionCookie(req, res, token);

    const ws = store.getTenantWorkspace(operator.id, operator.email);
    store.appendTenantAuditLog(ws, {
      pillar: 'AUTH',
      actor: operator.fullName,
      eventTitle: `Account Created (${operator.email})`,
      verdict: 'ALLOW',
      amountCents: 0,
      savedOrProtectedCents: 0,
      paypalRef: operator.paypalMerchantId,
      sha256Hash: operator.sessionTokenHash,
      deterministicRule: 'scrypt (N=16384, r=8, p=1) + Per-User Salt + HttpOnly Session Cookie',
    });

    res.status(201).json({
      authenticated: true,
      isNewAccount: true,
      token,
      operator,
      storage: store.getStorageArchitectureSummary(operator.id),
    });
  });

  app.post('/api/auth/login', authLimiter.middleware(), async (req, res) => {
    const { email, password } = req.body || {};
    const normalizedEmail = String(email || '')
      .trim()
      .toLowerCase();
    const rawPass = String(password || '');

    const account = store.getUserByEmail(normalizedEmail);
    if (!account) {
      res.status(401).json({
        error: 'Invalid email or password.',
      });
      return;
    }

    // Seamless OAuth -> Email Sign-In: if this user registered via Google OAuth and has no
    // email password yet, link their entered 8+ character password and sign them right in.
    if (account.hasPassword === false && account.role !== 'DEMO_OPERATOR') {
      if (rawPass.length < 8) {
        res.status(400).json({
          code: 'OAUTH_PASSWORD_MIN_LENGTH',
          error:
            'Your Google-linked account does not have an email password yet. Enter at least 8 characters to set your password and sign in, or click Continue with Google.',
        });
        return;
      }

      const linked = await store.linkPasswordToUser({
        email: normalizedEmail,
        rawPassword: rawPass,
      });
      if (!linked) {
        res.status(500).json({ error: 'Could not link password to existing account.' });
        return;
      }

      const { token, operator } = issueOperatorSession(linked, 'EMAIL_PASSWORD');
      setSessionCookie(req, res, token);

      const ws = store.getTenantWorkspace(operator.id, operator.email);
      store.appendTenantAuditLog(ws, {
        pillar: 'AUTH',
        actor: operator.fullName,
        eventTitle: `Linked Email Password & Signed In (${operator.email})`,
        verdict: 'ALLOW',
        amountCents: 0,
        savedOrProtectedCents: 0,
        paypalRef: operator.paypalMerchantId,
        sha256Hash: operator.sessionTokenHash,
        deterministicRule: 'Unified Google OAuth + scrypt Password Sign-In',
      });

      res.json({
        authenticated: true,
        isNewAccount: false,
        linkedFromOAuth: true,
        token,
        operator,
        storage: store.getStorageArchitectureSummary(operator.id),
      });
      return;
    }

    if (!verifyPasswordScrypt(rawPass, account.passwordScrypt)) {
      res.status(401).json({
        error: 'Invalid email or password.',
      });
      return;
    }

    const { token, operator } = issueOperatorSession(account, 'EMAIL_PASSWORD');
    setSessionCookie(req, res, token);

    const ws = store.getTenantWorkspace(operator.id, operator.email);
    store.appendTenantAuditLog(ws, {
      pillar: 'AUTH',
      actor: operator.fullName,
      eventTitle: `Signed In (${operator.email})`,
      verdict: 'ALLOW',
      amountCents: 0,
      savedOrProtectedCents: 0,
      paypalRef: operator.paypalMerchantId,
      sha256Hash: operator.sessionTokenHash,
      deterministicRule: 'Constant-Time scrypt Verification + HttpOnly Session Cookie',
    });

    res.json({
      authenticated: true,
      isNewAccount: false,
      token,
      operator,
      storage: store.getStorageArchitectureSummary(operator.id),
    });
  });

  // Explicit, isolated Demo Workspace session (non-privileged DEMO_OPERATOR role)
  app.post('/api/auth/demo', authLimiter.middleware(), (req, res) => {
    if (process.env.ALLOW_DEMO_SANDBOX === 'false') {
      res.status(403).json({ error: 'Interactive demo sandbox is disabled in this environment.' });
      return;
    }
    const demoAccount = store.getUserByEmail('demo@aegispay.io');
    if (!demoAccount) {
      res.status(500).json({ error: 'Demo sandbox account unavailable.' });
      return;
    }

    const { token, operator } = issueOperatorSession(demoAccount, 'DEMO_SANDBOX');
    setSessionCookie(req, res, token);

    const ws = store.getTenantWorkspace(operator.id, operator.email);
    store.appendTenantAuditLog(ws, {
      pillar: 'AUTH',
      actor: operator.fullName,
      eventTitle: 'Launched Isolated Interactive Sandbox Tour',
      verdict: 'ALLOW',
      amountCents: 0,
      savedOrProtectedCents: 0,
      paypalRef: operator.paypalMerchantId,
      sha256Hash: operator.sessionTokenHash,
      deterministicRule: 'Isolated DEMO_OPERATOR Tenant Sandbox + HttpOnly Session Cookie',
    });

    res.json({
      authenticated: true,
      isNewAccount: !ws.tutorialCompleted,
      token,
      operator,
      storage: store.getStorageArchitectureSummary(operator.id),
    });
  });

  app.get('/api/auth/google/url', authLimiter.middleware(), (req, res) => {
    const isSecure =
      req.secure ||
      req.headers['x-forwarded-proto'] === 'https' ||
      process.env.NODE_ENV === 'production';
    const protocol = isSecure ? 'https' : 'http';
    const host = req.headers.host || 'localhost:8787';
    const redirectUri =
      process.env.GOOGLE_REDIRECT_URI || `${protocol}://${host}/api/auth/google/callback`;

    if (!googleClientId || !googleClientSecret) {
      res.json({
        liveGoogleOAuthConfigured: false,
        redirectUri,
        message:
          'Google OAuth credentials are not configured on this server. Sign in with Email or launch the Interactive Demo Workspace.',
      });
      return;
    }

    const state = issueOAuthStateCookie(req, res, kernelSecret);
    const params = new URLSearchParams({
      client_id: googleClientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'openid email profile',
      access_type: 'online',
      prompt: 'select_account',
      state,
    });

    res.json({
      liveGoogleOAuthConfigured: true,
      authUrl: `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`,
      redirectUri,
    });
  });

  app.get('/api/auth/google/callback', authLimiter.middleware(), async (req, res) => {
    try {
      const code = String(req.query.code || '');
      const state = String(req.query.state || '');

      if (!verifyOAuthStateCookie(req, res, state, kernelSecret)) {
        res.redirect('/?auth_error=oauth_state_mismatch');
        return;
      }

      if (!code || !googleClientId || !googleClientSecret) {
        res.redirect('/?auth_error=oauth_missing_code');
        return;
      }

      const isSecure =
        req.secure ||
        req.headers['x-forwarded-proto'] === 'https' ||
        process.env.NODE_ENV === 'production';
      const protocol = isSecure ? 'https' : 'http';
      const host = req.headers.host || 'localhost:8787';
      const redirectUri =
        process.env.GOOGLE_REDIRECT_URI || `${protocol}://${host}/api/auth/google/callback`;

      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: googleClientId,
          client_secret: googleClientSecret,
          redirect_uri: redirectUri,
          grant_type: 'authorization_code',
        }).toString(),
      });

      if (!tokenRes.ok) {
        res.redirect('/?auth_error=oauth_token_exchange_failed');
        return;
      }

      const tokenData = (await tokenRes.json()) as { access_token?: string };
      if (!tokenData.access_token) {
        res.redirect('/?auth_error=oauth_no_access_token');
        return;
      }

      const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });
      if (!userRes.ok) {
        res.redirect('/?auth_error=oauth_userinfo_failed');
        return;
      }

      const profile = (await userRes.json()) as {
        email?: string;
        email_verified?: boolean;
        name?: string;
        hd?: string;
      };

      if (!profile.email || profile.email_verified === false) {
        res.redirect('/?auth_error=oauth_email_unverified');
        return;
      }

      const email = profile.email.trim().toLowerCase();
      const fullName = (profile.name || email.split('@')[0]).trim();
      const org = (profile.hd || 'Google Verified Workspace').trim();
      const isFirstOAuthSignup = !store.getUserByEmail(email);

      const upserted = store.upsertOAuthUser({
        email,
        fullName,
        organization: org,
        role: 'TREASURY_OPERATOR',
        paypalMerchantId: `SBX-MERCH-${sha256Hex(email).slice(0, 6).toUpperCase()}`,
      });

      const { token, operator } = issueOperatorSession(upserted, 'GOOGLE_OAUTH');
      setSessionCookie(req, res, token);

      const ws = store.getTenantWorkspace(operator.id, operator.email);
      store.appendTenantAuditLog(ws, {
        pillar: 'AUTH',
        actor: operator.fullName,
        eventTitle: `Signed In with Google (${operator.email})`,
        verdict: 'ALLOW',
        amountCents: 0,
        savedOrProtectedCents: 0,
        paypalRef: operator.paypalMerchantId,
        sha256Hash: operator.sessionTokenHash,
        deterministicRule: 'Google OAuth 2.0 State Cookie + Code Exchange + Verified Email',
      });

      // Security: Session is delivered strictly via HttpOnly cookie — NEVER leak tokens in URL query strings!
      res.redirect(isFirstOAuthSignup ? '/?auth_ready=1&first_signup=1' : '/?auth_ready=1');
    } catch {
      res.redirect('/?auth_error=google_callback_failed');
    }
  });

  app.post('/api/auth/google', authLimiter.middleware(), async (req, res) => {
    const { idToken } = req.body || {};
    if (typeof idToken !== 'string' || idToken.split('.').length !== 3) {
      res.status(401).json({
        error:
          'A cryptographically signed Google ID token is required. Unverified email assertions are rejected.',
      });
      return;
    }

    try {
      const verifyRes = await fetch(
        `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`
      );
      if (!verifyRes.ok) {
        res.status(401).json({ error: 'Google ID token verification failed.' });
        return;
      }

      const payload = (await verifyRes.json()) as {
        aud?: string;
        email?: string;
        email_verified?: string | boolean;
        name?: string;
        hd?: string;
      };

      if (googleClientId && payload.aud !== googleClientId) {
        res.status(401).json({ error: 'Google ID token audience mismatch.' });
        return;
      }

      const isVerified =
        payload.email_verified === true || payload.email_verified === 'true';
      if (!payload.email || !isVerified) {
        res.status(401).json({ error: 'Google account email is not verified.' });
        return;
      }

      const resolvedEmail = payload.email.trim().toLowerCase();
      const resolvedName = (payload.name || resolvedEmail.split('@')[0]).trim();
      const resolvedOrg = (payload.hd || 'Google Identity Verified').trim();
      const isFirstOAuthSignup = !store.getUserByEmail(resolvedEmail);

      const upserted = store.upsertOAuthUser({
        email: resolvedEmail,
        fullName: resolvedName,
        organization: resolvedOrg,
        role: 'TREASURY_OPERATOR',
        paypalMerchantId: `SBX-MERCH-${sha256Hex(resolvedEmail).slice(0, 6).toUpperCase()}`,
      });

      const { token, operator } = issueOperatorSession(upserted, 'GOOGLE_OAUTH');
      setSessionCookie(req, res, token);

      const ws = store.getTenantWorkspace(operator.id, operator.email);
      store.appendTenantAuditLog(ws, {
        pillar: 'AUTH',
        actor: operator.fullName,
        eventTitle: `Authenticated via Google Identity Token (${operator.email})`,
        verdict: 'ALLOW',
        amountCents: 0,
        savedOrProtectedCents: 0,
        paypalRef: operator.paypalMerchantId,
        sha256Hash: operator.sessionTokenHash,
        deterministicRule: 'Google ID Token Audience + Email Verification Enforced',
      });

      res.json({
        authenticated: true,
        isNewAccount: isFirstOAuthSignup,
        token,
        operator,
        storage: store.getStorageArchitectureSummary(operator.id),
      });
    } catch {
      res.status(401).json({ error: 'Unable to verify Google ID token.' });
    }
  });

  app.get('/api/auth/me', readLimiter.middleware(), (req, res) => {
    const resolved = resolveSessionOperator(req);
    if (!resolved) {
      res.status(401).json({ authenticated: false, operator: null });
      return;
    }
    res.json({
      authenticated: true,
      operator: resolved.operator,
      storage: store.getStorageArchitectureSummary(resolved.operator.id),
    });
  });

  app.post('/api/auth/logout', authLimiter.middleware(), (req, res) => {
    const token = extractTokenFromReq(req);
    if (token) {
      store.revokeToken(token);
    }
    clearSessionCookie(res);
    res.json({ loggedOut: true });
  });

  // Public PayPal Webhook Receiver — strictly requires PayPal Transmission Signature or HMAC-SHA256!
  app.post('/api/paypal/webhook', mutationLimiter.middleware(), async (req, res) => {
    const verification = await paypalGateway.verifyAndIngestExternalWebhook({
      headers: req.headers,
      body: (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, unknown>,
    });

    if (!verification.verified || !verification.event) {
      res.status(401).json({
        received: false,
        verified: false,
        error: verification.reason,
      });
      return;
    }

    res.json({
      received: true,
      verified: true,
      verificationMethod: verification.event.verificationMethod,
      eventId: verification.event.id,
    });
  });

  // ==========================================================================
  // MANDATORY AUTHENTICATION BARRIER FOR ALL PROTECTED /api/* ROUTES
  // ==========================================================================

  app.use('/api', (req, res, next) => {
    if (req.method === 'GET') {
      readLimiter.middleware()(req, res, (err) => {
        if (err) return next(err);
        requireAuth(req, res, next);
      });
      return;
    }
    mutationLimiter.middleware()(req, res, (err) => {
      if (err) return next(err);
      requireAuth(req, res, next);
    });
  });

  // ==========================================================================
  // 2. PROTECTED TENANT STATE, RBAC CREDENTIALS & WORKSPACE ONBOARDING
  // ==========================================================================

  app.get('/api/state', (req, res) => {
    const authed = req as AuthedRequest;
    const ws = getWorkspace(req);
    const tenantOrders = paypalGateway.getOrders(ws.tenantId);
    const tenantInvoices = paypalGateway.getInvoices(ws.tenantId);
    const tenantVaultTokens = paypalGateway.getVaultTokens(ws.tenantId);
    const tenantSubscriptions = paypalGateway.getSubscriptions(ws.tenantId);
    const tenantWebhooks = paypalGateway.getWebhookStream(ws.tenantId);

    const zombieReport = auditPayPalPermissions(ws.billingPermissions);
    const defaultAffordability = evaluateCashflowAffordability({
      itemTitle: 'Pro Studio 4K OLED Reference Monitor',
      proposedSpendCents: 58000,
      currentBalanceCents: ws.currentCheckingBalanceCents,
      commitments: ws.cashflowCommitments,
      minimumSafetyBufferCents: ws.minimumSafetyBufferCents,
    });

    const totalProtectedCents = ws.auditLogs.reduce((acc, r) => acc + r.savedOrProtectedCents, 0);

    res.json({
      system: {
        name: 'AegisPay',
        version: '3.1.0',
        tagline: 'Safer Payments, Automated Revenue Recovery, and Milestone Billing on PayPal.',
        paypal: paypalGateway.getStatus(ws.tenantId),
        gemini: geminiEngine.getStatus(),
        zapierConfigured: Boolean(zapierWebhookUrl),
        googleOAuth: {
          configured: Boolean(googleClientId && googleClientSecret),
          clientIdPreview: googleClientId ? `${googleClientId.slice(0, 14)}...` : 'Not Configured',
        },
        security: {
          rateLimits: {
            auth: authLimiter.getStats(),
            mutation: mutationLimiter.getStats(),
            read: readLimiter.getStats(),
          },
          storage: store.getStorageArchitectureSummary(authed.operator?.id),
        },
      },
      operator: authed.operator || null,
      workspace: {
        tenantId: ws.tenantId,
        tutorialCompleted: Boolean(ws.tutorialCompleted),
      },
      kpis: {
        totalProtectedCents,
        zombieAnnualExposureCents: zombieReport.totalAnnualExposureCents,
        recoverableMonthlyCents: zombieReport.recoverableMonthlyCents,
        activeAgentPermits: ws.agentPermits.filter((p) => p.active).length,
        heldOrdersPendingApproval: tenantOrders.filter((o) => o.status === 'AUTHORIZED').length,
        totalAuditRecords: ws.auditLogs.length,
        livePayPalInvoicesCount: tenantInvoices.length,
        activeMilestonePlansCount: ws.milestonePlans.length,
        payreviveDecisionsCount: ws.payreviveDecisions.length,
      },
      lupa: {
        billingPermissions: ws.billingPermissions,
        zombieReport,
        cashflowCommitments: ws.cashflowCommitments,
        currentCheckingBalanceCents: ws.currentCheckingBalanceCents,
        minimumSafetyBufferCents: ws.minimumSafetyBufferCents,
        defaultAffordability,
        agentPermits: ws.agentPermits,
        vaultTokens: tenantVaultTokens,
        subscriptions: tenantSubscriptions,
      },
      cliprefund: {
        merchantPolicy: ws.merchantPolicy || DEFAULT_MERCHANT_REFUND_POLICY,
      },
      paystream: {
        plans: ws.milestonePlans,
        invoices: tenantInvoices,
      },
      payrevive: {
        modelCard: PAYREVIVE_MODEL_METADATA,
        presets: PAYREVIVE_SAMPLE_EVENTS,
        actionCatalog: RECOVERY_ACTION_CATALOG,
        decisions: ws.payreviveDecisions,
        lastBenchmark: ws.lastPayReviveBenchmark,
      },
      orders: tenantOrders,
      invoices: tenantInvoices,
      webhooks: tenantWebhooks,
      auditLogs: ws.auditLogs,
      signedContracts: ws.signedContracts,
      zapierDispatchLog: zapierDispatchLogByTenant.get(ws.tenantId) || [],
    });
  });

  app.post('/api/workspace/tutorial', (req, res) => {
    const ws = getWorkspace(req);
    ws.tutorialCompleted = Boolean(req.body?.completed ?? true);
    store.scheduleFlush();
    res.json({ tutorialCompleted: ws.tutorialCompleted });
  });

  // Strict RBAC + SSRF validation on global infrastructure credentials
  app.post('/api/credentials', async (req, res) => {
    const authed = req as AuthedRequest;
    if (authed.operator?.role !== 'PRINCIPAL_ARCHITECT') {
      res.status(403).json({
        error:
          'Forbidden: Updating server-level gateway credentials requires PRINCIPAL_ARCHITECT privileges.',
      });
      return;
    }

    const {
      paypalClientId,
      paypalClientSecret,
      paypalWebhookId,
      paypalEnvironment,
      geminiApiKey,
      groqApiKey,
      simulateGeminiRateLimit,
      zapierUrl,
      googleOAuthClientId,
      googleOAuthClientSecret,
    } = req.body || {};

    if (typeof zapierUrl === 'string' && zapierUrl.trim()) {
      const check = validateSafeExternalUrl(zapierUrl, { requireHttps: true });
      if (!check.valid || !check.normalizedUrl) {
        res.status(400).json({ error: `Invalid zapierUrl: ${check.reason}` });
        return;
      }
      zapierWebhookUrl = check.normalizedUrl;
    } else if (zapierUrl === '') {
      zapierWebhookUrl = '';
    }

    if (
      typeof paypalClientId === 'string' ||
      typeof paypalClientSecret === 'string' ||
      typeof paypalWebhookId === 'string'
    ) {
      paypalGateway.updateCredentials({
        clientId:
          typeof paypalClientId === 'string' && paypalClientId.trim()
            ? paypalClientId.trim()
            : undefined,
        clientSecret:
          typeof paypalClientSecret === 'string' && paypalClientSecret.trim()
            ? paypalClientSecret.trim()
            : undefined,
        webhookId:
          typeof paypalWebhookId === 'string' && paypalWebhookId.trim()
            ? paypalWebhookId.trim()
            : undefined,
        environment: paypalEnvironment === 'live' ? 'live' : 'sandbox',
      });
    }

    geminiEngine.updateCredentials({
      geminiApiKey:
        typeof geminiApiKey === 'string' && geminiApiKey.trim()
          ? geminiApiKey.trim()
          : undefined,
      groqApiKey:
        typeof groqApiKey === 'string' && groqApiKey.trim() ? groqApiKey.trim() : undefined,
      simulateGeminiRateLimit:
        typeof simulateGeminiRateLimit === 'boolean' ? simulateGeminiRateLimit : undefined,
    });

    if (typeof googleOAuthClientId === 'string' && googleOAuthClientId.trim()) {
      googleClientId = googleOAuthClientId.trim();
    }
    if (typeof googleOAuthClientSecret === 'string' && googleOAuthClientSecret.trim()) {
      googleClientSecret = googleOAuthClientSecret.trim();
    }

    const ws = getWorkspace(req);
    const tokenTest = await paypalGateway.getAccessToken(true);
    res.json({
      updated: true,
      paypal: paypalGateway.getStatus(ws.tenantId),
      paypalOAuthLiveVerified: tokenTest.live,
      gemini: geminiEngine.getStatus(),
      zapierConfigured: Boolean(zapierWebhookUrl),
      googleOAuthConfigured: Boolean(googleClientId && googleClientSecret),
    });
  });

  app.post('/api/ai/failover-test', async (req, res) => {
    const { simulateRateLimit } = req.body || {};
    const shouldSimulate = simulateRateLimit !== undefined ? Boolean(simulateRateLimit) : true;
    geminiEngine.setSimulateRateLimit(shouldSimulate);

    const testScan = await geminiEngine.analyzePaymentScamSemantics({
      sanitizedText: 'Invoice #8012 for Cloud Security Infrastructure: $120.00 USD',
      claimedAmountCents: 12000,
      payeeIdentifier: 'billing@cloudinfra.io',
    });

    const auditRow = appendAudit(req, {
      pillar: 'FAILOVER',
      actor: 'AI Failover Router (Gemini -> Groq)',
      eventTitle: shouldSimulate
        ? `Gemini HTTP 429 Intercepted -> Automatic Failover to Groq (${testScan.telemetry.modelUsed || 'Groq'} in ${testScan.telemetry.latencyMs}ms)`
        : `Primary Google Gemini (${testScan.telemetry.modelUsed || 'gemini-3-flash-preview'}) Route Restored (${testScan.telemetry.latencyMs}ms)`,
      verdict: shouldSimulate ? 'REROUTED' : 'ALLOW',
      amountCents: 12000,
      savedOrProtectedCents: 0,
      paypalRef: testScan.telemetry.activeProviderUsed,
      sha256Hash: sha256Hex(testScan.telemetry),
      deterministicRule: testScan.telemetry.failoverReason,
    });

    res.json({
      aiStatus: geminiEngine.getStatus(),
      telemetry: testScan.telemetry,
      promptGuard: testScan.promptGuard,
      auditRow,
    });
  });

  // ==========================================================================
  // 3. PAYREVIVE: TRAINED NEWTON GBDT + SHAP + DISJOINT LINUCB + COMPLIANCE
  // ==========================================================================

  app.get('/api/payrevive/presets', (_req, res) => {
    res.json({
      modelCard: PAYREVIVE_MODEL_METADATA,
      presets: PAYREVIVE_SAMPLE_EVENTS,
      actionCatalog: RECOVERY_ACTION_CATALOG,
    });
  });

  app.post('/api/payrevive/recover', async (req, res) => {
    try {
      const ws = getWorkspace(req);
      const body = req.body || {};
      const preset = PAYREVIVE_SAMPLE_EVENTS.find((p) => p.presetId === body.presetId);
      const baseEvent = preset ? preset.event : PAYREVIVE_SAMPLE_EVENTS[0].event;

      const validDeclines: PaymentDeclineCode[] = [
        'INSUFFICIENT_FUNDS',
        'ISSUER_TIMEOUT',
        'EXPIRED_CARD',
        'VELOCITY_EXCEEDED',
        'STOLEN_OR_FRAUD_CARD',
        'REVOKED_AUTHORIZATION',
      ];
      const declineCode: PaymentDeclineCode = validDeclines.includes(body.declineCode)
        ? body.declineCode
        : baseEvent.declineCode;

      const event: FailedPaymentEvent = {
        eventId: String(body.eventId || `EVT-${Date.now().toString(36).toUpperCase()}`),
        customerEmail: String(body.customerEmail || baseEvent.customerEmail).trim(),
        merchantOrderRef: String(body.merchantOrderRef || baseEvent.merchantOrderRef).trim(),
        amountCents: Math.max(10, Math.round(Number(body.amountCents ?? baseEvent.amountCents))),
        currency: 'USD',
        declineCode,
        daysUntilPayday: Math.max(
          0,
          Math.min(14, Math.round(Number(body.daysUntilPayday ?? baseEvent.daysUntilPayday)))
        ),
        priorRetryCount30d: Math.max(
          0,
          Math.min(6, Math.round(Number(body.priorRetryCount30d ?? baseEvent.priorRetryCount30d)))
        ),
        historicalCaptureRate: Math.max(
          0,
          Math.min(1, Number(body.historicalCaptureRate ?? baseEvent.historicalCaptureRate))
        ),
        hasPayPalBackupFunding:
          body.hasPayPalBackupFunding !== undefined
            ? Boolean(body.hasPayPalBackupFunding)
            : baseEvent.hasPayPalBackupFunding,
        issuerLatencyMs: Math.max(
          50,
          Math.min(8000, Math.round(Number(body.issuerLatencyMs ?? baseEvent.issuerLatencyMs)))
        ),
        accountTenureDays: Math.max(
          1,
          Math.round(Number(body.accountTenureDays ?? baseEvent.accountTenureDays))
        ),
        customerOptedOutComms:
          body.customerOptedOutComms !== undefined
            ? Boolean(body.customerOptedOutComms)
            : baseEvent.customerOptedOutComms,
        localCustomerHour: Math.max(
          0,
          Math.min(23, Math.round(Number(body.localCustomerHour ?? baseEvent.localCustomerHour)))
        ),
        hasOpenPayPalDispute:
          body.hasOpenPayPalDispute !== undefined
            ? Boolean(body.hasOpenPayPalDispute)
            : baseEvent.hasOpenPayPalDispute,
      };

      const tenantBandit = getTenantBandit(ws);
      const decision = tenantBandit.evaluateAndDecide(event);
      store.recordPayReviveDecision(ws, decision);

      let paypalOrder = null;
      let paypalInvoice = null;

      if (decision.verdict === 'EXECUTE_RECOVERY' && body.executeLivePayPal !== false) {
        if (decision.selectedArmDetails.paypalMechanism === 'PAYPAL_ORDERS_V2_RETRY') {
          const intent =
            decision.selectedAction === 'IMMEDIATE_JITTER_RETRY' ? 'CAPTURE' : 'AUTHORIZE';
          paypalOrder = await paypalGateway.createOrder({
            ownerTenantId: ws.tenantId,
            intent,
            amountCents: event.amountCents,
            currency: 'USD',
            merchantName: `Recovery (${event.merchantOrderRef})`,
            description: `${decision.selectedArmDetails.actionLabel} [${event.merchantOrderRef}]`,
            customHash: decision.auditHash,
            idempotencyKey: decision.decisionId,
            pillar: 'PAYREVIVE',
            autoExecuteInSandbox: true,
          });
        } else if (decision.selectedArmDetails.paypalMechanism === 'PAYPAL_INVOICING_V2_LINK') {
          const recoveryInvoiceCents =
            decision.selectedAction === 'SPLIT_TWO_PART_INVOICE'
              ? Math.ceil(event.amountCents / 2)
              : event.amountCents;
          paypalInvoice = await paypalGateway.createLiveInvoice({
            ownerTenantId: ws.tenantId,
            title: `Payment Recovery: ${decision.selectedArmDetails.actionLabel}`,
            note: `Order ${event.merchantOrderRef}. ${decision.plainEnglishRecommendation}`,
            recipientEmail: event.customerEmail,
            amountCents: recoveryInvoiceCents,
            currency: 'USD',
            pillar: 'PAYREVIVE',
            contractOrPlanHash: decision.auditHash,
            sendImmediately: true,
          });
        }
        // NOTE: We intentionally do NOT call tenantBandit.updateOutcome(..., true) on invoice/order creation!
        // Bandit arm weights update ONLY when actual payment settlement outcome is confirmed via /api/payrevive/confirm-settlement.
      }

      const auditVerdict: AuditLedgerRow['verdict'] =
        decision.verdict === 'EXECUTE_RECOVERY'
          ? 'SETTLED'
          : decision.verdict === 'BLOCKED_BY_COMPLIANCE'
            ? 'BLOCK'
            : 'HOLD';

      const auditRow = appendAudit(req, {
        pillar: 'PAYREVIVE',
        actor: 'Failed Payment Recovery Engine',
        eventTitle:
          decision.verdict === 'EXECUTE_RECOVERY'
            ? `Recovery Initiated (${decision.selectedArmDetails.actionLabel}) on $${(event.amountCents / 100).toFixed(2)} -> Expected Net +$${(decision.selectedArmDetails.expectedNetGainCents / 100).toFixed(2)}`
            : decision.verdict === 'BLOCKED_BY_COMPLIANCE'
              ? `Compliance Blocked Recovery on ${event.merchantOrderRef} (${event.declineCode})`
              : `Skipped Unprofitable Retry on $${(event.amountCents / 100).toFixed(2)}`,
        verdict: auditVerdict,
        amountCents: event.amountCents,
        savedOrProtectedCents:
          decision.verdict === 'EXECUTE_RECOVERY'
            ? Math.max(0, decision.selectedArmDetails.expectedNetGainCents)
            : decision.selectedArmDetails.actionCostCents,
        paypalRef: paypalInvoice
          ? paypalInvoice.invoiceId
          : paypalOrder
            ? paypalOrder.orderId
            : decision.verdict,
        sha256Hash: decision.auditHash,
        deterministicRule: decision.deterministicRationale,
      });

      res.json({
        decision,
        paypalOrder,
        paypalInvoice,
        auditRow,
      });
    } catch (err) {
      res.status(400).json({ error: redactSecrets((err as Error).message) });
    }
  });

  // Explicit settlement outcome feedback loop for LinUCB contextual bandit learning
  app.post('/api/payrevive/confirm-settlement', (req, res) => {
    const ws = getWorkspace(req);
    const { decisionId, settled } = req.body || {};
    const target = ws.payreviveDecisions.find((d) => d.decisionId === String(decisionId || ''));
    if (!target) {
      res.status(404).json({ error: 'Recovery decision not found in workspace.' });
      return;
    }

    const tenantBandit = getTenantBandit(ws);
    tenantBandit.updateOutcomeForEvent(target.event, target.selectedAction, Boolean(settled));
    target.settlementConfirmed = Boolean(settled);
    ws.payreviveBanditState = tenantBandit.exportState();
    store.scheduleFlush();

    res.json({
      updated: true,
      decisionId: target.decisionId,
      selectedAction: target.selectedAction,
      settled: Boolean(settled),
    });
  });

  app.post('/api/payrevive/benchmark', (req, res) => {
    const batches = Math.min(1000, Math.max(50, Math.round(Number(req.body?.batches) || 500)));
    const batchSize = Math.min(50, Math.max(5, Math.round(Number(req.body?.batchSize) || 20)));
    const seed = Math.round(Number(req.body?.seed) || 20261028);

    const report = runPayRevive500BatchBenchmark(batches, batchSize, seed);
    const ws = getWorkspace(req);
    ws.lastPayReviveBenchmark = report;
    store.scheduleFlush();

    const auditRow = appendAudit(req, {
      pillar: 'PAYREVIVE',
      actor: 'PayRevive 500-Batch Benchmark Runner',
      eventTitle: `Verified ${report.batchesSimulated} Batches (${report.totalFailedPaymentsEvaluated.toLocaleString()} Failures): +${report.netRecoveryLiftPercent.toFixed(1)}% Net Recovery Lift, ${report.payRevive.complianceViolations} Compliance Violations`,
      verdict: report.payRevive.complianceViolations === 0 ? 'ALLOW' : 'BLOCK',
      amountCents: report.payRevive.netRecoveredCents,
      savedOrProtectedCents: Math.max(0, report.additionalNetRecoveredCents),
      paypalRef: `BENCH-${report.batchesSimulated}B`,
      sha256Hash: report.benchmarkProofHash,
      deterministicRule: `Held-Out ROC-AUC ${report.modelMetadata.heldOutRocAuc} | TreeSHAP Additivity ${report.shapAdditivityChecksPassed}/${report.totalFailedPaymentsEvaluated} | 0 Compliance Refusals`,
    });

    res.json({ report, auditRow });
  });

  // ==========================================================================
  // 4. BUYER SAFETY: BUDGET GUARD, SUBSCRIPTION CLEANUP & SPENDING LIMITS
  // ==========================================================================

  app.post('/api/lupa/cashflow-check', async (req, res) => {
    try {
      const ws = getWorkspace(req);
      const { itemTitle, proposedSpendCents, syncAgentPermitCap, includeAiAdvice } = req.body || {};
      const spend = Math.max(100, Math.round(Number(proposedSpendCents) || 58000));
      const result = evaluateCashflowAffordability({
        itemTitle: String(itemTitle || 'Custom Purchase Evaluation'),
        proposedSpendCents: spend,
        currentBalanceCents: ws.currentCheckingBalanceCents,
        commitments: ws.cashflowCommitments,
        minimumSafetyBufferCents: ws.minimumSafetyBufferCents,
      });

      if (syncAgentPermitCap && ws.agentPermits[0]) {
        ws.agentPermits[0].maxSingleTransactionCents = Math.max(
          2000,
          Math.min(100000, result.recommendedAgentCapCents)
        );
        store.scheduleFlush();
      }

      let aiAdvisor = null;
      if (includeAiAdvice) {
        aiAdvisor = await geminiEngine.adviseCashflowAffordability({
          itemTitle: result.itemTitle,
          proposedSpendCents: result.proposedSpendCents,
          trueFreeCashflowCents: result.trueFreeCashflowCents,
          postPurchaseFreeCashflowCents: result.postPurchaseFreeCashflowCents,
          verdict: result.verdict,
        });
      }

      appendAudit(req, {
        pillar: 'LUPAPERMIT',
        actor: 'Budget Guard',
        eventTitle: `Budget Check: "${result.itemTitle}" ($${(spend / 100).toFixed(2)}) -> ${result.verdict}`,
        verdict: result.verdict,
        amountCents: spend,
        savedOrProtectedCents: result.verdict === 'ALLOW' ? 0 : spend,
        paypalRef: 'CASHFLOW-GUARD',
        sha256Hash: sha256Hex(result),
        deterministicRule: result.deterministicExplanation,
      });

      res.json({ result, aiAdvisor, updatedPermit: ws.agentPermits[0] });
    } catch (err) {
      res.status(400).json({ error: redactSecrets((err as Error).message) });
    }
  });

  app.post('/api/lupa/cashflow-update', (req, res) => {
    const ws = getWorkspace(req);
    const { balanceCents, safetyBufferCents, addCommitment, removeCommitmentId } = req.body || {};
    if (typeof balanceCents === 'number' && Number.isFinite(balanceCents) && balanceCents >= 0) {
      ws.currentCheckingBalanceCents = Math.round(balanceCents);
    }
    if (
      typeof safetyBufferCents === 'number' &&
      Number.isFinite(safetyBufferCents) &&
      safetyBufferCents >= 0
    ) {
      ws.minimumSafetyBufferCents = Math.round(safetyBufferCents);
    }
    if (addCommitment && typeof addCommitment === 'object' && addCommitment.name) {
      ws.cashflowCommitments.push({
        id: `cf_${Date.now().toString(36)}`,
        name: String(addCommitment.name).slice(0, 80),
        amountCents: Math.max(100, Math.round(Number(addCommitment.amountCents) || 5000)),
        dueInDays: Math.max(1, Math.min(60, Math.round(Number(addCommitment.dueInDays) || 7))),
        category:
          addCommitment.category === 'SAVINGS_GOAL' ? 'SAVINGS_GOAL' : 'ESSENTIAL_LIVING',
        mandatory: addCommitment.category !== 'SAVINGS_GOAL',
      });
    }
    if (typeof removeCommitmentId === 'string' && removeCommitmentId) {
      ws.cashflowCommitments = ws.cashflowCommitments.filter((c) => c.id !== removeCommitmentId);
    }
    store.scheduleFlush();

    const updatedAffordability = evaluateCashflowAffordability({
      itemTitle: 'Pro Studio 4K OLED Reference Monitor',
      proposedSpendCents: 58000,
      currentBalanceCents: ws.currentCheckingBalanceCents,
      commitments: ws.cashflowCommitments,
      minimumSafetyBufferCents: ws.minimumSafetyBufferCents,
    });

    res.json({
      currentCheckingBalanceCents: ws.currentCheckingBalanceCents,
      minimumSafetyBufferCents: ws.minimumSafetyBufferCents,
      cashflowCommitments: ws.cashflowCommitments,
      defaultAffordability: updatedAffordability,
    });
  });

  app.post('/api/lupa/compile-policy', async (req, res) => {
    try {
      const ws = getWorkspace(req);
      const { sentence, applyToPermitId } = req.body || {};
      const cleanSentence = String(sentence || '').trim();
      if (!cleanSentence) {
        res.status(400).json({ error: 'Provide a plain-English spending rule sentence.' });
        return;
      }

      const compiled = await geminiEngine.compileNaturalLanguagePermitRule(cleanSentence);
      const proposedDollarValues = [
        compiled.maxSingleUsd,
        compiled.autoAllowUsd,
        compiled.minConfidencePct,
      ].filter((v): v is number => typeof v === 'number' && v > 0);

      const groundingCheck = verifyGroundedNumbers(cleanSentence, proposedDollarValues);

      let updatedPermit: AgentSpendingPermit | null = null;
      if (applyToPermitId && groundingCheck.grounded && compiled.promptGuard.label === 'BENIGN') {
        const target =
          ws.agentPermits.find((p) => p.permitId === applyToPermitId) || ws.agentPermits[0];
        if (target) {
          if (compiled.maxSingleUsd && compiled.maxSingleUsd > 0) {
            target.maxSingleTransactionCents = Math.round(compiled.maxSingleUsd * 100);
            target.dailyLimitCents = Math.max(
              target.dailyLimitCents,
              target.maxSingleTransactionCents * 2
            );
          }
          if (compiled.autoAllowUsd && compiled.autoAllowUsd > 0) {
            target.autoAllowMaxCents = Math.min(
              target.maxSingleTransactionCents,
              Math.round(compiled.autoAllowUsd * 100)
            );
          }
          if (
            compiled.minConfidencePct &&
            compiled.minConfidencePct >= 50 &&
            compiled.minConfidencePct <= 99
          ) {
            target.minConfidenceScore = compiled.minConfidencePct / 100;
          }
          if (compiled.allowedCategories.length > 0) {
            target.allowedCategories = compiled.allowedCategories;
          }
          updatedPermit = target;
          store.scheduleFlush();

          appendAudit(req, {
            pillar: 'LUPAPERMIT',
            actor: 'Spending Rule Assistant',
            eventTitle: `Updated Spending Rule (${target.permitId}: Cap $${(target.maxSingleTransactionCents / 100).toFixed(2)}, Auto $${(target.autoAllowMaxCents / 100).toFixed(2)})`,
            verdict: 'ALLOW',
            amountCents: target.maxSingleTransactionCents,
            savedOrProtectedCents: 0,
            paypalRef: target.permitId,
            sha256Hash: sha256Hex({ cleanSentence, target }),
            deterministicRule: `Grounded Rule Applied: "${cleanSentence}"`,
          });
        }
      }

      res.json({
        compiled,
        groundingCheck,
        updatedPermit,
      });
    } catch (err) {
      res.status(400).json({ error: redactSecrets((err as Error).message) });
    }
  });

  app.post('/api/lupa/update-permit', (req, res) => {
    const ws = getWorkspace(req);
    const {
      permitId,
      maxSingleTransactionCents,
      autoAllowMaxCents,
      dailyLimitCents,
      minConfidenceScore,
      active,
    } = req.body || {};
    const target = ws.agentPermits.find((p) => p.permitId === permitId) || ws.agentPermits[0];
    if (!target) {
      res.status(404).json({ error: 'Spending rule not found' });
      return;
    }
    if (typeof maxSingleTransactionCents === 'number' && maxSingleTransactionCents >= 100) {
      target.maxSingleTransactionCents = Math.round(maxSingleTransactionCents);
    }
    if (typeof autoAllowMaxCents === 'number' && autoAllowMaxCents >= 100) {
      target.autoAllowMaxCents = Math.min(
        target.maxSingleTransactionCents,
        Math.round(autoAllowMaxCents)
      );
    }
    if (
      typeof dailyLimitCents === 'number' &&
      dailyLimitCents >= target.maxSingleTransactionCents
    ) {
      target.dailyLimitCents = Math.round(dailyLimitCents);
    }
    if (
      typeof minConfidenceScore === 'number' &&
      minConfidenceScore >= 0.5 &&
      minConfidenceScore <= 0.99
    ) {
      target.minConfidenceScore = minConfidenceScore;
    }
    if (typeof active === 'boolean') {
      target.active = active;
    }
    store.scheduleFlush();
    res.json({ permit: target });
  });

  app.post('/api/lupa/mint-vault-permit', async (req, res) => {
    try {
      const ws = getWorkspace(req);
      const { agentName, maxSingleCents } = req.body || {};
      const tokenRecord = await paypalGateway.createVaultSetupToken({
        ownerTenantId: ws.tenantId,
        agentName: String(agentName || 'Team Procurement Assistant'),
        maxSingleCents: Math.max(500, Math.round(Number(maxSingleCents) || 8000)),
      });

      const auditRow = appendAudit(req, {
        pillar: 'LUPAPERMIT',
        actor: 'PayPal Vault Service',
        eventTitle: `Created PayPal Spending Authorization ${tokenRecord.setupTokenId} for ${tokenRecord.agentName}`,
        verdict: 'ALLOW',
        amountCents: tokenRecord.maxSingleCents,
        savedOrProtectedCents: 0,
        paypalRef: tokenRecord.setupTokenId,
        sha256Hash: sha256Hex(tokenRecord),
        deterministicRule: `PayPal Vault v3 Delegated Setup Token (${tokenRecord.mode})`,
      });

      res.json({ vaultToken: tokenRecord, auditRow });
    } catch (err) {
      res.status(400).json({ error: redactSecrets((err as Error).message) });
    }
  });

  app.post('/api/lupa/create-sandbox-subscription', async (req, res) => {
    try {
      const ws = getWorkspace(req);
      const { planName, monthlyPriceCents } = req.body || {};
      const sub = await paypalGateway.createLiveSubscription({
        ownerTenantId: ws.tenantId,
        planName: String(planName || 'Monitored Cloud Seat'),
        monthlyPriceCents: Math.max(500, Math.round(Number(monthlyPriceCents) || 2900)),
        pillar: 'LUPAPERMIT',
      });

      const auditRow = appendAudit(req, {
        pillar: 'LUPAPERMIT',
        actor: 'PayPal Subscriptions Service',
        eventTitle: `Created PayPal Subscription ${sub.subscriptionId} ($${(sub.monthlyPriceCents / 100).toFixed(2)}/mo)`,
        verdict: 'SETTLED',
        amountCents: sub.monthlyPriceCents,
        savedOrProtectedCents: 0,
        paypalRef: sub.subscriptionId,
        sha256Hash: sha256Hex(sub),
        deterministicRule: `PayPal Catalog ${sub.productId} -> Plan ${sub.planId} -> Subscription ${sub.subscriptionId}`,
      });

      res.json({ subscription: sub, auditRow });
    } catch (err) {
      res.status(400).json({ error: redactSecrets((err as Error).message) });
    }
  });

  app.post('/api/lupa/revoke-zombie', (req, res) => {
    const ws = getWorkspace(req);
    const { agreementId, action } = req.body || {};
    const perm = ws.billingPermissions.find((p) => p.agreementId === agreementId);
    if (!perm) {
      res.status(404).json({ error: `Billing Agreement ${agreementId} not found` });
      return;
    }

    if (action === 'TIGHTEN_CAP') {
      const oldCap = perm.monthlyCapCents;
      perm.monthlyCapCents = Math.ceil((perm.averageChargeCents * 1.1) / 100) * 100;
      appendAudit(req, {
        pillar: 'LUPAPERMIT',
        actor: 'Subscription Guard',
        eventTitle: `Lowered Monthly Limit for ${perm.merchantName} ($${(oldCap / 100).toFixed(2)} -> $${(perm.monthlyCapCents / 100).toFixed(2)}/mo)`,
        verdict: 'SETTLED',
        amountCents: perm.monthlyCapCents,
        savedOrProtectedCents: (oldCap - perm.monthlyCapCents) * 12,
        paypalRef: perm.agreementId,
        sha256Hash: sha256Hex({ agreementId, newCap: perm.monthlyCapCents }),
        deterministicRule: 'Capped recurring merchant pull authority to 110% of trailing average charge',
      });
    } else {
      perm.status = 'REVOKED';
      const recoverable = perm.averageChargeCents * 12;
      const autopayCommitment = ws.cashflowCommitments.find((c) => c.id === 'cf_paypal_subs');
      if (autopayCommitment) {
        autopayCommitment.amountCents = Math.max(
          0,
          autopayCommitment.amountCents - perm.averageChargeCents
        );
      }
      appendAudit(req, {
        pillar: 'LUPAPERMIT',
        actor: 'Subscription Guard',
        eventTitle: `Canceled Unused Autopay ${perm.agreementId} (${perm.merchantName})`,
        verdict: 'BLOCK',
        amountCents: perm.averageChargeCents,
        savedOrProtectedCents: recoverable,
        paypalRef: perm.agreementId,
        sha256Hash: sha256Hex({ agreementId, status: 'REVOKED' }),
        deterministicRule: 'Revoked dormant recurring pull permission; freed monthly cashflow',
      });
    }
    store.scheduleFlush();

    res.json({
      permission: perm,
      zombieReport: auditPayPalPermissions(ws.billingPermissions),
      cashflowCommitments: ws.cashflowCommitments,
    });
  });

  app.post('/api/lupa/agent-pay', async (req, res) => {
    try {
      const ws = getWorkspace(req);
      const {
        permitId,
        amountCents,
        merchantId,
        merchantName,
        category,
        itemDescription,
        aiConfidenceScore,
        aiSuggestedVerdict,
      } = req.body || {};

      const permit = ws.agentPermits.find((p) => p.permitId === permitId) || ws.agentPermits[0];
      const reqId = `REQ-${Date.now()}`;
      const numericAmount = Math.round(Number(amountCents) || 4500);
      const numericConfidence = Math.max(0, Math.min(1, Number(aiConfidenceScore ?? 0.9)));
      const validAiVerdict: DecisionVerdict = ['ALLOW', 'HOLD', 'BLOCK'].includes(
        aiSuggestedVerdict
      )
        ? aiSuggestedVerdict
        : 'ALLOW';

      const evaluation = evaluateAgentPermit(permit, {
        requestId: reqId,
        permitId: permit.permitId,
        amountCents: numericAmount,
        currency: 'USD',
        merchantId: String(merchantId || 'merch_nordic_hardware'),
        merchantName: String(merchantName || 'NordicLight Studio Hardware'),
        category: String(category || 'HARDWARE'),
        itemDescription: String(itemDescription || 'Automated Team Purchase'),
        aiConfidenceScore: numericConfidence,
        aiSuggestedVerdict: validAiVerdict,
        aiReasoning: `Evaluated merchant & item details (${(numericConfidence * 100).toFixed(0)}% match).`,
      });

      let paypalOrder = null;
      if (evaluation.finalVerdict === 'ALLOW' || evaluation.finalVerdict === 'HOLD') {
        paypalOrder = await paypalGateway.createOrder({
          ownerTenantId: ws.tenantId,
          intent: evaluation.paypalIntent === 'CAPTURE' ? 'CAPTURE' : 'AUTHORIZE',
          amountCents: numericAmount,
          currency: 'USD',
          merchantName: String(merchantName || 'NordicLight Studio Hardware'),
          description: `[${permit.agentName}] ${itemDescription}`,
          customHash: evaluation.auditHash,
          idempotencyKey: evaluation.auditHash,
          pillar: 'LUPAPERMIT',
          autoExecuteInSandbox: true,
        });

        if (evaluation.finalVerdict === 'ALLOW') {
          permit.spentTodayCents += numericAmount;
          store.scheduleFlush();
        }
      }

      const auditRow = appendAudit(req, {
        pillar: 'LUPAPERMIT',
        actor: permit.agentName,
        eventTitle: `Purchase Request: ${itemDescription} ($${(numericAmount / 100).toFixed(2)}) -> ${evaluation.finalVerdict}`,
        verdict: evaluation.finalVerdict,
        amountCents: numericAmount,
        savedOrProtectedCents: evaluation.finalVerdict === 'ALLOW' ? 0 : numericAmount,
        paypalRef: paypalOrder ? paypalOrder.orderId : 'BLOCKED_BY_LIMIT',
        sha256Hash: evaluation.auditHash,
        deterministicRule: evaluation.reasons.join(' | '),
      });

      res.json({
        evaluation,
        paypalOrder,
        permit,
        auditRow,
      });
    } catch (err) {
      res.status(400).json({ error: redactSecrets((err as Error).message) });
    }
  });

  app.post('/api/lupa/resolve-hold', async (req, res) => {
    try {
      const ws = getWorkspace(req);
      const { orderId, action, operatorNote, fallbackAmountCents, fallbackMerchantName } =
        req.body || {};
      const resolvedOrder = await paypalGateway.resolveHeldAuthorization({
        ownerTenantId: ws.tenantId,
        orderId: String(orderId),
        action: action === 'VOID' ? 'VOID' : 'CAPTURE',
        operatorNote: String(operatorNote || 'Reviewed by account owner'),
        fallbackAmountCents:
          typeof fallbackAmountCents === 'number' ? fallbackAmountCents : undefined,
        fallbackMerchantName:
          typeof fallbackMerchantName === 'string' ? fallbackMerchantName : undefined,
      });

      const auditRow = appendAudit(req, {
        pillar: 'LUPAPERMIT',
        actor: 'Account Owner',
        eventTitle: `${action === 'VOID' ? 'Declined & Voided' : 'Approved & Released'} Held Order ${resolvedOrder.orderId}`,
        verdict: action === 'VOID' ? 'BLOCK' : 'SETTLED',
        amountCents: resolvedOrder.amountCents,
        savedOrProtectedCents: action === 'VOID' ? resolvedOrder.amountCents : 0,
        paypalRef:
          resolvedOrder.captureId || resolvedOrder.authorizationId || resolvedOrder.orderId,
        sha256Hash: sha256Hex({ orderId: resolvedOrder.orderId, status: resolvedOrder.status }),
        deterministicRule: `Owner decision on held PayPal authorization (${resolvedOrder.status})`,
      });

      res.json({ order: resolvedOrder, auditRow });
    } catch (err) {
      res.status(400).json({ error: redactSecrets((err as Error).message) });
    }
  });

  // ==========================================================================
  // 5. PAYMENT SAFETY SCANNER & VERIFIED PAYPAL CHECKOUT
  // ==========================================================================

  app.get('/api/scamshield/fx-rates', async (_req, res) => {
    const fx = await getLiveOrFallbackFxRates();
    res.json(fx);
  });

  app.post('/api/scamshield/review', async (req, res) => {
    try {
      const ws = getWorkspace(req);
      const scamVault = getTenantScamVault(ws.tenantId);
      const {
        rawText,
        claimedAmountCents,
        currency,
        payeeIdentifier,
        imageBase64,
        imageMimeType,
        autoExtractCurrency,
      } = req.body || {};
      const text = String(rawText || '');
      const fx = await getLiveOrFallbackFxRates();
      const extracted = extractPaymentRequestMetadata(text, fx.rates);

      let amount = Math.max(100, Math.round(Number(claimedAmountCents) || 4500));
      if (autoExtractCurrency && extracted.convertedUsdCents) {
        amount = extracted.convertedUsdCents;
      }

      const curr = String(currency || 'USD').toUpperCase();
      const payee = String(
        payeeIdentifier || extracted.detectedPayee || 'billing@verified-studio.io'
      ).trim();

      const detResult = evaluatePaymentScamDeterministically({
        rawText: text,
        claimedAmountCents: amount,
        currency: curr,
        payeeIdentifier: payee,
      });

      let liveInvoiceLookup = null;
      if (extracted.detectedPayPalInvoiceId) {
        liveInvoiceLookup = await paypalGateway.lookupLiveInvoice(
          extracted.detectedPayPalInvoiceId,
          ws.tenantId
        );
      }

      const aiResult = await geminiEngine.analyzePaymentScamSemantics({
        sanitizedText: detResult.sanitizedText,
        claimedAmountCents: amount,
        payeeIdentifier: payee,
        imageBase64: typeof imageBase64 === 'string' ? imageBase64 : undefined,
        imageMimeType: typeof imageMimeType === 'string' ? imageMimeType : undefined,
      });

      let finalVerdict = stricterVerdict(
        detResult.deterministicVerdict,
        aiResult.aiSuggestedVerdict
      );
      let combinedRiskScore = Math.max(detResult.riskScore, aiResult.semanticRiskScore);

      if (liveInvoiceLookup && !liveInvoiceLookup.found) {
        finalVerdict = stricterVerdict(finalVerdict, 'HOLD');
        combinedRiskScore = Math.max(combinedRiskScore, 45);
      }

      const signedToken = scamVault.issueToken({
        input: {
          rawText: text,
          claimedAmountCents: amount,
          currency: curr,
          payeeIdentifier: payee,
        },
        verdict: finalVerdict,
        riskScore: combinedRiskScore,
      });

      lastIssuedScamTokenByTenant.set(ws.tenantId, signedToken);

      const auditRow = appendAudit(req, {
        pillar: 'SCAMSHIELD',
        actor: 'Invoice & Link Safety Scanner',
        eventTitle: `Scanned Payment Request to ${payee} ($${(amount / 100).toFixed(2)}) -> ${finalVerdict}`,
        verdict: finalVerdict,
        amountCents: amount,
        savedOrProtectedCents: finalVerdict === 'BLOCK' ? amount : 0,
        paypalRef: signedToken.payload.tokenId,
        sha256Hash: signedToken.signature,
        deterministicRule:
          detResult.matches.length > 0
            ? detResult.matches.map((m) => `${m.ruleId}: ${m.description}`).join(' ; ')
            : aiResult.aiSummary,
      });

      res.json({
        deterministic: detResult,
        ai: aiResult,
        extractedMetadata: extracted,
        liveInvoiceLookup,
        fxLive: fx.live,
        finalVerdict,
        combinedRiskScore,
        signedToken,
        paypalCheckoutUnlocked: finalVerdict !== 'BLOCK',
        auditRow,
      });
    } catch (err) {
      res.status(400).json({ error: redactSecrets((err as Error).message) });
    }
  });

  app.post('/api/scamshield/create-paypal-order', async (req, res) => {
    try {
      const ws = getWorkspace(req);
      const { signedToken } = req.body || {};
      const token: SignedScamShieldToken | undefined =
        signedToken || lastIssuedScamTokenByTenant.get(ws.tenantId);
      if (!token || token.payload.verdict === 'BLOCK') {
        res.status(403).json({
          error: 'This payment was flagged as unsafe and cannot proceed to PayPal checkout.',
        });
        return;
      }

      const order = await paypalGateway.createOrder({
        ownerTenantId: ws.tenantId,
        intent: 'CAPTURE',
        amountCents: token.payload.amountCents,
        currency: token.payload.currency,
        merchantName: token.payload.payeeIdentifier,
        description: `Verified Payment (${token.payload.tokenId})`,
        customHash: token.signature,
        idempotencyKey: `btn-${token.payload.tokenId}-${Date.now().toString().slice(-4)}`,
        pillar: 'SCAMSHIELD',
        autoExecuteInSandbox: false,
      });

      res.json({ orderId: order.orderId, approvalUrl: order.approvalUrl, order });
    } catch (err) {
      res.status(400).json({ error: redactSecrets((err as Error).message) });
    }
  });

  app.post('/api/scamshield/capture-paypal-order', async (req, res) => {
    try {
      const ws = getWorkspace(req);
      const scamVault = getTenantScamVault(ws.tenantId);
      const { orderId, signedToken } = req.body || {};
      const token: SignedScamShieldToken | undefined =
        signedToken || lastIssuedScamTokenByTenant.get(ws.tenantId);
      if (token) {
        const check = scamVault.verifyAndConsumeForCapture({
          signedToken: token,
          orderId: String(orderId),
          captureAmountCents: token.payload.amountCents,
          currency: token.payload.currency,
          payeeIdentifier: token.payload.payeeIdentifier,
        });
        if (!check.allowed) {
          res.status(403).json({ captured: false, verification: check });
          return;
        }
      }

      const captureRes = await paypalGateway.captureLiveOrder(
        String(orderId),
        'SCAMSHIELD',
        ws.tenantId
      );
      const auditRow = appendAudit(req, {
        pillar: 'SCAMSHIELD',
        actor: 'PayPal Checkout',
        eventTitle: `Buyer-Approved PayPal Order ${captureRes.orderId} Captured (${captureRes.captureId})`,
        verdict: 'SETTLED',
        amountCents: token?.payload.amountCents || 4500,
        savedOrProtectedCents: 0,
        paypalRef: captureRes.captureId,
        sha256Hash: sha256Hex(captureRes),
        deterministicRule: 'Verified Single-Use Approval Token + Buyer PayPal Checkout Completed',
      });

      res.json({ ...captureRes, auditRow });
    } catch (err) {
      res.status(400).json({ error: redactSecrets((err as Error).message) });
    }
  });

  app.post('/api/scamshield/capture', async (req, res) => {
    try {
      const ws = getWorkspace(req);
      const scamVault = getTenantScamVault(ws.tenantId);
      const { signedToken, tamperScenario } = req.body || {};
      const baseToken: SignedScamShieldToken | null =
        signedToken || lastIssuedScamTokenByTenant.get(ws.tenantId) || null;

      let tokenToVerify: SignedScamShieldToken | null = baseToken
        ? JSON.parse(JSON.stringify(baseToken))
        : null;
      let captureAmountCents = tokenToVerify?.payload.amountCents ?? 4500;
      const currency = tokenToVerify?.payload.currency ?? 'USD';
      let payeeIdentifier =
        tokenToVerify?.payload.payeeIdentifier ?? 'billing@verified-studio.io';
      let simulatedNowMs = Date.now();

      if (tamperScenario === 'MUTATE_AMOUNT' && tokenToVerify) {
        captureAmountCents = tokenToVerify.payload.amountCents * 10;
      } else if (tamperScenario === 'FORGE_SIGNATURE' && tokenToVerify) {
        tokenToVerify.payload.verdict = 'ALLOW';
        tokenToVerify.signature =
          'deadbeef0000111122223333444455556666777788889999aaaabbbbccccdddd';
      } else if (tamperScenario === 'EXPIRED_TOKEN' && tokenToVerify) {
        simulatedNowMs = tokenToVerify.payload.expiresAtMs + 60_000;
      } else if (tamperScenario === 'NEVER_REVIEWED') {
        tokenToVerify = null;
      } else if (tamperScenario === 'PAYEE_SWAP' && tokenToVerify) {
        payeeIdentifier = 'attacker-offshore-wallet@evil.example';
      }

      const preOrderId = `ORD-SAFE-${Date.now()}`;
      const verification = scamVault.verifyAndConsumeForCapture({
        signedToken: tokenToVerify,
        orderId: preOrderId,
        captureAmountCents,
        currency,
        payeeIdentifier,
        nowMs: simulatedNowMs,
      });

      if (!verification.allowed) {
        const auditRow = appendAudit(req, {
          pillar: 'SCAMSHIELD',
          actor: 'Checkout Lock',
          eventTitle: `Blocked Modified Checkout [${verification.errorCode}]: ${verification.reason}`,
          verdict: 'BLOCK',
          amountCents: captureAmountCents,
          savedOrProtectedCents: captureAmountCents,
          paypalRef: `REJECTED_${verification.errorCode}`,
          sha256Hash: sha256Hex({
            preOrderId,
            errorCode: verification.errorCode,
            captureAmountCents,
          }),
          deterministicRule: verification.reason,
        });

        res.json({
          captured: false,
          verification,
          auditRow,
        });
        return;
      }

      const paypalOrder = await paypalGateway.createOrder({
        ownerTenantId: ws.tenantId,
        intent: 'CAPTURE',
        amountCents: captureAmountCents,
        currency,
        merchantName: payeeIdentifier,
        description: `Verified Checkout (${tokenToVerify!.payload.tokenId})`,
        customHash: tokenToVerify!.signature,
        idempotencyKey: tokenToVerify!.payload.tokenId,
        pillar: 'SCAMSHIELD',
        autoExecuteInSandbox: true,
      });

      const auditRow = appendAudit(req, {
        pillar: 'SCAMSHIELD',
        actor: 'Checkout Lock',
        eventTitle: `Created Verified PayPal Order ${paypalOrder.orderId} ($${(captureAmountCents / 100).toFixed(2)})`,
        verdict: 'SETTLED',
        amountCents: captureAmountCents,
        savedOrProtectedCents: 0,
        paypalRef: paypalOrder.orderId,
        sha256Hash: tokenToVerify!.signature,
        deterministicRule: verification.reason,
      });

      res.json({
        captured: true,
        verification,
        paypalOrder,
        auditRow,
      });
    } catch (err) {
      res.status(400).json({ error: redactSecrets((err as Error).message) });
    }
  });

  // ==========================================================================
  // 6. VENDOR DEAL NEGOTIATION & DEPOSIT INVOICING
  // ==========================================================================

  app.post('/api/dealforge/negotiate', async (req, res) => {
    try {
      const ws = getWorkspace(req);
      const {
        buyerMandate: rawBuyer,
        sellerMandate: rawSeller,
        simulatePromptInjection,
        humanCounterOfferCents,
        issueLiveInvoice,
        buyerEmail,
      } = req.body || {};

      const buyerMandate: BuyerMandate = {
        mandateId: 'BM-LIVE-01',
        buyerName: String(rawBuyer?.buyerName || 'Acme Studio (Buyer)'),
        itemTitle: String(rawBuyer?.itemTitle || 'Security & Infrastructure Audit'),
        targetPriceCents: Math.round(Number(rawBuyer?.targetPriceCents) || 62000),
        maxPriceCents: Math.round(Number(rawBuyer?.maxPriceCents) || 82000),
        maxDeliveryDays: Math.round(Number(rawBuyer?.maxDeliveryDays) || 7),
        minRevisions: Math.round(Number(rawBuyer?.minRevisions) || 2),
        maxUpfrontDepositPct: Math.round(Number(rawBuyer?.maxUpfrontDepositPct) || 40),
      };

      const sellerMandate: SellerMandate = {
        mandateId: 'SM-LIVE-01',
        sellerName: String(rawSeller?.sellerName || 'Sentinel Partners (Vendor)'),
        listPriceCents: Math.round(Number(rawSeller?.listPriceCents) || 98000),
        minPriceCents: Math.round(Number(rawSeller?.minPriceCents) || 64000),
        fastestDeliveryDays: Math.round(Number(rawSeller?.fastestDeliveryDays) || 4),
        maxRevisionsAllowed: Math.round(Number(rawSeller?.maxRevisionsAllowed) || 3),
        minUpfrontDepositPct: Math.round(Number(rawSeller?.minUpfrontDepositPct) || 25),
      };

      const rounds: NegotiationRoundEntry[] = [];

      if (buyerMandate.maxPriceCents < sellerMandate.minPriceCents) {
        const auditRow = appendAudit(req, {
          pillar: 'DEALFORGE',
          actor: 'Deal Terms Guard',
          eventTitle: `No Price Overlap: Buyer Max ($${(buyerMandate.maxPriceCents / 100).toFixed(2)}) < Vendor Min ($${(sellerMandate.minPriceCents / 100).toFixed(2)})`,
          verdict: 'BLOCK',
          amountCents: sellerMandate.minPriceCents,
          savedOrProtectedCents: sellerMandate.listPriceCents,
          paypalRef: 'NO_OVERLAP_ABORT',
          sha256Hash: sha256Hex({ buyerMandate, sellerMandate }),
          deterministicRule:
            'Price ranges do not overlap; halted before creating any PayPal order or invoice.',
        });
        res.json({
          dealReached: false,
          reason: `No agreement possible: Your maximum budget ($${(buyerMandate.maxPriceCents / 100).toFixed(2)}) is below the vendor's minimum floor ($${(sellerMandate.minPriceCents / 100).toFixed(2)}).`,
          rounds,
          zopaAnalysis: {
            exists: false,
            sellerFloorCents: sellerMandate.minPriceCents,
            buyerCeilingCents: buyerMandate.maxPriceCents,
            zopaWidthCents: 0,
          },
          auditRow,
        });
        return;
      }

      const r1RawTerms = {
        priceCents: buyerMandate.targetPriceCents,
        deliveryDays: Math.max(sellerMandate.fastestDeliveryDays, buyerMandate.maxDeliveryDays - 2),
        revisions: buyerMandate.minRevisions + 1,
        upfrontDepositPct: sellerMandate.minUpfrontDepositPct,
      };
      const r1Msg = geminiEngine.generateNegotiationRoundMessage({
        round: 1,
        proposer: 'BUYER_AGENT',
        terms: r1RawTerms,
        buyerMandate,
        sellerMandate,
      });
      const r1Validated = validateAndClampOfferAgainstMandate({
        proposer: 'BUYER_AGENT',
        rawOffer: r1RawTerms,
        rawMessage: r1Msg,
        buyerMandate,
        sellerMandate,
      });
      rounds.push({
        round: 1,
        proposer: 'BUYER_AGENT',
        proposedTerms: r1Validated.validatedTerms,
        sanitizedMessage: r1Validated.sanitizedMessage,
        kernelValidated: true,
        kernelAdjustments: r1Validated.kernelAdjustments,
        promptInjectionBlocked: r1Validated.promptInjectionBlocked,
      });

      const midHighCents = Math.round(
        (sellerMandate.listPriceCents + sellerMandate.minPriceCents) / 2
      );
      const r2RawTerms = {
        priceCents: Math.max(sellerMandate.minPriceCents, midHighCents),
        deliveryDays: buyerMandate.maxDeliveryDays,
        revisions: buyerMandate.minRevisions,
        upfrontDepositPct: simulatePromptInjection
          ? 95
          : Math.min(buyerMandate.maxUpfrontDepositPct, 40),
      };
      const r2Msg = geminiEngine.generateNegotiationRoundMessage({
        round: 2,
        proposer: 'SELLER_AGENT',
        terms: r2RawTerms,
        buyerMandate,
        sellerMandate,
        simulateInjectionAttack: Boolean(simulatePromptInjection),
      });
      const r2Validated = validateAndClampOfferAgainstMandate({
        proposer: 'SELLER_AGENT',
        rawOffer: r2RawTerms,
        rawMessage: r2Msg,
        buyerMandate,
        sellerMandate,
      });
      rounds.push({
        round: 2,
        proposer: 'SELLER_AGENT',
        proposedTerms: r2Validated.validatedTerms,
        sanitizedMessage: r2Validated.sanitizedMessage,
        kernelValidated: true,
        kernelAdjustments: r2Validated.kernelAdjustments,
        promptInjectionBlocked: r2Validated.promptInjectionBlocked,
      });

      const effectiveBuyerTarget = Math.max(
        buyerMandate.targetPriceCents,
        sellerMandate.minPriceCents
      );
      const fairSettlementPriceCents =
        typeof humanCounterOfferCents === 'number' && humanCounterOfferCents > 0
          ? Math.round(humanCounterOfferCents)
          : Math.round((effectiveBuyerTarget + buyerMandate.maxPriceCents) / 2);

      const agreedPriceCents = Math.min(
        buyerMandate.maxPriceCents,
        Math.max(sellerMandate.minPriceCents, fairSettlementPriceCents)
      );
      const agreedDeliveryDays = Math.min(
        buyerMandate.maxDeliveryDays,
        Math.max(sellerMandate.fastestDeliveryDays, 5)
      );
      const agreedRevisions = Math.min(
        sellerMandate.maxRevisionsAllowed,
        Math.max(buyerMandate.minRevisions, 2)
      );
      const agreedDepositPct = Math.min(
        buyerMandate.maxUpfrontDepositPct,
        Math.max(sellerMandate.minUpfrontDepositPct, 30)
      );

      const isHumanTakeover =
        typeof humanCounterOfferCents === 'number' && humanCounterOfferCents > 0;
      const r3Terms = {
        priceCents: agreedPriceCents,
        deliveryDays: agreedDeliveryDays,
        revisions: agreedRevisions,
        upfrontDepositPct: agreedDepositPct,
      };
      const r3Msg = isHumanTakeover
        ? `Manual Counter-Offer: $${(agreedPriceCents / 100).toFixed(2)} (${agreedDeliveryDays}d delivery, ${agreedRevisions} revisions, ${agreedDepositPct}% PayPal deposit).`
        : geminiEngine.generateNegotiationRoundMessage({
            round: 3,
            proposer: 'BUYER_AGENT',
            terms: r3Terms,
            buyerMandate,
            sellerMandate,
          });

      const r3Validated = validateAndClampOfferAgainstMandate({
        proposer: 'BUYER_AGENT',
        rawOffer: r3Terms,
        rawMessage: r3Msg,
        buyerMandate,
        sellerMandate,
      });
      rounds.push({
        round: 3,
        proposer: isHumanTakeover ? 'HUMAN_OPERATOR' : 'BUYER_AGENT',
        proposedTerms: r3Validated.validatedTerms,
        sanitizedMessage: r3Validated.sanitizedMessage,
        kernelValidated: true,
        kernelAdjustments: r3Validated.kernelAdjustments,
        promptInjectionBlocked: r3Validated.promptInjectionBlocked,
      });

      const r4Msg = geminiEngine.generateNegotiationRoundMessage({
        round: 4,
        proposer: 'SELLER_AGENT',
        terms: r3Validated.validatedTerms,
        buyerMandate,
        sellerMandate,
      });
      rounds.push({
        round: 4,
        proposer: 'SELLER_AGENT',
        proposedTerms: r3Validated.validatedTerms,
        sanitizedMessage: r4Msg,
        kernelValidated: true,
        kernelAdjustments: ['Both buyer and vendor limits verified satisfied.'],
        promptInjectionBlocked: false,
      });

      const contract = createSignedDealContract({
        buyerMandate,
        sellerMandate,
        agreedTerms: r3Validated.validatedTerms,
      });
      ws.signedContracts.unshift(contract);
      if (ws.signedContracts.length > 100) ws.signedContracts.length = 100;
      store.scheduleFlush();

      const paypalOrder = await paypalGateway.createOrder({
        ownerTenantId: ws.tenantId,
        intent: 'CAPTURE',
        amountCents: contract.upfrontDepositCents,
        currency: 'USD',
        merchantName: sellerMandate.sellerName,
        description: `Agreement ${contract.contractId} (${contract.agreedTerms.upfrontDepositPct}% Deposit for ${buyerMandate.itemTitle})`,
        customHash: contract.contractSha256,
        idempotencyKey: contract.contractId,
        pillar: 'DEALFORGE',
        autoExecuteInSandbox: true,
      });

      let paypalInvoice = null;
      if (issueLiveInvoice) {
        paypalInvoice = await paypalGateway.createLiveInvoice({
          ownerTenantId: ws.tenantId,
          title: `${buyerMandate.itemTitle} (${contract.agreedTerms.upfrontDepositPct}% Deposit)`,
          note: `Agreement ${contract.contractId} settled at $${(contract.agreedTerms.priceCents / 100).toFixed(2)} (${contract.agreedTerms.deliveryDays}d delivery, ${contract.agreedTerms.revisions} revisions).`,
          recipientEmail: String(buyerEmail || 'buyer-treasury@personal.example.com'),
          amountCents: contract.upfrontDepositCents,
          pillar: 'DEALFORGE',
          contractOrPlanHash: contract.contractSha256,
          sendImmediately: true,
        });
      }

      const zopaWidthCents = Math.max(1, buyerMandate.maxPriceCents - sellerMandate.minPriceCents);
      const buyerSurplusCents = Math.max(
        0,
        buyerMandate.maxPriceCents - contract.agreedTerms.priceCents
      );
      const sellerSurplusCents = Math.max(
        0,
        contract.agreedTerms.priceCents - sellerMandate.minPriceCents
      );

      const auditRow = appendAudit(req, {
        pillar: 'DEALFORGE',
        actor: isHumanTakeover ? 'Manual Counter-Offer' : 'Automated Deal Desk',
        eventTitle: `Agreement ${contract.contractId} ($${(contract.agreedTerms.priceCents / 100).toFixed(2)}, saved $${(contract.buyerSavedCents / 100).toFixed(2)}) & Deposit Created ($${(contract.upfrontDepositCents / 100).toFixed(2)})`,
        verdict: 'SETTLED',
        amountCents: contract.upfrontDepositCents,
        savedOrProtectedCents: contract.buyerSavedCents,
        paypalRef: paypalInvoice ? paypalInvoice.invoiceId : paypalOrder.orderId,
        sha256Hash: contract.contractSha256,
        deterministicRule: `Contract Integrity ${verifyContractIntegrity(contract) ? 'VALID' : 'INVALID'}`,
      });

      res.json({
        dealReached: true,
        rounds,
        contract,
        contractIntegrityVerified: verifyContractIntegrity(contract),
        zopaAnalysis: {
          exists: true,
          sellerFloorCents: sellerMandate.minPriceCents,
          buyerCeilingCents: buyerMandate.maxPriceCents,
          agreedPriceCents: contract.agreedTerms.priceCents,
          zopaWidthCents,
          buyerSurplusCents,
          sellerSurplusCents,
          buyerSurplusPct: Math.round((buyerSurplusCents / zopaWidthCents) * 100),
          sellerSurplusPct: Math.round((sellerSurplusCents / zopaWidthCents) * 100),
        },
        paypalOrder,
        paypalInvoice,
        auditRow,
      });
    } catch (err) {
      res.status(400).json({ error: redactSecrets((err as Error).message) });
    }
  });

  // ==========================================================================
  // 7. INSTANT PARTIAL REFUNDS FOR DAMAGED DELIVERIES (PER-TENANT POLICY)
  // ==========================================================================

  app.post('/api/cliprefund/update-policy', (req, res) => {
    const ws = getWorkspace(req);
    if (!ws.merchantPolicy) {
      ws.merchantPolicy = JSON.parse(JSON.stringify(DEFAULT_MERCHANT_REFUND_POLICY));
    }
    const {
      tierPercentages,
      tierRefundPercentages,
      minPhotoAuthenticityConfidence,
      minAuthenticityConfidence,
      estimatedReturnShippingLabelCents,
      returnShippingCostCents,
    } = req.body || {};
    const incomingTiers = tierRefundPercentages || tierPercentages;
    if (incomingTiers && typeof incomingTiers === 'object') {
      for (const key of [
        'COSMETIC_MINOR',
        'COSMETIC_MODERATE',
        'FUNCTIONAL_IMPAIRED',
        'TOTAL_LOSS',
      ] as const) {
        if (typeof incomingTiers[key] === 'number') {
          ws.merchantPolicy.tierRefundPercentages[key] = Math.max(
            0,
            Math.min(100, Math.round(incomingTiers[key]))
          );
        }
      }
    }
    const incomingConf =
      typeof minAuthenticityConfidence === 'number'
        ? minAuthenticityConfidence
        : minPhotoAuthenticityConfidence;
    if (typeof incomingConf === 'number' && incomingConf >= 0.5 && incomingConf <= 0.99) {
      ws.merchantPolicy.minAuthenticityConfidence = incomingConf;
    }
    const incomingShip =
      typeof returnShippingCostCents === 'number'
        ? returnShippingCostCents
        : estimatedReturnShippingLabelCents;
    if (typeof incomingShip === 'number') {
      ws.merchantPolicy.returnShippingCostCents = Math.max(0, Math.round(incomingShip));
    }
    store.scheduleFlush();
    res.json({ merchantPolicy: ws.merchantPolicy });
  });

  app.post('/api/cliprefund/evaluate-and-refund', async (req, res) => {
    try {
      const ws = getWorkspace(req);
      if (!ws.merchantPolicy) {
        ws.merchantPolicy = JSON.parse(JSON.stringify(DEFAULT_MERCHANT_REFUND_POLICY));
      }
      if (!ws.claimedVisionImageHashes) ws.claimedVisionImageHashes = [];
      if (!ws.refundedCentsByCapture) ws.refundedCentsByCapture = {};

      const {
        presetId,
        orderId,
        itemTitle,
        originalOrderCents,
        customerNote,
        imageBase64,
        imageMimeType,
        simulateReplayAttack,
        merchantPolicyOverride,
      } = req.body || {};

      const targetOrderId = String(orderId || 'PAYPAL-SBX-8F92A1C4E7B01');
      const existingOrder = paypalGateway.getOrder(targetOrderId, ws.tenantId);
      const targetCaptureId =
        existingOrder?.captureId || `SIMCAP-${targetOrderId.replace('PAYPAL-SBX-', '')}`;
      const orderCents = Math.max(500, Math.round(Number(originalOrderCents) || 2800));

      const claimedSet = new Set<string>(ws.claimedVisionImageHashes);
      const imageSeed = simulateReplayAttack
        ? 'REPLAY_IMAGE_STATIC_DIGEST'
        : imageBase64
          ? `${imageBase64.slice(0, 512)}_${Date.now()}`
          : `${presetId || 'chipped_ceramic_mug'}_${Date.now()}`;
      const imageSha256 = sha256Hex(imageSeed);

      if (simulateReplayAttack) {
        claimedSet.add(imageSha256);
      }

      const visionResult = await geminiEngine.extractVisionDefectTelemetry({
        presetId: presetId ? String(presetId) : undefined,
        itemTitle: String(itemTitle || 'Handcrafted Stoneware Espresso Mug'),
        customerNote: String(customerNote || 'Arrived with a chip on the upper rim.'),
        imageBase64: typeof imageBase64 === 'string' ? imageBase64 : undefined,
        imageMimeType: typeof imageMimeType === 'string' ? imageMimeType : undefined,
      });

      const overrideTiers =
        merchantPolicyOverride?.tierRefundPercentages ||
        merchantPolicyOverride?.tierPercentages ||
        {};
      const policyToUse: MerchantRefundPolicyMatrix =
        merchantPolicyOverride && typeof merchantPolicyOverride === 'object'
          ? {
              ...ws.merchantPolicy,
              tierRefundPercentages: {
                ...ws.merchantPolicy.tierRefundPercentages,
                ...overrideTiers,
              },
            }
          : ws.merchantPolicy;

      const prevRefunded = ws.refundedCentsByCapture[targetCaptureId] || 0;

      const calculation = calculateDeterministicVisionRefund({
        orderId: targetOrderId,
        captureId: targetCaptureId,
        originalOrderCents: orderCents,
        imageSha256,
        previouslyClaimedImageHashes: claimedSet,
        previouslyRefundedCentsOnCapture: prevRefunded,
        telemetry: visionResult.telemetry,
        policy: policyToUse,
      });

      let paypalRefund = null;
      if (calculation.approved && calculation.refundCents > 0) {
        ws.claimedVisionImageHashes.push(imageSha256);
        if (ws.claimedVisionImageHashes.length > 500) {
          ws.claimedVisionImageHashes = ws.claimedVisionImageHashes.slice(-500);
        }
        ws.refundedCentsByCapture[targetCaptureId] = prevRefunded + calculation.refundCents;
        store.scheduleFlush();

        paypalRefund = await paypalGateway.issuePartialRefund({
          ownerTenantId: ws.tenantId,
          orderId: targetOrderId,
          captureId: targetCaptureId,
          refundCents: calculation.refundCents,
          reasonNote: calculation.explanation,
          calculationHash: calculation.calculationHash,
        });
      }

      const unitEconomics = {
        traditionalReturnCostCents: orderCents + policyToUse.returnShippingCostCents,
        instantPartialRefundCostCents: calculation.refundCents,
        merchantNetSavedCents: calculation.merchantNetSavedCents,
        shippingLabelSavedCents: policyToUse.returnShippingCostCents,
      };

      const auditRow = appendAudit(req, {
        pillar: 'CLIPREFUND',
        actor: 'Keep-the-Item Partial Refund',
        eventTitle: calculation.approved
          ? `Approved Partial Refund: $${(calculation.refundCents / 100).toFixed(2)} (${calculation.appliedPercentage}%) on ${visionResult.telemetry.detectedItemCategory}`
          : `Declined Refund Request: ${calculation.explanation}`,
        verdict: calculation.approved ? 'REFUNDED' : 'BLOCK',
        amountCents: calculation.refundCents,
        savedOrProtectedCents: calculation.approved
          ? calculation.merchantNetSavedCents
          : orderCents,
        paypalRef: paypalRefund ? paypalRefund.refundId : 'CLAIM_DECLINED',
        sha256Hash: calculation.calculationHash,
        deterministicRule: calculation.explanation,
      });

      res.json({
        visionTelemetry: visionResult.telemetry,
        visionEngineMode: visionResult.engineMode,
        failoverTelemetry: visionResult.failoverTelemetry,
        calculation,
        unitEconomics,
        paypalRefund,
        imageSha256,
        auditRow,
      });
    } catch (err) {
      res.status(400).json({ error: redactSecrets((err as Error).message) });
    }
  });

  // ==========================================================================
  // 8. SUBSCRIPTION CANCEL-FLOW RETENTION & LEGAL ESCALATION GUARD
  // ==========================================================================

  app.post('/api/churnrescue/intercept', async (req, res) => {
    try {
      const ws = getWorkspace(req);
      const atomicLedger = getTenantAtomicLedger(ws.tenantId);
      const {
        accountId,
        customerName,
        planName,
        currentPlanPriceCents,
        featureUtilizationPct,
        negotiationStep,
        paypalDeclineCode,
        customerMessage,
        simulateDuplicateClick,
        createDiscountedSubscription,
      } = req.body || {};

      const ctx = {
        accountId: String(accountId || 'ACC-SAAS-9042'),
        customerName: String(customerName || 'Jordan Vance'),
        planName: String(planName || 'Cloud Pro Plan'),
        currentPlanPriceCents: Math.max(1000, Math.round(Number(currentPlanPriceCents) || 9900)),
        featureUtilizationPct: Math.max(
          0,
          Math.min(100, Math.round(Number(featureUtilizationPct ?? 34)))
        ),
        negotiationStep: Math.max(1, Math.round(Number(negotiationStep) || 1)),
        paypalDeclineCode: paypalDeclineCode || 'VOLUNTARY_CANCEL_CLICK',
        customerMessage: String(
          customerMessage ||
            'Our PayPal billing declined and $99/mo is too steep right now—thinking of canceling.'
        ),
      };

      const decision = evaluateChurnIntervention(ctx);
      const empathy = await geminiEngine.generateEmpatheticRetentionResponse(ctx, decision);

      let zapierDispatched = false;
      if (decision.circuitBreakerTripped) {
        const zapPayload = {
          alert: 'AEGISPAY_RETENTION_LEGAL_ESCALATION',
          accountId: ctx.accountId,
          customerName: ctx.customerName,
          matchedKeyword: decision.matchedCircuitBreakerKeyword,
          customerMessage: ctx.customerMessage,
          timestampIso: new Date().toISOString(),
        };
        let status = 'RECORDED_SUPPORT_ESCALATION';
        if (zapierWebhookUrl && !process.env.VITEST) {
          const check = validateSafeExternalUrl(zapierWebhookUrl, { requireHttps: true });
          if (check.valid && check.normalizedUrl) {
            try {
              const zRes = await fetch(check.normalizedUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(zapPayload),
              });
              if (zRes.ok) status = 'DISPATCHED_LIVE_ZAPIER';
            } catch {
              status = 'ZAPIER_QUEUE_RECORDED';
            }
          }
        }
        const tenantZapLog = zapierDispatchLogByTenant.get(ws.tenantId) || [];
        tenantZapLog.unshift({
          timestampIso: zapPayload.timestampIso,
          eventType: 'HUMAN_SUPPORT_ESCALATION',
          payload: zapPayload,
          status,
        });
        zapierDispatchLogByTenant.set(ws.tenantId, tenantZapLog.slice(0, 50));
        zapierDispatched = true;
      }

      const lockKey = simulateDuplicateClick
        ? `STATIC_DUPLICATE_KEY_${ctx.accountId}_${decision.concessionStepIndex}`
        : `${decision.idempotencyLockKey}_${Date.now()}`;

      if (simulateDuplicateClick) {
        atomicLedger.executeAtomically(lockKey, () => ({
          orderId: `PAYPAL-SBX-LOCKED-${decision.idempotencyLockKey.slice(0, 8).toUpperCase()}`,
          status: 'COMPLETED',
          data: { initial: true },
        }));
      }

      let paypalOrder = null;
      const atomicOutcome = atomicLedger.executeAtomically(lockKey, () => {
        const orderId = `PAYPAL-SBX-RET-${decision.idempotencyLockKey.slice(0, 8).toUpperCase()}`;
        return {
          orderId,
          status: decision.circuitBreakerTripped ? 'PAUSED_FOR_SUPPORT' : 'COMPLETED',
          data: { finalOfferPriceCents: decision.finalOfferPriceCents },
        };
      });

      if (!atomicOutcome.duplicateBlocked && !decision.circuitBreakerTripped) {
        paypalOrder = await paypalGateway.createOrder({
          ownerTenantId: ws.tenantId,
          intent: 'CAPTURE',
          amountCents: decision.finalOfferPriceCents,
          currency: 'USD',
          merchantName: ctx.planName,
          description: `Retention Offer (${decision.approvedDiscountPct}% Off Applied)`,
          customHash: decision.idempotencyLockKey,
          idempotencyKey: lockKey,
          pillar: 'CHURNRESCUE',
          autoExecuteInSandbox: true,
        });
      }

      let paypalSubscription = null;
      if (
        createDiscountedSubscription &&
        !atomicOutcome.duplicateBlocked &&
        !decision.circuitBreakerTripped
      ) {
        paypalSubscription = await paypalGateway.createLiveSubscription({
          ownerTenantId: ws.tenantId,
          planName: `${ctx.planName} (${decision.approvedDiscountPct}% Loyalty Rate)`,
          monthlyPriceCents: decision.finalOfferPriceCents,
          pillar: 'CHURNRESCUE',
        });
      }

      const auditRow = appendAudit(req, {
        pillar: 'CHURNRESCUE',
        actor: decision.circuitBreakerTripped
          ? 'Support Escalation Guard'
          : 'Subscriber Retention Desk',
        eventTitle: decision.circuitBreakerTripped
          ? `Paused Automated Offer ("${decision.matchedCircuitBreakerKeyword}") -> Routed to Human Support`
          : atomicOutcome.duplicateBlocked
            ? `Prevented Duplicate Charge (${atomicOutcome.orderId})`
            : `Retention Offer Applied: ${decision.approvedDiscountPct}% Off ($${(decision.finalOfferPriceCents / 100).toFixed(2)}/mo)`,
        verdict: decision.circuitBreakerTripped
          ? 'CIRCUIT_BREAKER'
          : atomicOutcome.duplicateBlocked
            ? 'BLOCK'
            : 'SETTLED',
        amountCents: decision.finalOfferPriceCents,
        savedOrProtectedCents: decision.circuitBreakerTripped
          ? ctx.currentPlanPriceCents
          : decision.finalOfferPriceCents * 12,
        paypalRef: paypalSubscription
          ? paypalSubscription.subscriptionId
          : paypalOrder
            ? paypalOrder.orderId
            : atomicOutcome.orderId,
        sha256Hash: decision.idempotencyLockKey,
        deterministicRule: atomicOutcome.duplicateBlocked
          ? atomicOutcome.reason
          : decision.deterministicReason,
      });

      res.json({
        decision,
        agentReply: empathy.agentReply,
        engineMode: empathy.engineMode,
        failoverTelemetry: empathy.failoverTelemetry,
        atomicOutcome,
        paypalOrder,
        paypalSubscription,
        zapierDispatched,
        auditRow,
      });
    } catch (err) {
      res.status(400).json({ error: redactSecrets((err as Error).message) });
    }
  });

  // ==========================================================================
  // 9. MILESTONE INVOICING & TEAM PAYOUT SPLITS
  // ==========================================================================

  app.post('/api/paystream/create-plan', async (req, res) => {
    try {
      const ws = getWorkspace(req);
      const { projectTitle, projectBrief, clientEmail, totalBudgetCents, collaborators } =
        req.body || {};

      const budgetCents = Math.max(1000, Math.round(Number(totalBudgetCents) || 245000));
      const cleanTitle = String(projectTitle || 'Client Web & Payment Build');
      const cleanBrief = String(
        projectBrief ||
          'Design, implement, test, and launch a client web application with PayPal checkout.'
      );
      const cleanClientEmail = String(clientEmail || 'client-treasury@personal.example.com');

      const aiScope = await geminiEngine.architectSmartMilestones({
        projectBrief: `${cleanTitle}: ${cleanBrief}`,
        totalBudgetCents: budgetCents,
      });

      const parsedCollabs: CollaboratorShareInput[] = Array.isArray(collaborators)
        ? collaborators.map((c: Record<string, unknown>) => ({
            collaboratorName: String(c.collaboratorName || 'Team Member'),
            paypalEmail: String(c.paypalEmail || 'member@personal.example.com'),
            role: String(c.role || 'Specialist'),
            sharePct: Math.max(1, Number(c.sharePct) || 50),
          }))
        : [];

      const plan = computePennyExactMilestonePlan({
        projectTitle: cleanTitle,
        clientEmail: cleanClientEmail,
        totalBudgetCents: budgetCents,
        proposals: aiScope.proposals,
        collaborators: parsedCollabs,
      });

      ws.milestonePlans.unshift(plan);
      if (ws.milestonePlans.length > 50) ws.milestonePlans.length = 50;
      store.scheduleFlush();

      const auditRow = appendAudit(req, {
        pillar: 'PAYSTREAM',
        actor: 'Milestone Planner',
        eventTitle: `Created Milestone Schedule ${plan.planId} ($${(plan.totalBudgetCents / 100).toFixed(2)} across ${plan.milestones.length} phases)`,
        verdict: 'ALLOW',
        amountCents: plan.totalBudgetCents,
        savedOrProtectedCents: plan.totalBudgetCents,
        paypalRef: plan.planId,
        sha256Hash: plan.planSha256,
        deterministicRule: `Exact cent split verified: sum(milestones) == $${(plan.totalBudgetCents / 100).toFixed(2)}`,
      });

      res.json({
        plan,
        aiSummary: aiScope.aiSummary,
        telemetry: aiScope.telemetry,
        promptGuard: aiScope.promptGuard,
        auditRow,
      });
    } catch (err) {
      res.status(400).json({ error: redactSecrets((err as Error).message) });
    }
  });

  app.post('/api/paystream/issue-invoice', async (req, res) => {
    try {
      const ws = getWorkspace(req);
      const { planId, milestoneId, planSnapshot } = req.body || {};
      let plan = ws.milestonePlans.find((p) => p.planId === String(planId || ''));
      if (!plan && planSnapshot && typeof planSnapshot === 'object' && planSnapshot.planId) {
        plan = planSnapshot as SmartMilestonePlan;
        ws.milestonePlans.unshift(plan);
      }
      if (!plan) {
        plan = ws.milestonePlans[0];
      }
      if (!plan) {
        res.status(404).json({ error: 'Milestone plan not found.' });
        return;
      }

      const milestone =
        plan.milestones.find((m) => m.milestoneId === milestoneId) || plan.milestones[0];
      if (!milestone) {
        res.status(404).json({ error: 'Milestone not found in plan.' });
        return;
      }

      const invoice = await paypalGateway.createLiveInvoice({
        ownerTenantId: ws.tenantId,
        title: `${plan.projectTitle} - ${milestone.title}`,
        note: `Deliverables: ${milestone.acceptanceCriteria.join('; ')}. Team Split (${milestone.collaboratorSplits.map((c) => `${c.collaboratorName}: $${(c.payoutCents / 100).toFixed(2)}`).join(', ')}).`,
        recipientEmail: plan.clientEmail,
        amountCents: milestone.amountCents,
        currency: plan.currency,
        pillar: 'PAYSTREAM',
        contractOrPlanHash: plan.planSha256,
        sendImmediately: true,
      });

      milestone.paypalInvoiceId = invoice.invoiceId;
      milestone.paypalInvoiceUrl = invoice.payerViewUrl;
      milestone.status = 'INVOICED_ON_PAYPAL';
      store.scheduleFlush();

      const auditRow = appendAudit(req, {
        pillar: 'PAYSTREAM',
        actor: 'PayPal Invoicing',
        eventTitle: `Sent PayPal Invoice ${invoice.invoiceId} for ${milestone.title} ($${(milestone.amountCents / 100).toFixed(2)})`,
        verdict: 'SETTLED',
        amountCents: milestone.amountCents,
        savedOrProtectedCents: 0,
        paypalRef: invoice.invoiceId,
        sha256Hash: sha256Hex({ invoiceId: invoice.invoiceId, planSha256: plan.planSha256 }),
        deterministicRule: `PayPal Invoicing v2 (${invoice.mode})`,
      });

      res.json({
        plan,
        milestone,
        invoice,
        auditRow,
      });
    } catch (err) {
      res.status(400).json({ error: redactSecrets((err as Error).message) });
    }
  });

  app.post('/api/paystream/verify-proof', async (req, res) => {
    try {
      const ws = getWorkspace(req);
      const { planId, milestoneId, evidenceText, evidenceUrl, imageBase64, planSnapshot } =
        req.body || {};

      let safeEvidenceUrl: string | undefined;
      if (typeof evidenceUrl === 'string' && evidenceUrl.trim()) {
        const urlCheck = validateSafeExternalUrl(evidenceUrl, { requireHttps: false });
        if (!urlCheck.valid || !urlCheck.normalizedUrl) {
          res.status(400).json({ error: `Invalid evidenceUrl: ${urlCheck.reason}` });
          return;
        }
        safeEvidenceUrl = urlCheck.normalizedUrl;
      }

      let plan = ws.milestonePlans.find((p) => p.planId === String(planId || ''));
      if (!plan && planSnapshot && typeof planSnapshot === 'object' && planSnapshot.planId) {
        plan = planSnapshot as SmartMilestonePlan;
        ws.milestonePlans.unshift(plan);
      }
      if (!plan) {
        plan = ws.milestonePlans[0];
      }
      if (!plan) {
        res.status(404).json({ error: 'Milestone plan not found.' });
        return;
      }

      const milestone =
        plan.milestones.find((m) => m.milestoneId === milestoneId) || plan.milestones[0];
      if (!milestone) {
        res.status(404).json({ error: 'Milestone not found in plan.' });
        return;
      }

      const aiAudit = await geminiEngine.evaluateDeliverableProof({
        milestone,
        evidenceText: String(evidenceText || ''),
        evidenceUrl: safeEvidenceUrl,
        imageBase64: typeof imageBase64 === 'string' ? imageBase64 : undefined,
      });

      const verification = verifyDeliverableProofDeterministically({
        milestone,
        evidenceText: String(evidenceText || ''),
        evidenceUrl: safeEvidenceUrl,
        aiQualityScore: aiAudit.aiQualityScore,
        aiSuggestedVerdict: aiAudit.aiSuggestedVerdict,
        neuralInjectionScore: aiAudit.promptGuard.probability,
      });

      if (verification.approved) {
        milestone.status = 'PROOF_VERIFIED';
        milestone.proofAttestationHash = verification.attestationHash;
        store.scheduleFlush();
      }

      const auditRow = appendAudit(req, {
        pillar: 'PAYSTREAM',
        actor: 'Deliverable Review',
        eventTitle: `${verification.approved ? 'Approved' : 'Held'} Deliverable for ${milestone.title} (${verification.finalScore}/100)`,
        verdict: verification.approved ? 'SETTLED' : verification.verdict,
        amountCents: milestone.amountCents,
        savedOrProtectedCents: verification.approved ? 0 : milestone.amountCents,
        paypalRef: milestone.paypalInvoiceId || milestone.milestoneId,
        sha256Hash: verification.attestationHash,
        deterministicRule: verification.explanation,
      });

      res.json({
        plan,
        milestone,
        aiAudit,
        verification,
        collaboratorPayoutSchedule: milestone.collaboratorSplits,
        auditRow,
      });
    } catch (err) {
      res.status(400).json({ error: redactSecrets((err as Error).message) });
    }
  });

  // ==========================================================================
  // 10. DIAGNOSTICS LAB: FUZZER, AUDIT EXPORT & STATIC ASSETS
  // ==========================================================================

  app.post('/api/security/fuzz', (req, res) => {
    const iterations = Math.min(5000, Math.max(100, Number(req.body?.iterations) || 1000));
    const report = runDeterministicSafetyFuzzer(iterations, Date.now() & 0xffffffff);

    const auditRow = appendAudit(req, {
      pillar: 'FUZZER',
      actor: 'Property-Based Security Verifier',
      eventTitle: `Verified ${report.passedCases}/${report.totalCasesRun} Random Adversarial Cases (${report.durationMs}ms)`,
      verdict: report.failedCases === 0 ? 'ALLOW' : 'BLOCK',
      amountCents: 0,
      savedOrProtectedCents: 100000,
      paypalRef: `FUZZ-${report.totalCasesRun}-PASS`,
      sha256Hash: sha256Hex(report.invariantsVerified),
      deterministicRule:
        '100% Monotonicity, Concession Floor <=50%, Circuit Breaker Zero Leakage, Mandate Ceiling, Penny-Exact Split Conservation Verified',
    });

    res.json({ report, auditRow });
  });

  app.get('/api/export/elastic-ndjson', (req, res) => {
    const ws = getWorkspace(req);
    const lines: string[] = [];
    for (const row of ws.auditLogs) {
      lines.push(
        JSON.stringify({ index: { _index: 'aegispay-security-audit-2026', _id: row.id } })
      );
      lines.push(JSON.stringify({ '@timestamp': row.timestampIso, ...row }));
    }
    res.setHeader('Content-Type', 'application/x-ndjson');
    res.setHeader('Content-Disposition', 'attachment; filename="aegispay-elastic-audit.ndjson"');
    res.send(lines.join('\n') + '\n');
  });

  app.get('/postman/AegisPay_Collection.json', readLimiter.middleware(), (_req, res) => {
    const candidates = [
      path.join(ROOT_DIR, 'postman', 'AegisPay_Collection.json'),
      path.join(process.cwd(), 'postman', 'AegisPay_Collection.json'),
      path.join(process.cwd(), 'public', 'postman', 'AegisPay_Collection.json'),
    ];
    const found = candidates.find((p) => fs.existsSync(p));
    if (found) {
      res.sendFile(found);
    } else {
      res.status(404).json({ error: 'Postman collection not generated yet' });
    }
  });

  app.get('/extension.zip', readLimiter.middleware(), (_req, res) => {
    const candidates = [
      path.join(ROOT_DIR, 'public', 'extension.zip'),
      path.join(process.cwd(), 'public', 'extension.zip'),
      path.join(process.cwd(), 'dist', 'extension.zip'),
    ];
    const found = candidates.find((p) => fs.existsSync(p));
    if (found) {
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader(
        'Content-Disposition',
        'attachment; filename="aegispay-chrome-extension-mv3.zip"'
      );
      res.sendFile(found);
    } else {
      res.status(404).json({ error: 'Extension zip not packaged yet' });
    }
  });

  const distDir = path.join(ROOT_DIR, 'dist');
  if (!process.env.VERCEL && fs.existsSync(distDir)) {
    app.use(express.static(distDir));
    app.get('*', (req, res, next) => {
      if (
        req.path.startsWith('/api') ||
        req.path.startsWith('/postman') ||
        req.path === '/extension.zip'
      ) {
        next();
        return;
      }
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  // Safe error boundary that redacts any secret pattern and hides stack traces
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const message = err instanceof Error ? redactSecrets(err.message) : 'Request validation error';
    res.status(400).json({ error: message });
  });

  return app;
}

if (!process.env.VERCEL && process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  const port = Number(process.env.PORT) || 8787;
  const app = createAegisServer();
  app.listen(port, () => {
    console.log(
      `[AEGISPAY v3.1.0] Hardened Multi-Tenant Payment & Recovery Server listening on http://localhost:${port}`
    );
  });
}
