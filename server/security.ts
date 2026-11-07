import crypto from 'node:crypto';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { hmacSha256Hex } from '../shared/kernel';

// ============================================================================
// AEGISPAY ZERO-TRUST SECURITY, STRICT CORS/CSRF, SSRF GUARD & RATE LIMITER
// ============================================================================

const SECRET_PATTERNS: RegExp[] = [
  /AQ\.[A-Za-z0-9_-]{12,}/g,
  /gsk_[A-Za-z0-9_-]{12,}/g,
  /GOCSPX-[A-Za-z0-9_-]{10,}/g,
  /aegis_sess_[A-Za-z0-9._-]{16,}/g,
  /Bearer\s+[A-Za-z0-9._-]{16,}/gi,
];

export function redactSecrets(input: unknown): string {
  let text = typeof input === 'string' ? input : JSON.stringify(input ?? '');
  for (const pattern of SECRET_PATTERNS) {
    text = text.replace(pattern, '[REDACTED_SECRET]');
  }
  return text;
}

export function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;
  const parts = cookieHeader.split(';');
  for (const part of parts) {
    const eqIdx = part.indexOf('=');
    if (eqIdx === -1) continue;
    const key = part.slice(0, eqIdx).trim();
    const val = part.slice(eqIdx + 1).trim();
    if (key && key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
      try {
        out[key] = decodeURIComponent(val);
      } catch {
        out[key] = val;
      }
    }
  }
  return out;
}

function appendSetCookie(res: Response, cookieStr: string): void {
  const existing = res.getHeader('Set-Cookie');
  if (!existing) {
    res.setHeader('Set-Cookie', [cookieStr]);
  } else if (Array.isArray(existing)) {
    res.setHeader('Set-Cookie', [...existing.map(String), cookieStr]);
  } else {
    res.setHeader('Set-Cookie', [String(existing), cookieStr]);
  }
}

function isHttpsRequest(req: Request): boolean {
  const host = String(req.headers.host || '').toLowerCase();
  if (host.startsWith('localhost') || host.startsWith('127.0.0.1') || host.startsWith('[::1]')) {
    return false;
  }
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '')
    .split(',')[0]
    .trim()
    .toLowerCase();
  return Boolean(process.env.VERCEL) || Boolean(req.secure) || forwardedProto === 'https';
}

export function setSessionCookie(req: Request, res: Response, token: string): void {
  const parts = [
    `aegis_session=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=43200',
  ];
  if (isHttpsRequest(req)) {
    parts.push('Secure');
  }
  appendSetCookie(res, parts.join('; '));
}

export function clearSessionCookie(res: Response): void {
  appendSetCookie(
    res,
    'aegis_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT'
  );
}

/**
 * Cryptographic OAuth 2.0 CSRF state cookie (10-minute TTL).
 */
export function issueOAuthStateCookie(req: Request, res: Response, secret: string): string {
  const ts = Date.now();
  const nonce = crypto.randomBytes(16).toString('hex');
  const sig = hmacSha256Hex(secret, { ts, nonce, purpose: 'GOOGLE_OAUTH_CSRF_STATE' }).slice(
    0,
    32
  );
  const stateValue = `${ts}.${nonce}.${sig}`;
  const parts = [
    `aegis_oauth_state=${encodeURIComponent(stateValue)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=600',
  ];
  if (isHttpsRequest(req)) {
    parts.push('Secure');
  }
  appendSetCookie(res, parts.join('; '));
  return stateValue;
}

export function verifyOAuthStateCookie(
  req: Request,
  res: Response,
  queryState: string,
  secret: string
): boolean {
  appendSetCookie(
    res,
    'aegis_oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT'
  );
  if (!queryState) return false;
  const cookies = parseCookies(req.headers.cookie);
  const cookieState = cookies.aegis_oauth_state || '';
  if (!cookieState || cookieState.length !== queryState.length) return false;

  const bufA = Buffer.from(cookieState, 'utf8');
  const bufB = Buffer.from(queryState, 'utf8');
  if (!crypto.timingSafeEqual(bufA, bufB)) return false;

  const parts = queryState.split('.');
  if (parts.length !== 3) return false;
  const ts = Number(parts[0]);
  const nonce = parts[1];
  const sig = parts[2];
  if (!Number.isFinite(ts) || Date.now() - ts > 10 * 60_000 || Date.now() - ts < -30_000) {
    return false;
  }
  const expectedSig = hmacSha256Hex(secret, {
    ts,
    nonce,
    purpose: 'GOOGLE_OAUTH_CSRF_STATE',
  }).slice(0, 32);
  if (sig.length !== expectedSig.length) return false;
  return crypto.timingSafeEqual(Buffer.from(sig, 'utf8'), Buffer.from(expectedSig, 'utf8'));
}

/**
 * Explicit Origin Allowlist CORS + CSRF Protection.
 * Rejects wildcard credentialed reflection completely.
 */
export function getAllowedOrigins(): Set<string> {
  const allowed = new Set<string>([
    'http://localhost:8787',
    'http://127.0.0.1:8787',
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:4173',
    'https://aegispay-orpin.vercel.app',
  ]);
  const extra = process.env.ALLOWED_ORIGINS || process.env.ALLOWED_ORIGIN || '';
  for (const item of extra.split(',')) {
    const trimmed = item.trim();
    if (trimmed) allowed.add(trimmed);
  }
  return allowed;
}

export function isOriginPermitted(origin: string | undefined): boolean {
  if (!origin) return true; // Same-origin non-CORS or server-to-server CLI
  if (origin.startsWith('chrome-extension://')) return true;
  const allowed = getAllowedOrigins();
  if (allowed.has(origin)) return true;
  // Allow ephemeral local test ports on 127.0.0.1 / localhost during local dev/tests
  if (/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(origin)) return true;
  return false;
}

export const strictCorsMiddleware: RequestHandler = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const origin = typeof req.headers.origin === 'string' ? req.headers.origin : undefined;
  res.setHeader('Vary', 'Origin');

  if (origin && isOriginPermitted(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, X-Requested-With, PayPal-Transmission-Id, PayPal-Transmission-Time, PayPal-Transmission-Sig, PayPal-Cert-Url, PayPal-Auth-Algo, X-Aegis-Webhook-Signature'
    );
  }

  if (req.method === 'OPTIONS') {
    if (origin && !isOriginPermitted(origin)) {
      res.status(403).json({ error: 'Origin not permitted by AegisPay CORS policy.' });
      return;
    }
    res.status(204).end();
    return;
  }

  next();
};

/**
 * Enforces CSRF protection for cookie-authenticated state-mutating requests.
 * Requests carrying explicit Authorization: Bearer tokens or PayPal webhooks are exempt.
 */
export const csrfProtectionMiddleware: RequestHandler = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    next();
    return;
  }
  if (req.path === '/api/paypal/webhook') {
    next();
    return;
  }
  const hasBearer = String(req.headers.authorization || '').startsWith('Bearer ');
  if (hasBearer) {
    next();
    return;
  }
  const cookies = parseCookies(req.headers.cookie);
  if (!cookies.aegis_session) {
    next();
    return;
  }

  const customHeader = String(req.headers['x-requested-with'] || '');
  const origin = typeof req.headers.origin === 'string' ? req.headers.origin : '';
  if (customHeader === 'AegisPay-Client' || (origin && isOriginPermitted(origin))) {
    next();
    return;
  }

  res.status(403).json({
    code: 'CSRF_VERIFICATION_FAILED',
    error: 'Cross-site request blocked: missing trusted Origin or X-Requested-With header.',
  });
};

/**
 * SSRF Guard: Validates outbound webhook / proof URLs and rejects loopback,
 * link-local metadata (169.254.169.254), RFC1918 private IPs, and non-HTTPS URLs.
 */
export function validateSafeExternalUrl(
  rawUrl: string,
  options?: { requireHttps?: boolean }
): {
  valid: boolean;
  normalizedUrl: string;
  reason?: string;
} {
  const trimmed = rawUrl.trim();
  if (!trimmed) return { valid: true, normalizedUrl: '' };
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, normalizedUrl: '', reason: 'Invalid URL syntax.' };
  }

  const requireHttps = options?.requireHttps ?? true;
  if (requireHttps && parsed.protocol !== 'https:') {
    return {
      valid: false,
      normalizedUrl: '',
      reason: 'External webhook URLs must use HTTPS.',
    };
  }
  if (!requireHttps && parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return {
      valid: false,
      normalizedUrl: '',
      reason: 'External proof URLs must use HTTP or HTTPS.',
    };
  }

  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host === '0.0.0.0' ||
    host === '::1' ||
    host.startsWith('127.') ||
    host.startsWith('10.') ||
    host.startsWith('192.168.') ||
    host.startsWith('169.254.') ||
    host.startsWith('fc00:') ||
    host.startsWith('fd00:') ||
    host.startsWith('fe80:') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(host)
  ) {
    return {
      valid: false,
      normalizedUrl: '',
      reason: 'Private, loopback, or cloud metadata hostnames are blocked (SSRF protection).',
    };
  }

  return { valid: true, normalizedUrl: parsed.toString() };
}

/**
 * Recursively strips null bytes and blocks prototype-pollution keys.
 */
function sanitizeValue(val: unknown, depth = 0): unknown {
  if (depth > 8) return undefined;
  if (typeof val === 'string') {
    return val.replace(/\0/g, '');
  }
  if (Array.isArray(val)) {
    return val.slice(0, 500).map((item) => sanitizeValue(item, depth + 1));
  }
  if (val !== null && typeof val === 'object') {
    const clean: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') {
        continue;
      }
      clean[k] = sanitizeValue(v, depth + 1);
    }
    return clean;
  }
  return val;
}

export const sanitizePayloadMiddleware: RequestHandler = (
  req: Request,
  _res: Response,
  next: NextFunction
) => {
  if (req.body && typeof req.body === 'object') {
    req.body = sanitizeValue(req.body, 0);
  }
  next();
};

export const securityHeadersMiddleware: RequestHandler = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const reqId =
    (typeof req.headers['x-request-id'] === 'string' &&
      req.headers['x-request-id'].slice(0, 64)) ||
    crypto.randomUUID();

  res.setHeader('X-Request-Id', reqId);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), usb=(), payment=(self "https://www.paypal.com" "https://www.sandbox.paypal.com")'
  );
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self' https://www.paypal.com https://www.sandbox.paypal.com https://www.paypalobjects.com https://accounts.google.com",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://accounts.google.com",
      "font-src 'self' https://fonts.gstatic.com data:",
      "img-src 'self' data: blob: https://*.paypal.com https://*.paypalobjects.com https://*.googleusercontent.com",
      "connect-src 'self' https://*.paypal.com https://*.sandbox.paypal.com https://accounts.google.com",
      "frame-src 'self' https://*.paypal.com https://*.sandbox.paypal.com https://accounts.google.com",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; ')
  );
  next();
};

export interface RateLimitTierOptions {
  tierName: 'AUTH' | 'MUTATION' | 'READ';
  windowMs: number;
  maxRequests: number;
  maxTrackedBuckets?: number;
}

interface BucketRecord {
  timestamps: number[];
  lastSeenMs: number;
}

export class SlidingWindowRateLimiter {
  private readonly buckets = new Map<string, BucketRecord>();
  private readonly options: Required<RateLimitTierOptions>;
  private totalBlocked = 0;

  constructor(options: RateLimitTierOptions) {
    this.options = {
      maxTrackedBuckets: 10_000,
      ...options,
    };
  }

  public getStats(): {
    tierName: string;
    windowMs: number;
    maxRequests: number;
    activeBuckets: number;
    totalBlocked: number;
  } {
    return {
      tierName: this.options.tierName,
      windowMs: this.options.windowMs,
      maxRequests: this.options.maxRequests,
      activeBuckets: this.buckets.size,
      totalBlocked: this.totalBlocked,
    };
  }

  private resolveClientKey(req: Request): string {
    const authUser = (req as unknown as { operator?: { id?: string } }).operator?.id;
    if (authUser) {
      return `usr:${authUser}`;
    }
    const trustForwarded = Boolean(process.env.VERCEL) || process.env.TRUST_PROXY === '1';
    const forwarded = trustForwarded ? req.headers['x-forwarded-for'] : undefined;
    const rawIp =
      (typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : '') ||
      req.socket?.remoteAddress ||
      req.ip ||
      '127.0.0.1';
    return `ip:${rawIp.slice(0, 64)}`;
  }

  private evictIfNeeded(now: number): void {
    if (this.buckets.size < this.options.maxTrackedBuckets) return;
    const cutoff = now - this.options.windowMs;
    for (const [k, rec] of this.buckets.entries()) {
      if (rec.lastSeenMs < cutoff) {
        this.buckets.delete(k);
      }
      if (this.buckets.size < this.options.maxTrackedBuckets * 0.8) break;
    }
    if (this.buckets.size >= this.options.maxTrackedBuckets) {
      const oldestKey = this.buckets.keys().next().value;
      if (oldestKey) this.buckets.delete(oldestKey);
    }
  }

  public middleware(): RequestHandler {
    return (req: Request, res: Response, next: NextFunction) => {
      const now = Date.now();
      const key = this.resolveClientKey(req);
      let rec = this.buckets.get(key);
      if (!rec) {
        this.evictIfNeeded(now);
        rec = { timestamps: [], lastSeenMs: now };
        this.buckets.set(key, rec);
      } else {
        this.buckets.delete(key);
        this.buckets.set(key, rec);
      }

      const cutoff = now - this.options.windowMs;
      while (rec.timestamps.length > 0 && rec.timestamps[0] <= cutoff) {
        rec.timestamps.shift();
      }
      rec.lastSeenMs = now;

      const remaining = Math.max(0, this.options.maxRequests - rec.timestamps.length);
      const resetSec =
        rec.timestamps.length > 0
          ? Math.max(1, Math.ceil((rec.timestamps[0] + this.options.windowMs - now) / 1000))
          : Math.ceil(this.options.windowMs / 1000);

      res.setHeader('RateLimit-Limit', String(this.options.maxRequests));
      res.setHeader('RateLimit-Policy', `${this.options.maxRequests};w=${Math.ceil(this.options.windowMs / 1000)}`);

      if (rec.timestamps.length >= this.options.maxRequests) {
        this.totalBlocked += 1;
        res.setHeader('RateLimit-Remaining', '0');
        res.setHeader('RateLimit-Reset', String(resetSec));
        res.setHeader('Retry-After', String(resetSec));
        res.status(429).json({
          code: 'RATE_LIMIT_EXCEEDED',
          tier: this.options.tierName,
          retryAfterSeconds: resetSec,
          error: `Rate limit exceeded for ${this.options.tierName} tier. Please retry in ${resetSec}s.`,
        });
        return;
      }

      rec.timestamps.push(now);
      res.setHeader('RateLimit-Remaining', String(Math.max(0, remaining - 1)));
      res.setHeader('RateLimit-Reset', String(resetSec));
      next();
    };
  }
}
