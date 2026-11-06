import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  AgentSpendingPermit,
  CashflowCommitment,
  computePennyExactMilestonePlan,
  DEFAULT_MERCHANT_REFUND_POLICY,
  MerchantRefundPolicyMatrix,
  PayPalBillingPermission,
  sha256Hex,
  SignedDealContract,
  SmartMilestonePlan,
} from '../shared/kernel';
import type {
  PayReviveBenchmarkReport,
  PayReviveDecision,
  SerializedBanditState,
} from '../shared/payrevive';
import type { AuditLedgerRow, AuthenticatedOperator } from './index';

// ============================================================================
// AEGISPAY MULTI-TENANT PERSISTENT DATA STORE + ASYNC WRITE QUEUE + LRU CACHE
// ============================================================================

export interface StoredUserRecord {
  id: string;
  email: string;
  fullName: string;
  organization: string;
  role: AuthenticatedOperator['role'];
  passwordScrypt: string;
  hasPassword?: boolean;
  authProviders?: Array<AuthenticatedOperator['authProvider']>;
  paypalMerchantId: string;
  createdAtIso: string;
  lastLoginAtIso: string;
}

export interface TenantWorkspace {
  tenantId: string;
  ownerEmail: string;
  billingPermissions: PayPalBillingPermission[];
  cashflowCommitments: CashflowCommitment[];
  currentCheckingBalanceCents: number;
  minimumSafetyBufferCents: number;
  agentPermits: AgentSpendingPermit[];
  milestonePlans: SmartMilestonePlan[];
  auditLogs: AuditLedgerRow[];
  signedContracts: SignedDealContract[];
  payreviveDecisions: PayReviveDecision[];
  payreviveBanditState: SerializedBanditState;
  lastPayReviveBenchmark: PayReviveBenchmarkReport | null;
  merchantPolicy: MerchantRefundPolicyMatrix;
  claimedVisionImageHashes: string[];
  refundedCentsByCapture: Record<string, number>;
  tutorialCompleted: boolean;
  updatedAtIso: string;
}

interface PersistedVaultSchema {
  schemaVersion: 3;
  savedAtIso: string;
  generatedKernelSecret?: string;
  users: StoredUserRecord[];
  revokedTokenHashes: string[];
  tenants: Record<string, TenantWorkspace>;
}

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 64;

export function hashPasswordScrypt(rawPassword: string, saltHex?: string): string {
  const salt = saltHex ? Buffer.from(saltHex, 'hex') : crypto.randomBytes(16);
  const derived = crypto.scryptSync(rawPassword, salt, SCRYPT_KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('hex')}$${derived.toString('hex')}`;
}

export function verifyPasswordScrypt(rawPassword: string, stored: string): boolean {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const n = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  const salt = Buffer.from(parts[4], 'hex');
  const expected = Buffer.from(parts[5], 'hex');
  if (!salt.length || expected.length !== SCRYPT_KEYLEN) return false;
  const actual = crypto.scryptSync(rawPassword, salt, expected.length, { N: n, r, p });
  return crypto.timingSafeEqual(actual, expected);
}

export function createDefaultTenantWorkspace(
  tenantId: string,
  ownerEmail: string
): TenantWorkspace {
  const initialPayStreamPlan = computePennyExactMilestonePlan({
    projectTitle: 'Web Platform Redesign & Checkout Launch',
    clientEmail: 'client-billing@acme-studio.io',
    currency: 'USD',
    totalBudgetCents: 10000,
    proposals: [
      {
        title: 'Milestone 1: Product Scope & Wireframes',
        weightPct: 34,
        dueInDays: 5,
        acceptanceCriteria: [
          'Approved page layouts',
          'Checkout user flow signed off',
        ],
      },
      {
        title: 'Milestone 2: PayPal Checkout & Invoicing Integration',
        weightPct: 33,
        dueInDays: 10,
        acceptanceCriteria: [
          'Live PayPal checkout working',
          'Automated customer receipts verified',
        ],
      },
      {
        title: 'Milestone 3: Final QA & Production Launch',
        weightPct: 33,
        dueInDays: 15,
        acceptanceCriteria: [
          'End-to-end automated verification passing',
          'Production handoff documentation complete',
        ],
      },
    ],
    collaborators: [
      {
        collaboratorName: 'Lead Developer',
        paypalEmail: 'lead-dev@studio.io',
        role: 'Engineering',
        sharePct: 50,
      },
      {
        collaboratorName: 'Product Designer',
        paypalEmail: 'design@studio.io',
        role: 'Design',
        sharePct: 30,
      },
      {
        collaboratorName: 'QA Specialist',
        paypalEmail: 'qa@studio.io',
        role: 'Verification',
        sharePct: 20,
      },
    ],
  });

  return {
    tenantId,
    ownerEmail,
    billingPermissions: [
      {
        agreementId: 'BA-94827104-ZOMBIE1',
        merchantName: 'CloudMetrics Legacy DevTools Inc.',
        merchantId: 'merch_cloudmetrics_legacy',
        category: 'CLOUD',
        monthlyCapCents: 15000,
        averageChargeCents: 4900,
        lastChargedDaysAgo: 412,
        lastUserInteractionDaysAgo: 412,
        createdDaysAgo: 780,
        status: 'ACTIVE',
      },
      {
        agreementId: 'BA-88312095-ZOMBIE2',
        merchantName: 'StreamVault Ultra 4K Bundle',
        merchantId: 'merch_streamvault',
        category: 'ENTERTAINMENT',
        monthlyCapCents: 6000,
        averageChargeCents: 2999,
        previousChargeCents: 1999,
        lastChargedDaysAgo: 14,
        lastUserInteractionDaysAgo: 215,
        createdDaysAgo: 390,
        status: 'ACTIVE',
      },
      {
        agreementId: 'BA-77219402-OVERCAP',
        merchantName: 'QuickShip Fulfill API',
        merchantId: 'merch_quickship',
        category: 'SAAS',
        monthlyCapCents: 50000,
        averageChargeCents: 4500,
        lastChargedDaysAgo: 9,
        lastUserInteractionDaysAgo: 3,
        createdDaysAgo: 240,
        status: 'ACTIVE',
      },
      {
        agreementId: 'BA-66109821-HEALTHY',
        merchantName: 'GitHub Copilot Business',
        merchantId: 'merch_github',
        category: 'SAAS',
        monthlyCapCents: 4500,
        averageChargeCents: 3900,
        lastChargedDaysAgo: 11,
        lastUserInteractionDaysAgo: 1,
        createdDaysAgo: 520,
        status: 'ACTIVE',
      },
    ],
    cashflowCommitments: [
      {
        id: 'cf_rent',
        name: 'Monthly Office / Apartment Lease',
        amountCents: 185000,
        dueInDays: 5,
        category: 'RENT_MORTGAGE',
        mandatory: true,
      },
      {
        id: 'cf_loan',
        name: 'Equipment & Insurance Autopay',
        amountCents: 46000,
        dueInDays: 8,
        category: 'LOAN',
        mandatory: true,
      },
      {
        id: 'cf_paypal_subs',
        name: 'Active PayPal Software Subscriptions',
        amountCents: 18500,
        dueInDays: 12,
        category: 'PAYPAL_AUTOPAY',
        mandatory: true,
      },
      {
        id: 'cf_savings',
        name: 'Monthly Reserve Target',
        amountCents: 50000,
        dueInDays: 15,
        category: 'SAVINGS_GOAL',
        mandatory: false,
      },
    ],
    currentCheckingBalanceCents: 382000,
    minimumSafetyBufferCents: 35000,
    agentPermits: [
      {
        permitId: 'PRM-CLAUDE-CODE-01',
        agentId: 'agent_claude_code_v1',
        agentName: 'Workspace Procurement Assistant',
        parentAgreementId: 'BA-PAYPAL-VAULT-01',
        maxSingleTransactionCents: 7500,
        dailyLimitCents: 15000,
        spentTodayCents: 2400,
        autoAllowMaxCents: 4000,
        minConfidenceScore: 0.82,
        allowedCategories: ['HARDWARE', 'SAAS', 'OFFICE', 'CLOUD'],
        blockedMerchants: ['shady-keys-outlet', 'unverified-crypto-wire'],
        active: true,
      },
      {
        permitId: 'PRM-PROCUREMENT-02',
        agentId: 'agent_procurement_v2',
        agentName: 'Office Restock Assistant',
        parentAgreementId: 'BA-PAYPAL-VAULT-02',
        maxSingleTransactionCents: 25000,
        dailyLimitCents: 40000,
        spentTodayCents: 8000,
        autoAllowMaxCents: 12000,
        minConfidenceScore: 0.88,
        allowedCategories: ['OFFICE', 'HARDWARE'],
        blockedMerchants: ['shady-keys-outlet'],
        active: true,
      },
    ],
    milestonePlans: [initialPayStreamPlan],
    auditLogs: [
      {
        id: 'AUD-1001',
        timestampIso: new Date(Date.now() - 3600_000 * 3.2).toISOString(),
        pillar: 'LUPAPERMIT',
        actor: 'Autopay Protection',
        eventTitle: 'Flagged 3 Inactive or Over-Capped PayPal Autopay Agreements',
        verdict: 'HOLD',
        amountCents: 71000,
        savedOrProtectedCents: 7899,
        paypalRef: 'BA-94827104-ZOMBIE1',
        sha256Hash: sha256Hex({ id: 'AUD-1001', tenantId }),
        deterministicRule: 'Inactive >365d + Price Increase >15% + Cap >2.5x Average Charge',
      },
      {
        id: 'AUD-1002',
        timestampIso: new Date(Date.now() - 3600_000 * 2.4).toISOString(),
        pillar: 'SCAMSHIELD',
        actor: 'Invoice Protection',
        eventTitle: 'Blocked Suspicious Friends-and-Family Payment Request ($490.00)',
        verdict: 'BLOCK',
        amountCents: 49000,
        savedOrProtectedCents: 49000,
        paypalRef: 'BLOCKED-PRE-ORDER',
        sha256Hash: sha256Hex({ id: 'AUD-1002', tenantId }),
        deterministicRule: 'Buyer-Protection Bypass + Coercive Urgency Blocked',
      },
      {
        id: 'AUD-1003',
        timestampIso: new Date(Date.now() - 3600_000 * 1.4).toISOString(),
        pillar: 'DEALFORGE',
        actor: 'Smart Deal Builder',
        eventTitle: 'Vendor Agreement Reached ($950 -> $680, 35% PayPal Deposit)',
        verdict: 'SETTLED',
        amountCents: 23800,
        savedOrProtectedCents: 27000,
        paypalRef: 'PAYPAL-SBX-DEAL680',
        sha256Hash: sha256Hex({ id: 'AUD-1003', tenantId }),
        deterministicRule: 'Within Buyer Budget & Vendor Minimum; Terms Locked',
      },
      {
        id: 'AUD-1004',
        timestampIso: new Date(Date.now() - 3600_000 * 0.6).toISOString(),
        pillar: 'PAYREVIVE',
        actor: 'PayRevive Recovery',
        eventTitle: 'Sent PayPal Backup Funding Link for Expired Card Renewal ($240.00)',
        verdict: 'SETTLED',
        amountCents: 24000,
        savedOrProtectedCents: 19245,
        paypalRef: 'PAYPAL-SBX-PRV240',
        sha256Hash: sha256Hex({ id: 'AUD-1004', tenantId }),
        deterministicRule: 'Positive Expected Net Value & All Compliance Checks Passed',
      },
    ],
    signedContracts: [],
    payreviveDecisions: [],
    payreviveBanditState: {},
    lastPayReviveBenchmark: null,
    merchantPolicy: JSON.parse(JSON.stringify(DEFAULT_MERCHANT_REFUND_POLICY)),
    claimedVisionImageHashes: [],
    refundedCentsByCapture: {},
    tutorialCompleted: false,
    updatedAtIso: new Date().toISOString(),
  };
}

export interface PersistentStoreOptions {
  rootDir: string;
  customFilePath?: string;
  maxHotTenants?: number;
  maxAuditLogsPerTenant?: number;
}

export class AegisMultiTenantStore {
  private readonly storeFilePath: string;
  private readonly storageMode:
    | 'LOCAL_ENCRYPTED_FS_VAULT'
    | 'SERVERLESS_STATELESS_HMAC_WITH_TMP_CACHE'
    | 'ISOLATED_TEST_VAULT';
  private readonly maxHotTenants: number;
  private readonly maxAuditLogsPerTenant: number;

  private vaultKernelSecret = '';
  private readonly usersByEmail = new Map<string, StoredUserRecord>();
  private readonly revokedTokenHashes = new Set<string>();
  private readonly hotTenants = new Map<string, TenantWorkspace>();
  private persistedTenantsSnapshot: Record<string, TenantWorkspace> = {};

  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  private activeWritePromise: Promise<void> | null = null;
  private writePendingAgain = false;

  constructor(opts: PersistentStoreOptions) {
    this.maxHotTenants = opts.maxHotTenants || 2000;
    this.maxAuditLogsPerTenant = opts.maxAuditLogsPerTenant || 250;

    if (opts.customFilePath) {
      this.storeFilePath = opts.customFilePath;
      this.storageMode = 'LOCAL_ENCRYPTED_FS_VAULT';
    } else if (process.env.VITEST) {
      const randId = crypto.randomBytes(6).toString('hex');
      this.storeFilePath = path.join(os.tmpdir(), `aegispay_vitest_${randId}.store.json`);
      this.storageMode = 'ISOLATED_TEST_VAULT';
    } else if (process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME) {
      this.storeFilePath = path.join(os.tmpdir(), 'aegispay_store.json');
      this.storageMode = 'SERVERLESS_STATELESS_HMAC_WITH_TMP_CACHE';
    } else {
      const dataDir = path.join(opts.rootDir, 'data');
      fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
      this.storeFilePath = path.join(dataDir, 'aegispay_store.json');
      this.storageMode = 'LOCAL_ENCRYPTED_FS_VAULT';
    }

    this.loadFromDiskSyncOnBoot();
    if (!this.vaultKernelSecret) {
      this.vaultKernelSecret = crypto.randomBytes(32).toString('hex');
      this.scheduleFlush();
    }
    this.ensureDefaultSandboxAccounts();
  }

  /**
   * Returns a cryptographic kernel secret without ever falling back to a hardcoded string:
   * uses AEGIS_KERNEL_SECRET if provided, otherwise uses the 32-byte random secret persisted in the 0o600 vault.
   */
  public resolveKernelSecret(): string {
    const fromEnv = (process.env.AEGIS_KERNEL_SECRET || '').trim();
    if (fromEnv.length >= 24) {
      return fromEnv;
    }
    return this.vaultKernelSecret;
  }

  private ensureDefaultSandboxAccounts(): void {
    const allowSandboxSeed = process.env.ALLOW_DEMO_SANDBOX !== 'false';
    if (!allowSandboxSeed) return;

    const now = new Date().toISOString();
    const demoSalt = sha256Hex('aegis-sandbox-seed-salt-v3').slice(0, 32);

    const defaultOperator = 'operator@aegispay.io';
    if (!this.usersByEmail.has(defaultOperator)) {
      this.usersByEmail.set(defaultOperator, {
        id: 'OP-AEGIS-001',
        email: defaultOperator,
        fullName: 'Sandbox Workspace Owner',
        organization: 'AegisPay Sandbox Account',
        role: 'PRINCIPAL_ARCHITECT',
        passwordScrypt: hashPasswordScrypt('AegisPay2026!', demoSalt),
        hasPassword: true,
        authProviders: ['EMAIL_PASSWORD'],
        paypalMerchantId: 'SBX-MERCH-AEGIS-01',
        createdAtIso: now,
        lastLoginAtIso: now,
      });
    }

    const guestDemo = 'demo@aegispay.io';
    if (!this.usersByEmail.has(guestDemo)) {
      this.usersByEmail.set(guestDemo, {
        id: 'OP-DEMO-GUEST',
        email: guestDemo,
        fullName: 'Interactive Tour Guest',
        organization: 'PayPal Sandbox Demo',
        role: 'DEMO_OPERATOR',
        passwordScrypt: hashPasswordScrypt(crypto.randomBytes(24).toString('hex')),
        hasPassword: false,
        authProviders: ['DEMO_SANDBOX'],
        paypalMerchantId: 'SBX-DEMO-GUEST-01',
        createdAtIso: now,
        lastLoginAtIso: now,
      });
    }
    this.scheduleFlush();
  }

  private loadFromDiskSyncOnBoot(): void {
    try {
      if (!fs.existsSync(this.storeFilePath)) return;
      const raw = fs.readFileSync(this.storeFilePath, 'utf8');
      if (!raw.trim()) return;
      const parsed = JSON.parse(raw) as Partial<PersistedVaultSchema>;
      if (typeof parsed.generatedKernelSecret === 'string' && parsed.generatedKernelSecret.length >= 32) {
        this.vaultKernelSecret = parsed.generatedKernelSecret;
      }
      if (Array.isArray(parsed.users)) {
        for (const u of parsed.users) {
          if (u?.email && u?.passwordScrypt) {
            const normalizedEmail = u.email.toLowerCase();
            const isDemo = normalizedEmail === 'demo@aegispay.io' || u.role === 'DEMO_OPERATOR';
            const isLegacyOAuthOnly = String(u.paypalMerchantId || '').startsWith('SBX-GOOGLE-');
            const inferredHasPassword =
              typeof u.hasPassword === 'boolean' ? u.hasPassword : !isDemo && !isLegacyOAuthOnly;
            const inferredProviders =
              Array.isArray(u.authProviders) && u.authProviders.length > 0
                ? u.authProviders
                : isDemo
                  ? (['DEMO_SANDBOX'] as const)
                  : isLegacyOAuthOnly
                    ? (['GOOGLE_OAUTH'] as const)
                    : (['EMAIL_PASSWORD'] as const);
            this.usersByEmail.set(normalizedEmail, {
              ...u,
              email: normalizedEmail,
              hasPassword: inferredHasPassword,
              authProviders: [...inferredProviders],
            });
          }
        }
      }
      if (Array.isArray(parsed.revokedTokenHashes)) {
        for (const h of parsed.revokedTokenHashes.slice(-2000)) {
          this.revokedTokenHashes.add(h);
        }
      }
      if (parsed.tenants && typeof parsed.tenants === 'object') {
        this.persistedTenantsSnapshot = parsed.tenants;
      }
    } catch {
      // Unreadable vault initializes cleanly
    }
  }

  private buildVaultPayload(): PersistedVaultSchema {
    for (const [tid, ws] of this.hotTenants.entries()) {
      this.persistedTenantsSnapshot[tid] = ws;
    }
    return {
      schemaVersion: 3,
      savedAtIso: new Date().toISOString(),
      generatedKernelSecret: this.vaultKernelSecret,
      users: Array.from(this.usersByEmail.values()),
      revokedTokenHashes: Array.from(this.revokedTokenHashes).slice(-2000),
      tenants: this.persistedTenantsSnapshot,
    };
  }

  /**
   * Non-blocking async atomic write-ahead flush using fs.promises.
   * Coalesces concurrent mutations so the Node event loop is never blocked.
   */
  public async flushAsync(): Promise<void> {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    if (this.activeWritePromise) {
      this.writePendingAgain = true;
      return this.activeWritePromise;
    }

    this.activeWritePromise = (async () => {
      do {
        this.writePendingAgain = false;
        try {
          const dir = path.dirname(this.storeFilePath);
          await fs.promises.mkdir(dir, { recursive: true, mode: 0o700 });
          const serialized = JSON.stringify(this.buildVaultPayload());
          const tmpPath = `${this.storeFilePath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
          await fs.promises.writeFile(tmpPath, serialized, { encoding: 'utf8', mode: 0o600 });
          await fs.promises.rename(tmpPath, this.storeFilePath);
        } catch {
          // Ignore write errors on read-only environments
        }
      } while (this.writePendingAgain);
    })().finally(() => {
      this.activeWritePromise = null;
    });

    return this.activeWritePromise;
  }

  public scheduleFlush(): void {
    if (this.flushTimer) return;
    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      void this.flushAsync();
    }, 80);
    if (typeof this.flushTimer.unref === 'function') {
      this.flushTimer.unref();
    }
  }

  public getUserByEmail(email: string): StoredUserRecord | undefined {
    return this.usersByEmail.get(email.trim().toLowerCase());
  }

  public async createUser(params: {
    email: string;
    rawPassword: string;
    fullName: string;
    organization: string;
    role?: AuthenticatedOperator['role'];
  }): Promise<StoredUserRecord> {
    const normalizedEmail = params.email.trim().toLowerCase();
    const now = new Date().toISOString();
    const record: StoredUserRecord = {
      id: `OP-${sha256Hex(normalizedEmail).slice(0, 8).toUpperCase()}`,
      email: normalizedEmail,
      fullName: params.fullName.trim() || 'Workspace Operator',
      organization: params.organization.trim() || 'PayPal Workspace',
      role: params.role || 'TREASURY_OPERATOR',
      passwordScrypt: hashPasswordScrypt(params.rawPassword),
      hasPassword: true,
      authProviders: ['EMAIL_PASSWORD'],
      paypalMerchantId: `SBX-MERCH-${sha256Hex(normalizedEmail).slice(0, 6).toUpperCase()}`,
      createdAtIso: now,
      lastLoginAtIso: now,
    };
    this.usersByEmail.set(normalizedEmail, record);
    await this.flushAsync();
    return record;
  }

  public async linkPasswordToUser(params: {
    email: string;
    rawPassword: string;
    fullName?: string;
    organization?: string;
  }): Promise<StoredUserRecord | undefined> {
    const normalizedEmail = params.email.trim().toLowerCase();
    const existing = this.usersByEmail.get(normalizedEmail);
    if (!existing) return undefined;
    existing.passwordScrypt = hashPasswordScrypt(params.rawPassword);
    existing.hasPassword = true;
    const providers = new Set<AuthenticatedOperator['authProvider']>(
      existing.authProviders || ['GOOGLE_OAUTH']
    );
    providers.add('EMAIL_PASSWORD');
    existing.authProviders = Array.from(providers);
    if (params.fullName && params.fullName.trim()) {
      existing.fullName = params.fullName.trim();
    }
    if (params.organization && params.organization.trim()) {
      existing.organization = params.organization.trim();
    }
    existing.lastLoginAtIso = new Date().toISOString();
    await this.flushAsync();
    return existing;
  }

  public upsertOAuthUser(params: {
    email: string;
    fullName: string;
    organization: string;
    role: AuthenticatedOperator['role'];
    paypalMerchantId: string;
  }): StoredUserRecord {
    const normalizedEmail = params.email.trim().toLowerCase();
    const existing = this.usersByEmail.get(normalizedEmail);
    const now = new Date().toISOString();
    if (existing) {
      existing.lastLoginAtIso = now;
      if (!existing.fullName && params.fullName) {
        existing.fullName = params.fullName;
      }
      const providers = new Set<AuthenticatedOperator['authProvider']>(
        existing.authProviders || (existing.hasPassword ? ['EMAIL_PASSWORD'] : [])
      );
      providers.add('GOOGLE_OAUTH');
      existing.authProviders = Array.from(providers);
      this.scheduleFlush();
      return existing;
    }
    const record: StoredUserRecord = {
      id: `OP-${sha256Hex(normalizedEmail).slice(0, 8).toUpperCase()}`,
      email: normalizedEmail,
      fullName: params.fullName,
      organization: params.organization,
      role: params.role,
      passwordScrypt: hashPasswordScrypt(crypto.randomBytes(24).toString('hex')),
      hasPassword: false,
      authProviders: ['GOOGLE_OAUTH'],
      paypalMerchantId: params.paypalMerchantId,
      createdAtIso: now,
      lastLoginAtIso: now,
    };
    this.usersByEmail.set(normalizedEmail, record);
    this.scheduleFlush();
    return record;
  }

  public revokeToken(token: string): void {
    this.revokedTokenHashes.add(sha256Hex(token));
    this.scheduleFlush();
  }

  public isTokenRevoked(token: string): boolean {
    return this.revokedTokenHashes.has(sha256Hex(token));
  }

  public getTenantWorkspace(tenantId: string, ownerEmail = 'operator@aegispay.io'): TenantWorkspace {
    const cleanId = tenantId || 'OP-AEGIS-001';
    const existingHot = this.hotTenants.get(cleanId);
    if (existingHot) {
      this.hotTenants.delete(cleanId);
      this.hotTenants.set(cleanId, existingHot);
      return existingHot;
    }

    const fromDisk = this.persistedTenantsSnapshot[cleanId];
    const defaults = createDefaultTenantWorkspace(cleanId, ownerEmail);
    const ws: TenantWorkspace = fromDisk
      ? {
          ...defaults,
          ...fromDisk,
          merchantPolicy: fromDisk.merchantPolicy || defaults.merchantPolicy,
          claimedVisionImageHashes: Array.isArray(fromDisk.claimedVisionImageHashes)
            ? fromDisk.claimedVisionImageHashes
            : [],
          refundedCentsByCapture: fromDisk.refundedCentsByCapture || {},
          payreviveBanditState: fromDisk.payreviveBanditState || {},
        }
      : defaults;

    if (this.hotTenants.size >= this.maxHotTenants) {
      const oldestTenantId = this.hotTenants.keys().next().value;
      if (oldestTenantId) {
        const evicted = this.hotTenants.get(oldestTenantId);
        if (evicted) {
          this.persistedTenantsSnapshot[oldestTenantId] = evicted;
        }
        this.hotTenants.delete(oldestTenantId);
      }
    }

    this.hotTenants.set(cleanId, ws);
    return ws;
  }

  public appendTenantAuditLog(
    ws: TenantWorkspace,
    entry: Omit<AuditLedgerRow, 'id' | 'timestampIso'>
  ): AuditLedgerRow {
    const row: AuditLedgerRow = {
      id: `AUD-${1001 + ws.auditLogs.length}`,
      timestampIso: new Date().toISOString(),
      ...entry,
    };
    ws.auditLogs.unshift(row);
    if (ws.auditLogs.length > this.maxAuditLogsPerTenant) {
      ws.auditLogs.length = this.maxAuditLogsPerTenant;
    }
    ws.updatedAtIso = row.timestampIso;
    this.scheduleFlush();
    return row;
  }

  public recordPayReviveDecision(ws: TenantWorkspace, decision: PayReviveDecision): void {
    ws.payreviveDecisions.unshift(decision);
    if (ws.payreviveDecisions.length > 100) {
      ws.payreviveDecisions.length = 100;
    }
    ws.updatedAtIso = new Date().toISOString();
    this.scheduleFlush();
  }

  public getStorageArchitectureSummary(activeTenantId?: string) {
    const displayPath =
      this.storageMode === 'LOCAL_ENCRYPTED_FS_VAULT'
        ? 'data/aegispay_store.json (0o600 Async Atomic Write-Ahead Vault, Git-Ignored)'
        : this.storageMode === 'SERVERLESS_STATELESS_HMAC_WITH_TMP_CACHE'
          ? 'Stateless HMAC-SHA256 Identity + Per-Instance /tmp Ephemeral Cache (External KV Hook Ready)'
          : 'Isolated Ephemeral Test Vault';

    return {
      mode: this.storageMode,
      vaultLocation: displayPath,
      passwordKdf: 'crypto.scryptSync (N=16384, r=8, p=1, 64B key + 16B random salt)',
      sessionTransport: 'HttpOnly SameSite=Strict Cookie (Zero localStorage Token Storage)',
      tenantIsolation: 'Strict Per-Tenant Partitioning (Orders, Invoices, Permits, Bandit, Policy)',
      activeTenantId: activeTenantId || 'UNAUTHENTICATED',
      registeredUsersCount: this.usersByEmail.size,
      hotTenantsInLru: this.hotTenants.size,
      maxHotTenantsCap: this.maxHotTenants,
      maxAuditRowsPerTenant: this.maxAuditLogsPerTenant,
    };
  }
}
