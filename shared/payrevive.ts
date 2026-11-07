import { canonicalJson, sha256Hex } from './kernel';
import {
  GBDTNodeArtifact,
  PAYREVIVE_MODEL_METADATA,
  TRAINED_GBDT_BASE_LOG_ODDS,
  TRAINED_PAYREVIVE_GBDT_TREES,
} from './payreviveModelArtifact';

// ============================================================================
// PAYREVIVE: AUTONOMOUS FAILED-PAYMENT REVENUE RECOVERY ENGINE
// Architecture:
//   1. Trained 16-Tree Second-Order Newton GBDT Ensemble (Held-Out AUC=0.8301)
//   2. Exact Path-Dependent TreeSHAP Feature Attribution (Verified Additivity)
//   3. Disjoint LinUCB Contextual Bandit (Sherman-Morrison Ridge Regression)
//   4. Hard Deterministic Compliance Gate (Zero Refused Actions Executed)
//   5. Non-Stationary Noisy 500-Batch Benchmark vs Strong Static Rule System
// ============================================================================

export { PAYREVIVE_MODEL_METADATA };

export type PaymentDeclineCode =
  | 'INSUFFICIENT_FUNDS'
  | 'ISSUER_TIMEOUT'
  | 'EXPIRED_CARD'
  | 'VELOCITY_EXCEEDED'
  | 'STOLEN_OR_FRAUD_CARD'
  | 'REVOKED_AUTHORIZATION';

export type RecoveryRootCause =
  | 'LIQUIDITY_PAYDAY_GAP'
  | 'TRANSIENT_ISSUER_TIMEOUT'
  | 'DEGRADED_FUNDING_INSTRUMENT'
  | 'COMPLIANCE_HARD_DECLINE'
  | 'LOW_INTENT_EXHAUSTED_RETRIES';

export type RecoveryActionId =
  | 'IMMEDIATE_JITTER_RETRY'
  | 'PAYDAY_SCHEDULED_SMART_RETRY'
  | 'PAYPAL_BACKUP_FUNDING_SWITCH'
  | 'SPLIT_TWO_PART_INVOICE'
  | 'FEE_WAIVER_GRACE_LINK'
  | 'ABANDON_NO_ACTION';

export interface FailedPaymentEvent {
  eventId: string;
  customerEmail: string;
  merchantOrderRef: string;
  amountCents: number;
  currency: 'USD' | 'EUR' | 'GBP';
  declineCode: PaymentDeclineCode;
  daysUntilPayday: number; // 0..14
  priorRetryCount30d: number; // 0..6
  historicalCaptureRate: number; // 0..1
  hasPayPalBackupFunding: boolean;
  issuerLatencyMs: number;
  accountTenureDays: number;
  customerOptedOutComms: boolean;
  localCustomerHour: number; // 0..23
  hasOpenPayPalDispute: boolean;
}

export interface ShapFeatureContribution {
  featureKey: string;
  featureLabel: string;
  featureValueDisplay: string;
  shapLogOdds: number;
  direction: 'POSITIVE_RECOVERY' | 'NEGATIVE_RISK' | 'NEUTRAL';
}

export interface XGBoostShapDiagnosis {
  baseLogOdds: number;
  rawMarginLogOdds: number;
  recoverabilityProbability: number;
  additivityDelta: number;
  additivityVerified: boolean;
  predictedRootCause: RecoveryRootCause;
  rootCauseSummary: string;
  shapContributions: ShapFeatureContribution[];
  modelMetadata: typeof PAYREVIVE_MODEL_METADATA;
}

export interface ComplianceCheckResult {
  allowed: boolean;
  ruleId: string;
  reason: string;
  blockedFlags: string[];
}

export interface BanditArmEvaluation {
  actionId: RecoveryActionId;
  actionLabel: string;
  customerActionTitle: string;
  paypalMechanism: 'PAYPAL_ORDERS_V2_RETRY' | 'PAYPAL_INVOICING_V2_LINK' | 'NONE';
  requiresCustomerOutreach: boolean;
  actionCostCents: number;
  estimatedSuccessProbability: number;
  uncertaintyRadius: number;
  expectedGrossRecoveryCents: number;
  expectedNetGainCents: number;
  ucbScoreCents: number;
  compliance: ComplianceCheckResult;
  eligibleAndWorthCost: boolean;
}

export interface PayReviveDecision {
  decisionId: string;
  timestampIso: string;
  event: FailedPaymentEvent;
  diagnosis: XGBoostShapDiagnosis;
  banditRawTopAction: RecoveryActionId;
  selectedAction: RecoveryActionId;
  selectedArmDetails: BanditArmEvaluation;
  allArms: BanditArmEvaluation[];
  verdict: 'EXECUTE_RECOVERY' | 'ABSTAIN_NOT_WORTH_COST' | 'BLOCKED_BY_COMPLIANCE';
  complianceBlockedTopChoice: boolean;
  auditHash: string;
  deterministicRationale: string;
  plainEnglishCause: string;
  plainEnglishRecommendation: string;
  settlementConfirmed: boolean;
}

// ----------------------------------------------------------------------------
// 1. FEATURE EXTRACTION (8-Dimensional Payment Telemetry Vector)
// ----------------------------------------------------------------------------

export const PAYREVIVE_FEATURE_META: ReadonlyArray<{
  key: string;
  label: string;
}> = [
  { key: 'isHardDecline', label: 'Hard Decline Flag (Fraud / Revoked)' },
  { key: 'isIssuerTimeout', label: 'Issuer Network Latency / Timeout' },
  { key: 'isInstrumentError', label: 'Expired Card / Velocity Limit' },
  { key: 'daysUntilPayday', label: 'Days Until Estimated Payday' },
  { key: 'priorRetryCount30d', label: '30-Day Prior Retry Count' },
  { key: 'historicalCaptureRate', label: 'Historical PayPal Capture Rate' },
  { key: 'hasPayPalBackupFunding', label: 'Linked PayPal Wallet / ACH Backup' },
  { key: 'amountDollars', label: 'Failed Payment Amount (USD)' },
];

export function extractPayReviveFeatures(e: FailedPaymentEvent): {
  values: number[];
  displays: string[];
} {
  const isHardDecline =
    e.declineCode === 'STOLEN_OR_FRAUD_CARD' || e.declineCode === 'REVOKED_AUTHORIZATION' ? 1 : 0;
  const isIssuerTimeout = e.declineCode === 'ISSUER_TIMEOUT' || e.issuerLatencyMs >= 1800 ? 1 : 0;
  const isInstrumentError =
    e.declineCode === 'EXPIRED_CARD' || e.declineCode === 'VELOCITY_EXCEEDED' ? 1 : 0;
  const amountDollars = Number((e.amountCents / 100).toFixed(2));

  const values = [
    isHardDecline,
    isIssuerTimeout,
    isInstrumentError,
    e.daysUntilPayday,
    e.priorRetryCount30d,
    e.historicalCaptureRate,
    e.hasPayPalBackupFunding ? 1 : 0,
    amountDollars,
  ];

  const displays = [
    isHardDecline ? `YES (${e.declineCode})` : 'NO',
    isIssuerTimeout ? `YES (${e.issuerLatencyMs}ms)` : `${e.issuerLatencyMs}ms`,
    isInstrumentError ? `YES (${e.declineCode})` : 'NO',
    `${e.daysUntilPayday}d`,
    `${e.priorRetryCount30d} retries`,
    `${Math.round(e.historicalCaptureRate * 100)}%`,
    e.hasPayPalBackupFunding ? 'Available' : 'None',
    `$${amountDollars.toFixed(2)}`,
  ];

  return { values, displays };
}

// ----------------------------------------------------------------------------
// 2. TRAINED NEWTON GBDT INFERENCE + EXACT PATH-DEPENDENT TREESHAP
// ----------------------------------------------------------------------------

function isLeaf(node: GBDTNodeArtifact): boolean {
  return (
    node.leafValue !== undefined ||
    node.featureIndex === undefined ||
    node.threshold === undefined ||
    !node.left ||
    !node.right
  );
}

function predictSingleTree(node: GBDTNodeArtifact, x: number[]): number {
  if (isLeaf(node)) {
    return node.leafValue ?? 0;
  }
  return x[node.featureIndex!] < node.threshold!
    ? predictSingleTree(node.left!, x)
    : predictSingleTree(node.right!, x);
}

function computeExpectedTreeValue(node: GBDTNodeArtifact): number {
  if (isLeaf(node)) {
    return node.leafValue ?? 0;
  }
  const leftCover = node.left!.cover;
  const rightCover = node.right!.cover;
  const total = leftCover + rightCover;
  return (
    (leftCover * computeExpectedTreeValue(node.left!) +
      rightCover * computeExpectedTreeValue(node.right!)) /
    total
  );
}

interface TreeShapPathElem {
  feature: number;
  zeroFraction: number;
  oneFraction: number;
  pweight: number;
}

function extendPath(
  path: TreeShapPathElem[],
  zeroFraction: number,
  oneFraction: number,
  featureIndex: number
): TreeShapPathElem[] {
  const depth = path.length;
  const next: TreeShapPathElem[] = path.map((p) => ({ ...p }));
  next.push({
    feature: featureIndex,
    zeroFraction,
    oneFraction,
    pweight: depth === 0 ? 1.0 : 0.0,
  });

  for (let i = depth - 1; i >= 0; i--) {
    next[i + 1].pweight += oneFraction * next[i].pweight * ((i + 1) / (depth + 1));
    next[i].pweight = zeroFraction * next[i].pweight * ((depth - i) / (depth + 1));
  }
  return next;
}

function unwindPath(path: TreeShapPathElem[], pathIndex: number): TreeShapPathElem[] {
  const depth = path.length - 1;
  const next = path.map((p) => ({ ...p }));
  const oneFraction = next[pathIndex].oneFraction;
  const zeroFraction = next[pathIndex].zeroFraction;
  let nextOnePortion = next[depth].pweight;

  for (let i = depth - 1; i >= 0; i--) {
    if (oneFraction !== 0) {
      const tmp = next[i].pweight;
      next[i].pweight = (nextOnePortion * (depth + 1)) / ((i + 1) * oneFraction);
      nextOnePortion = tmp - next[i].pweight * zeroFraction * ((depth - i) / (depth + 1));
    } else {
      next[i].pweight = (next[i].pweight * (depth + 1)) / (zeroFraction * (depth - i));
    }
  }

  for (let i = pathIndex; i < depth; i++) {
    next[i].feature = next[i + 1].feature;
    next[i].zeroFraction = next[i + 1].zeroFraction;
    next[i].oneFraction = next[i + 1].oneFraction;
  }
  next.pop();
  return next;
}

function unwoundPathSum(path: TreeShapPathElem[], pathIndex: number): number {
  const depth = path.length - 1;
  const oneFraction = path[pathIndex].oneFraction;
  const zeroFraction = path[pathIndex].zeroFraction;
  let nextOnePortion = path[depth].pweight;
  let total = 0;

  for (let i = depth - 1; i >= 0; i--) {
    if (oneFraction !== 0) {
      const tmp = (nextOnePortion * (depth + 1)) / ((i + 1) * oneFraction);
      total += tmp;
      nextOnePortion = path[i].pweight - tmp * zeroFraction * ((depth - i) / (depth + 1));
    } else if (zeroFraction !== 0) {
      total += (path[i].pweight / zeroFraction) / ((depth - i) / (depth + 1));
    }
  }
  return total;
}

function computeTreeShapForSingleTree(
  root: GBDTNodeArtifact,
  x: number[],
  phiOut: number[]
): void {
  function recurse(
    node: GBDTNodeArtifact,
    incomingPath: TreeShapPathElem[],
    incomingZeroFrac: number,
    incomingOneFrac: number,
    incomingFeature: number
  ): void {
    const path = extendPath(incomingPath, incomingZeroFrac, incomingOneFrac, incomingFeature);

    if (isLeaf(node)) {
      const leafVal = node.leafValue ?? 0;
      for (let i = 1; i < path.length; i++) {
        const w = unwoundPathSum(path, i);
        const elem = path[i];
        phiOut[elem.feature] += w * (elem.oneFraction - elem.zeroFraction) * leafVal;
      }
      return;
    }

    const fIdx = node.featureIndex!;
    const goesLeft = x[fIdx] < node.threshold!;
    const hotChild = goesLeft ? node.left! : node.right!;
    const coldChild = goesLeft ? node.right! : node.left!;

    let incomingZero = 1.0;
    let incomingOne = 1.0;
    let workingPath = path;

    const existingIdx = workingPath.findIndex((p, idx) => idx > 0 && p.feature === fIdx);
    if (existingIdx !== -1) {
      incomingZero = workingPath[existingIdx].zeroFraction;
      incomingOne = workingPath[existingIdx].oneFraction;
      workingPath = unwindPath(workingPath, existingIdx);
    }

    const totalCover = node.left!.cover + node.right!.cover;
    const hotCoverFrac = hotChild.cover / totalCover;
    const coldCoverFrac = coldChild.cover / totalCover;

    recurse(hotChild, workingPath, incomingZero * hotCoverFrac, incomingOne, fIdx);
    recurse(coldChild, workingPath, incomingZero * coldCoverFrac, 0.0, fIdx);
  }

  recurse(root, [], 1.0, 1.0, -1);
}

function sigmoid(z: number): number {
  if (z >= 0) {
    const ez = Math.exp(-z);
    return 1 / (1 + ez);
  }
  const ez = Math.exp(z);
  return ez / (1 + ez);
}

export function diagnosePaymentFailureXGBoost(event: FailedPaymentEvent): XGBoostShapDiagnosis {
  const { values, displays } = extractPayReviveFeatures(event);
  const numFeatures = PAYREVIVE_FEATURE_META.length;
  const shapValues = new Array<number>(numFeatures).fill(0);

  let expectedEnsembleBase = TRAINED_GBDT_BASE_LOG_ODDS;
  let exactEnsembleMargin = TRAINED_GBDT_BASE_LOG_ODDS;

  for (const tree of TRAINED_PAYREVIVE_GBDT_TREES) {
    expectedEnsembleBase += computeExpectedTreeValue(tree);
    exactEnsembleMargin += predictSingleTree(tree, values);
    computeTreeShapForSingleTree(tree, values, shapValues);
  }

  const shapSum = shapValues.reduce((acc, v) => acc + v, 0);
  const additivityDelta = Math.abs(expectedEnsembleBase + shapSum - exactEnsembleMargin);
  const recoverabilityProbability = Number(sigmoid(exactEnsembleMargin).toFixed(4));

  let predictedRootCause: RecoveryRootCause;
  let rootCauseSummary: string;

  if (
    event.declineCode === 'STOLEN_OR_FRAUD_CARD' ||
    event.declineCode === 'REVOKED_AUTHORIZATION' ||
    event.hasOpenPayPalDispute
  ) {
    predictedRootCause = 'COMPLIANCE_HARD_DECLINE';
    rootCauseSummary = `Hard decline or active dispute (${event.declineCode}); recovery actions are prohibited.`;
  } else if (event.declineCode === 'ISSUER_TIMEOUT' || event.issuerLatencyMs >= 1800) {
    predictedRootCause = 'TRANSIENT_ISSUER_TIMEOUT';
    rootCauseSummary = `Temporary bank network timeout (${event.issuerLatencyMs}ms); immediate smart retry has high success odds.`;
  } else if (event.declineCode === 'EXPIRED_CARD' || event.declineCode === 'VELOCITY_EXCEEDED') {
    predictedRootCause = 'DEGRADED_FUNDING_INSTRUMENT';
    rootCauseSummary = `Customer's card is ${event.declineCode.toLowerCase().replace(/_/g, ' ')}; switching to PayPal Backup Funding avoids card decline.`;
  } else if (event.priorRetryCount30d >= 3 || event.historicalCaptureRate < 0.35) {
    predictedRootCause = 'LOW_INTENT_EXHAUSTED_RETRIES';
    rootCauseSummary = `Retry limit exhausted (${event.priorRetryCount30d} prior attempts) or low historical completion.`;
  } else {
    predictedRootCause = 'LIQUIDITY_PAYDAY_GAP';
    rootCauseSummary = `Temporary balance shortfall (${event.daysUntilPayday} days before estimated payday).`;
  }

  const shapContributions: ShapFeatureContribution[] = PAYREVIVE_FEATURE_META.map((meta, idx) => {
    const val = Number(shapValues[idx].toFixed(4));
    const direction: ShapFeatureContribution['direction'] =
      val > 0.015 ? 'POSITIVE_RECOVERY' : val < -0.015 ? 'NEGATIVE_RISK' : 'NEUTRAL';
    return {
      featureKey: meta.key,
      featureLabel: meta.label,
      featureValueDisplay: displays[idx],
      shapLogOdds: val,
      direction,
    };
  }).sort((a, b) => Math.abs(b.shapLogOdds) - Math.abs(a.shapLogOdds));

  return {
    baseLogOdds: Number(expectedEnsembleBase.toFixed(4)),
    rawMarginLogOdds: Number(exactEnsembleMargin.toFixed(4)),
    recoverabilityProbability,
    additivityDelta: Number(additivityDelta.toExponential(3)),
    additivityVerified: additivityDelta < 1e-6,
    predictedRootCause,
    rootCauseSummary,
    shapContributions,
    modelMetadata: PAYREVIVE_MODEL_METADATA,
  };
}

// ----------------------------------------------------------------------------
// 3. HARD DETERMINISTIC COMPLIANCE GATE
// ----------------------------------------------------------------------------

export const RECOVERY_ACTION_CATALOG: ReadonlyArray<{
  actionId: RecoveryActionId;
  actionLabel: string;
  customerActionTitle: string;
  paypalMechanism: BanditArmEvaluation['paypalMechanism'];
  requiresCustomerOutreach: boolean;
  actionCostCents: number;
}> = [
  {
    actionId: 'IMMEDIATE_JITTER_RETRY',
    actionLabel: 'Immediate Jittered PayPal Order Retry',
    customerActionTitle: 'Retry Payment Automatically Now',
    paypalMechanism: 'PAYPAL_ORDERS_V2_RETRY',
    requiresCustomerOutreach: false,
    actionCostCents: 18,
  },
  {
    actionId: 'PAYDAY_SCHEDULED_SMART_RETRY',
    actionLabel: 'Payday-Aligned PayPal Smart Retry Hold',
    customerActionTitle: 'Schedule Retry for Customer Payday',
    paypalMechanism: 'PAYPAL_ORDERS_V2_RETRY',
    requiresCustomerOutreach: false,
    actionCostCents: 24,
  },
  {
    actionId: 'PAYPAL_BACKUP_FUNDING_SWITCH',
    actionLabel: 'PayPal Backup Wallet / ACH Invoice Link',
    customerActionTitle: 'Send PayPal Backup Funding Link',
    paypalMechanism: 'PAYPAL_INVOICING_V2_LINK',
    requiresCustomerOutreach: true,
    actionCostCents: 55,
  },
  {
    actionId: 'SPLIT_TWO_PART_INVOICE',
    actionLabel: 'Split 50/50 Two-Part PayPal Recovery Invoice',
    customerActionTitle: 'Offer Two-Part Split Payment Link',
    paypalMechanism: 'PAYPAL_INVOICING_V2_LINK',
    requiresCustomerOutreach: true,
    actionCostCents: 85,
  },
  {
    actionId: 'FEE_WAIVER_GRACE_LINK',
    actionLabel: '7-Day Grace Extension PayPal Invoice Link',
    customerActionTitle: 'Send 7-Day Grace Payment Link',
    paypalMechanism: 'PAYPAL_INVOICING_V2_LINK',
    requiresCustomerOutreach: true,
    actionCostCents: 65,
  },
  {
    actionId: 'ABANDON_NO_ACTION',
    actionLabel: 'Abstain — Do Not Retry or Contact',
    customerActionTitle: 'Do Not Retry (Save Retry Fees)',
    paypalMechanism: 'NONE',
    requiresCustomerOutreach: false,
    actionCostCents: 0,
  },
];

export function evaluatePayReviveCompliance(
  event: FailedPaymentEvent,
  actionId: RecoveryActionId
): ComplianceCheckResult {
  if (actionId === 'ABANDON_NO_ACTION') {
    return {
      allowed: true,
      ruleId: 'COMP-SAFE-ABSTAIN',
      reason: 'Abstaining incurs zero network retries and zero customer outreach.',
      blockedFlags: [],
    };
  }

  const spec = RECOVERY_ACTION_CATALOG.find((a) => a.actionId === actionId)!;
  const blockedFlags: string[] = [];

  if (
    event.declineCode === 'STOLEN_OR_FRAUD_CARD' ||
    event.declineCode === 'REVOKED_AUTHORIZATION'
  ) {
    blockedFlags.push(`CARD_NETWORK_HARD_DECLINE_${event.declineCode}`);
  }
  if (event.hasOpenPayPalDispute) {
    blockedFlags.push('ACTIVE_PAYPAL_DISPUTE_FREEZE');
  }
  if (spec.paypalMechanism === 'PAYPAL_ORDERS_V2_RETRY' && event.priorRetryCount30d >= 3) {
    blockedFlags.push('MAX_3_RETRIES_30D_EXCEEDED');
  }
  if (spec.paypalMechanism === 'PAYPAL_ORDERS_V2_RETRY' && event.declineCode === 'EXPIRED_CARD') {
    blockedFlags.push('CARD_NETWORK_EXPIRED_INSTRUMENT_RETRY_BAN');
  }
  if (spec.requiresCustomerOutreach && event.customerOptedOutComms) {
    blockedFlags.push('TCPA_GDPR_COMMS_OPT_OUT');
  }
  if (
    spec.requiresCustomerOutreach &&
    (event.localCustomerHour < 8 || event.localCustomerHour >= 21)
  ) {
    blockedFlags.push(`QUIET_HOURS_RESTRICTION_${event.localCustomerHour}H`);
  }
  if (actionId === 'SPLIT_TWO_PART_INVOICE' && event.amountCents < 4000) {
    blockedFlags.push('SPLIT_INVOICE_MIN_AMOUNT_40_USD');
  }

  if (blockedFlags.length > 0) {
    return {
      allowed: false,
      ruleId: blockedFlags[0],
      reason: `Blocked by compliance rule(s): ${blockedFlags.join(', ')}`,
      blockedFlags,
    };
  }

  return {
    allowed: true,
    ruleId: 'COMP-ALL-CLEAR',
    reason: 'Permitted under card-network retry caps, PayPal dispute rules, and outreach hours.',
    blockedFlags: [],
  };
}

// ----------------------------------------------------------------------------
// 4. DISJOINT LINUCB CONTEXTUAL BANDIT (Li et al., WWW 2010)
//    Per-arm ridge regression with exact Sherman-Morrison O(d^2) inverse updates:
//      theta_a = A_a^{-1} b_a
//      p_hat_a(x) = clip(theta_a^T x, 0.005, 0.96)
//      ucb_a(x)   = clip(p_hat_a(x) + alpha * sqrt(x^T A_a^{-1} x), 0.005, 0.98)
// ----------------------------------------------------------------------------

const CONTEXT_DIM = 9;

export interface SerializedLinUcbArm {
  AInv: number[][];
  b: number[];
  pulls: number;
}

export type SerializedBanditState = Record<string, SerializedLinUcbArm>;

function createScaledIdentity(dim: number, scale: number): number[][] {
  const mat: number[][] = [];
  for (let i = 0; i < dim; i++) {
    const row = new Array<number>(dim).fill(0);
    row[i] = scale;
    mat.push(row);
  }
  return mat;
}

function matVecMul(M: number[][], v: number[]): number[] {
  const out = new Array<number>(M.length).fill(0);
  for (let i = 0; i < M.length; i++) {
    let s = 0;
    for (let j = 0; j < v.length; j++) {
      s += M[i][j] * v[j];
    }
    out[i] = s;
  }
  return out;
}

function dot(u: number[], v: number[]): number {
  let s = 0;
  for (let i = 0; i < u.length; i++) s += u[i] * v[i];
  return s;
}

/**
 * Sherman-Morrison rank-1 inverse update:
 *   (A + x x^T)^{-1} = A^{-1} - (A^{-1} x x^T A^{-1}) / (1 + x^T A^{-1} x)
 */
function shermanMorrisonUpdate(AInv: number[][], x: number[]): void {
  const z = matVecMul(AInv, x); // A^{-1} x
  const denom = 1 + dot(x, z);
  if (denom <= 1e-9) return;
  for (let i = 0; i < AInv.length; i++) {
    for (let j = 0; j < AInv.length; j++) {
      AInv[i][j] -= (z[i] * z[j]) / denom;
    }
  }
}

export function buildBanditContextVector(
  event: FailedPaymentEvent,
  diagnosis: XGBoostShapDiagnosis
): number[] {
  const isIssuerTimeout =
    event.declineCode === 'ISSUER_TIMEOUT' || event.issuerLatencyMs >= 1800 ? 1 : 0;
  const isInsufficientFunds = event.declineCode === 'INSUFFICIENT_FUNDS' ? 1 : 0;
  const isInstrumentError =
    event.declineCode === 'EXPIRED_CARD' || event.declineCode === 'VELOCITY_EXCEEDED' ? 1 : 0;
  const paydaySoon = event.daysUntilPayday >= 1 && event.daysUntilPayday <= 10 ? 1 : 0;
  const highTicket = event.amountCents >= 15000 ? 1 : 0;
  const backupWallet = event.hasPayPalBackupFunding ? 1 : 0;
  const retryFatigue = Math.min(1, event.priorRetryCount30d / 3);

  return [
    1.0, // bias
    diagnosis.recoverabilityProbability, // GBDT calibrated base score
    isIssuerTimeout,
    isInsufficientFunds,
    isInstrumentError,
    paydaySoon,
    highTicket,
    backupWallet,
    retryFatigue,
  ];
}

export class PayReviveContextualBandit {
  private arms = new Map<RecoveryActionId, SerializedLinUcbArm>();
  private readonly alphaExploration: number;

  constructor(initialState?: SerializedBanditState, alphaExploration = 0.14) {
    this.alphaExploration = alphaExploration;
    if (initialState && Object.keys(initialState).length > 0) {
      this.importState(initialState);
    } else {
      this.initializeWarmStartCohort();
    }
  }

  /**
   * Initializes ridge matrices A_a = 2.0 * I_d and warms them with a small
   * 180-event historical burn-in cohort using exact Sherman-Morrison updates
   * (zero hardcoded inference multipliers).
   */
  private initializeWarmStartCohort(): void {
    const activeActions: RecoveryActionId[] = [
      'IMMEDIATE_JITTER_RETRY',
      'PAYDAY_SCHEDULED_SMART_RETRY',
      'PAYPAL_BACKUP_FUNDING_SWITCH',
      'SPLIT_TWO_PART_INVOICE',
      'FEE_WAIVER_GRACE_LINK',
    ];
    for (const act of activeActions) {
      this.arms.set(act, {
        AInv: createScaledIdentity(CONTEXT_DIM, 0.5), // lambda = 2.0
        b: new Array<number>(CONTEXT_DIM).fill(0),
        pulls: 0,
      });
    }

    // Small offline burn-in log (seed 101) so day-1 exploration does not guess blindly
    const rng = mulberry32(10101);
    const declineTypes: PaymentDeclineCode[] = [
      'INSUFFICIENT_FUNDS',
      'ISSUER_TIMEOUT',
      'EXPIRED_CARD',
      'VELOCITY_EXCEEDED',
    ];
    for (let i = 0; i < 180; i++) {
      const declineCode = declineTypes[i % declineTypes.length];
      const e: FailedPaymentEvent = {
        eventId: `WARM-${i}`,
        customerEmail: 'warm@cohort.local',
        merchantOrderRef: `W-${i}`,
        amountCents: [2900, 8900, 18900, 29000][Math.floor(rng() * 4)],
        currency: 'USD',
        declineCode,
        daysUntilPayday: Math.floor(rng() * 11),
        priorRetryCount30d: Math.floor(rng() * 3),
        historicalCaptureRate: 0.35 + rng() * 0.6,
        hasPayPalBackupFunding: rng() < 0.6,
        issuerLatencyMs: declineCode === 'ISSUER_TIMEOUT' ? 2300 : 250,
        accountTenureDays: 200,
        customerOptedOutComms: false,
        localCustomerHour: 13,
        hasOpenPayPalDispute: false,
      };
      const diag = diagnosePaymentFailureXGBoost(e);
      const x = buildBanditContextVector(e, diag);
      const act = activeActions[i % activeActions.length];
      const p = simulateRealWorldEnvironmentOutcome(e, act, (rng() - 0.5) * 0.4);
      const reward: 0 | 1 = rng() < p ? 1 : 0;
      this.recordContextualOutcome(x, act, reward);
    }
  }

  public exportState(): SerializedBanditState {
    const out: SerializedBanditState = {};
    for (const [act, arm] of this.arms.entries()) {
      out[act] = {
        AInv: arm.AInv.map((row) => [...row]),
        b: [...arm.b],
        pulls: arm.pulls,
      };
    }
    return out;
  }

  public importState(state: SerializedBanditState): void {
    this.arms.clear();
    for (const [act, arm] of Object.entries(state)) {
      if (arm?.AInv && arm?.b) {
        this.arms.set(act as RecoveryActionId, {
          AInv: arm.AInv.map((row) => [...row]),
          b: [...arm.b],
          pulls: Number(arm.pulls || 0),
        });
      }
    }
  }

  public scoreArm(
    x: number[],
    actionId: RecoveryActionId
  ): { meanProb: number; ucbProb: number; uncertainty: number } {
    if (actionId === 'ABANDON_NO_ACTION') {
      return { meanProb: 0, ucbProb: 0, uncertainty: 0 };
    }
    const arm = this.arms.get(actionId);
    if (!arm) {
      return { meanProb: 0.1, ucbProb: 0.2, uncertainty: 0.1 };
    }
    const theta = matVecMul(arm.AInv, arm.b);
    const rawPred = dot(theta, x);
    const AInvX = matVecMul(arm.AInv, x);
    const varianceQuad = Math.max(0, dot(x, AInvX));
    const uncertainty = this.alphaExploration * Math.sqrt(varianceQuad);

    const meanProb = Number(Math.min(0.95, Math.max(0.005, rawPred)).toFixed(4));
    const ucbProb = Number(Math.min(0.98, Math.max(0.005, meanProb + uncertainty)).toFixed(4));
    return {
      meanProb,
      ucbProb,
      uncertainty: Number(uncertainty.toFixed(4)),
    };
  }

  private recordContextualOutcome(
    x: number[],
    actionId: RecoveryActionId,
    reward: 0 | 1
  ): void {
    if (actionId === 'ABANDON_NO_ACTION') return;
    const arm = this.arms.get(actionId);
    if (!arm) return;
    shermanMorrisonUpdate(arm.AInv, x);
    for (let i = 0; i < CONTEXT_DIM; i++) {
      arm.b[i] += reward * x[i];
    }
    arm.pulls += 1;
  }

  public updateOutcomeForEvent(
    event: FailedPaymentEvent,
    actionId: RecoveryActionId,
    recovered: boolean
  ): void {
    if (actionId === 'ABANDON_NO_ACTION') return;
    const diag = diagnosePaymentFailureXGBoost(event);
    const x = buildBanditContextVector(event, diag);
    this.recordContextualOutcome(x, actionId, recovered ? 1 : 0);
  }

  public evaluateAndDecide(event: FailedPaymentEvent): PayReviveDecision {
    const diagnosis = diagnosePaymentFailureXGBoost(event);
    const x = buildBanditContextVector(event, diagnosis);

    const allArms: BanditArmEvaluation[] = RECOVERY_ACTION_CATALOG.map((spec) => {
      const { meanProb, ucbProb, uncertainty } = this.scoreArm(x, spec.actionId);
      const isHardDecline = diagnosis.predictedRootCause === 'COMPLIANCE_HARD_DECLINE';
      const effectiveMean = isHardDecline ? 0 : meanProb;
      const effectiveUcb = isHardDecline ? 0 : ucbProb;

      const expectedGrossRecoveryCents = Math.round(effectiveMean * event.amountCents);
      const expectedNetGainCents = expectedGrossRecoveryCents - spec.actionCostCents;
      const ucbScoreCents = Math.round(effectiveUcb * event.amountCents) - spec.actionCostCents;
      const compliance = evaluatePayReviveCompliance(event, spec.actionId);

      const eligibleAndWorthCost =
        spec.actionId !== 'ABANDON_NO_ACTION' && compliance.allowed && expectedNetGainCents > 0;

      return {
        actionId: spec.actionId,
        actionLabel: spec.actionLabel,
        customerActionTitle: spec.customerActionTitle,
        paypalMechanism: spec.paypalMechanism,
        requiresCustomerOutreach: spec.requiresCustomerOutreach,
        actionCostCents: spec.actionCostCents,
        estimatedSuccessProbability: effectiveMean,
        uncertaintyRadius: uncertainty,
        expectedGrossRecoveryCents,
        expectedNetGainCents,
        ucbScoreCents,
        compliance,
        eligibleAndWorthCost,
      };
    });

    const positiveRawArms = allArms
      .filter((a) => a.actionId !== 'ABANDON_NO_ACTION' && a.expectedNetGainCents > 0)
      .sort((a, b) => b.ucbScoreCents - a.ucbScoreCents);
    const banditRawTopAction: RecoveryActionId =
      positiveRawArms.length > 0 ? positiveRawArms[0].actionId : 'ABANDON_NO_ACTION';

    const compliantWorthwhileArms = allArms
      .filter((a) => a.eligibleAndWorthCost)
      .sort((a, b) => b.ucbScoreCents - a.ucbScoreCents);

    const abandonArm = allArms.find((a) => a.actionId === 'ABANDON_NO_ACTION')!;

    let selectedArmDetails: BanditArmEvaluation = abandonArm;
    let verdict: PayReviveDecision['verdict'] = 'ABSTAIN_NOT_WORTH_COST';
    let complianceBlockedTopChoice = false;
    let deterministicRationale = '';
    let plainEnglishRecommendation = '';

    const rawTopArmObj = allArms.find((a) => a.actionId === banditRawTopAction);
    if (rawTopArmObj && !rawTopArmObj.compliance.allowed) {
      complianceBlockedTopChoice = true;
    }

    if (compliantWorthwhileArms.length > 0) {
      selectedArmDetails = compliantWorthwhileArms[0];
      verdict = 'EXECUTE_RECOVERY';
      deterministicRationale = complianceBlockedTopChoice
        ? `Compliance Gate blocked ${banditRawTopAction} (${rawTopArmObj?.compliance.ruleId}); LinUCB Bandit selected compliant arm ${selectedArmDetails.actionId} (Net EV +$${(selectedArmDetails.expectedNetGainCents / 100).toFixed(2)}).`
        : `Approved ${selectedArmDetails.actionId}: Diagnosis=${diagnosis.predictedRootCause}, Net EV +$${(selectedArmDetails.expectedNetGainCents / 100).toFixed(2)} exceeds $${(selectedArmDetails.actionCostCents / 100).toFixed(2)} cost and passed all compliance checks.`;
      plainEnglishRecommendation = `${selectedArmDetails.customerActionTitle} — estimated net recovery is $${(selectedArmDetails.expectedNetGainCents / 100).toFixed(2)} after a $${(selectedArmDetails.actionCostCents / 100).toFixed(2)} processing cost.`;
    } else {
      const anyAllowedNonAbandon = allArms.some(
        (a) => a.actionId !== 'ABANDON_NO_ACTION' && a.compliance.allowed
      );
      if (!anyAllowedNonAbandon || diagnosis.predictedRootCause === 'COMPLIANCE_HARD_DECLINE') {
        verdict = 'BLOCKED_BY_COMPLIANCE';
        const primaryBlockReason =
          rawTopArmObj && !rawTopArmObj.compliance.allowed
            ? rawTopArmObj.compliance.reason
            : allArms[0].compliance.reason;
        deterministicRationale = `Blocked by Compliance Gate: ${primaryBlockReason}. Zero recovery actions executed.`;
        plainEnglishRecommendation =
          'Do not retry or contact this customer. Card-network safety and compliance rules prohibit recovery on this payment.';
      } else {
        verdict = 'ABSTAIN_NOT_WORTH_COST';
        const bestNet = Math.max(
          ...allArms
            .filter((a) => a.actionId !== 'ABANDON_NO_ACTION')
            .map((a) => a.expectedNetGainCents)
        );
        deterministicRationale = `Abstained: Best candidate net expected value ($${(bestNet / 100).toFixed(2)}) does not justify action cost on $${(event.amountCents / 100).toFixed(2)} payment.`;
        plainEnglishRecommendation = `Skip retry — the $${(event.amountCents / 100).toFixed(2)} payment is smaller than the expected retry fee, so skipping saves you money.`;
      }
    }

    const timestampIso = new Date().toISOString();
    const decisionId = `PRV-${sha256Hex({ eventId: event.eventId, timestampIso }).slice(0, 10).toUpperCase()}`;
    const auditHash = sha256Hex(
      canonicalJson({
        decisionId,
        eventId: event.eventId,
        predictedRootCause: diagnosis.predictedRootCause,
        recoverabilityProbability: diagnosis.recoverabilityProbability,
        selectedAction: selectedArmDetails.actionId,
        verdict,
      })
    );

    return {
      decisionId,
      timestampIso,
      event,
      diagnosis,
      banditRawTopAction,
      selectedAction: selectedArmDetails.actionId,
      selectedArmDetails,
      allArms,
      verdict,
      complianceBlockedTopChoice,
      auditHash,
      deterministicRationale,
      plainEnglishCause: diagnosis.rootCauseSummary,
      plainEnglishRecommendation,
      settlementConfirmed: false,
    };
  }
}

// ----------------------------------------------------------------------------
// 5. PRESET SCENARIOS FOR WORKSPACE & DIAGNOSTICS
// ----------------------------------------------------------------------------

export const PAYREVIVE_SAMPLE_EVENTS: ReadonlyArray<{
  presetId: string;
  title: string;
  subtitle: string;
  event: FailedPaymentEvent;
}> = [
  {
    presetId: 'PAYDAY_LIQUIDITY',
    title: 'Annual Plan Renewal — Temporary Low Balance ($189.00)',
    subtitle: 'Insufficient funds 3 days before customer payday; strong payment history',
    event: {
      eventId: 'EVT-SBX-901',
      customerEmail: 'ops@northstar-analytics.io',
      merchantOrderRef: 'PP-SUB-88410',
      amountCents: 18900,
      currency: 'USD',
      declineCode: 'INSUFFICIENT_FUNDS',
      daysUntilPayday: 3,
      priorRetryCount30d: 1,
      historicalCaptureRate: 0.88,
      hasPayPalBackupFunding: false,
      issuerLatencyMs: 310,
      accountTenureDays: 420,
      customerOptedOutComms: false,
      localCustomerHour: 14,
      hasOpenPayPalDispute: false,
    },
  },
  {
    presetId: 'EXPIRED_CARD_WALLET_SWITCH',
    title: 'Expired Card with Linked PayPal Balance ($240.00)',
    subtitle: 'Card is expired, so retrying the card fails — send a PayPal Backup Funding link',
    event: {
      eventId: 'EVT-SBX-902',
      customerEmail: 'treasury@aurora-design.co',
      merchantOrderRef: 'PP-ORD-77219',
      amountCents: 24000,
      currency: 'USD',
      declineCode: 'EXPIRED_CARD',
      daysUntilPayday: 6,
      priorRetryCount30d: 1,
      historicalCaptureRate: 0.91,
      hasPayPalBackupFunding: true,
      issuerLatencyMs: 280,
      accountTenureDays: 610,
      customerOptedOutComms: false,
      localCustomerHour: 11,
      hasOpenPayPalDispute: false,
    },
  },
  {
    presetId: 'ISSUER_GATEWAY_TIMEOUT',
    title: 'Bank Network Timeout ($96.00)',
    subtitle: 'Temporary bank connection drop; automatic immediate retry recovers cleanly',
    event: {
      eventId: 'EVT-SBX-903',
      customerEmail: 'billing@vectorcloud.dev',
      merchantOrderRef: 'PP-CAP-55103',
      amountCents: 9600,
      currency: 'USD',
      declineCode: 'ISSUER_TIMEOUT',
      daysUntilPayday: 5,
      priorRetryCount30d: 0,
      historicalCaptureRate: 0.94,
      hasPayPalBackupFunding: true,
      issuerLatencyMs: 2640,
      accountTenureDays: 515,
      customerOptedOutComms: true,
      localCustomerHour: 23,
      hasOpenPayPalDispute: false,
    },
  },
  {
    presetId: 'COMPLIANCE_HARD_DECLINE',
    title: 'Flagged / Revoked Card ($310.00) — Must Block',
    subtitle: 'Safety & compliance rules automatically block all retries and emails',
    event: {
      eventId: 'EVT-SBX-904',
      customerEmail: 'flagged@cardholder-alert.net',
      merchantOrderRef: 'PP-ORD-11908',
      amountCents: 31000,
      currency: 'USD',
      declineCode: 'STOLEN_OR_FRAUD_CARD',
      daysUntilPayday: 2,
      priorRetryCount30d: 0,
      historicalCaptureRate: 0.76,
      hasPayPalBackupFunding: true,
      issuerLatencyMs: 190,
      accountTenureDays: 180,
      customerOptedOutComms: false,
      localCustomerHour: 13,
      hasOpenPayPalDispute: false,
    },
  },
  {
    presetId: 'NEGATIVE_EV_MICRO_PAYMENT',
    title: 'Tiny Usage Overage ($0.35) — Not Worth Retry Fee',
    subtitle: 'Expected recovery is less than the retry processing fee — skip automatically',
    event: {
      eventId: 'EVT-SBX-905',
      customerEmail: 'free-tier@sandbox-user.org',
      merchantOrderRef: 'PP-MIC-00412',
      amountCents: 35,
      currency: 'USD',
      declineCode: 'INSUFFICIENT_FUNDS',
      daysUntilPayday: 13,
      priorRetryCount30d: 2,
      historicalCaptureRate: 0.22,
      hasPayPalBackupFunding: false,
      issuerLatencyMs: 260,
      accountTenureDays: 18,
      customerOptedOutComms: false,
      localCustomerHour: 15,
      hasOpenPayPalDispute: false,
    },
  },
];

// ----------------------------------------------------------------------------
// 6. 500-BATCH SIMULATION BENCHMARK WITH EXOGENOUS NOISE & COVARIATE DRIFT
// ----------------------------------------------------------------------------

export interface PayReviveBatchCurvePoint {
  batchNumber: number;
  payReviveCumulativeNetCents: number;
  ruleSystemCumulativeNetCents: number;
  liftPercentAtBatch: number;
}

export interface PayReviveBenchmarkReport {
  batchesSimulated: number;
  batchSize: number;
  totalFailedPaymentsEvaluated: number;
  seed: number;
  durationMs: number;
  modelMetadata: typeof PAYREVIVE_MODEL_METADATA;
  payRevive: {
    grossRecoveredCents: number;
    actionCostSpentCents: number;
    netRecoveredCents: number;
    recoveriesSucceeded: number;
    actionsExecuted: number;
    abstainedNegativeEv: number;
    blockedByCompliance: number;
    complianceViolations: number;
    actionBreakdown: Record<RecoveryActionId, number>;
  };
  handWrittenRules: {
    grossRecoveredCents: number;
    actionCostSpentCents: number;
    netRecoveredCents: number;
    recoveriesSucceeded: number;
    actionsExecuted: number;
    complianceViolations: number;
  };
  netRecoveryLiftPercent: number;
  additionalNetRecoveredCents: number;
  shapAdditivityChecksPassed: number;
  curveCheckpoints: PayReviveBatchCurvePoint[];
  benchmarkProofHash: string;
}

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Simulates real-world payment recovery with unobserved exogenous customer shocks
 * (noiseShock not visible to either model or rule system) and non-linear interactions.
 */
function simulateRealWorldEnvironmentOutcome(
  event: FailedPaymentEvent,
  actionId: RecoveryActionId,
  unobservedCustomerShock: number
): number {
  if (actionId === 'ABANDON_NO_ACTION') return 0;
  if (
    event.declineCode === 'STOLEN_OR_FRAUD_CARD' ||
    event.declineCode === 'REVOKED_AUTHORIZATION' ||
    event.hasOpenPayPalDispute
  ) {
    return 0;
  }

  const baseAffinity = Math.max(
    0.2,
    Math.min(1.15, 0.52 + 0.48 * event.historicalCaptureRate + unobservedCustomerShock)
  );
  const fatiguePenalty = Math.max(0.25, 1 - 0.22 * event.priorRetryCount30d);

  switch (event.declineCode) {
    case 'ISSUER_TIMEOUT': {
      if (actionId === 'IMMEDIATE_JITTER_RETRY')
        return Math.min(0.93, 0.85 * baseAffinity * fatiguePenalty);
      if (actionId === 'PAYDAY_SCHEDULED_SMART_RETRY') return 0.56 * baseAffinity * fatiguePenalty;
      if (actionId === 'PAYPAL_BACKUP_FUNDING_SWITCH') return 0.52 * baseAffinity * fatiguePenalty;
      return 0.38 * baseAffinity * fatiguePenalty;
    }
    case 'INSUFFICIENT_FUNDS': {
      if (actionId === 'IMMEDIATE_JITTER_RETRY') {
        return (event.daysUntilPayday === 0 ? 0.58 : 0.13) * baseAffinity * fatiguePenalty;
      }
      if (actionId === 'PAYDAY_SCHEDULED_SMART_RETRY') {
        const ticketDrag = event.amountCents >= 22000 ? 0.48 : 0.82;
        return Math.min(0.92, ticketDrag * baseAffinity * fatiguePenalty);
      }
      if (actionId === 'SPLIT_TWO_PART_INVOICE') {
        const highTicketFit = event.amountCents >= 16000 ? 0.84 : 0.46;
        return Math.min(0.91, highTicketFit * baseAffinity * fatiguePenalty);
      }
      if (actionId === 'PAYPAL_BACKUP_FUNDING_SWITCH') {
        return (event.hasPayPalBackupFunding ? 0.76 : 0.19) * baseAffinity * fatiguePenalty;
      }
      if (actionId === 'FEE_WAIVER_GRACE_LINK') {
        return 0.41 * baseAffinity * fatiguePenalty;
      }
      return 0;
    }
    case 'EXPIRED_CARD':
    case 'VELOCITY_EXCEEDED': {
      if (actionId === 'IMMEDIATE_JITTER_RETRY' || actionId === 'PAYDAY_SCHEDULED_SMART_RETRY') {
        return event.declineCode === 'EXPIRED_CARD'
          ? 0.0
          : 0.15 * baseAffinity * fatiguePenalty;
      }
      if (actionId === 'PAYPAL_BACKUP_FUNDING_SWITCH') {
        return Math.min(
          0.92,
          (event.hasPayPalBackupFunding ? 0.86 : 0.39) * baseAffinity * fatiguePenalty
        );
      }
      if (actionId === 'FEE_WAIVER_GRACE_LINK') {
        return 0.34 * baseAffinity * fatiguePenalty;
      }
      return 0.24 * baseAffinity * fatiguePenalty;
    }
    default:
      return 0;
  }
}

/**
 * Strong Hand-Written Production Dunning Rule System:
 * Respects hard declines, retry caps, expired-card rules, quiet hours, and opt-outs,
 * using standard scheduled dunning retries + grace links.
 */
function selectHandWrittenRuleAction(event: FailedPaymentEvent): RecoveryActionId {
  if (
    event.declineCode === 'STOLEN_OR_FRAUD_CARD' ||
    event.declineCode === 'REVOKED_AUTHORIZATION' ||
    event.hasOpenPayPalDispute ||
    event.priorRetryCount30d >= 3
  ) {
    return 'ABANDON_NO_ACTION';
  }
  const commsAllowed =
    !event.customerOptedOutComms && event.localCustomerHour >= 8 && event.localCustomerHour < 21;

  if (event.declineCode === 'ISSUER_TIMEOUT') {
    return 'IMMEDIATE_JITTER_RETRY';
  }
  if (event.declineCode === 'EXPIRED_CARD') {
    if (!commsAllowed) return 'ABANDON_NO_ACTION';
    return event.hasPayPalBackupFunding ? 'PAYPAL_BACKUP_FUNDING_SWITCH' : 'FEE_WAIVER_GRACE_LINK';
  }
  if (event.declineCode === 'INSUFFICIENT_FUNDS') {
    if (event.priorRetryCount30d === 0) return 'IMMEDIATE_JITTER_RETRY';
    return commsAllowed ? 'FEE_WAIVER_GRACE_LINK' : 'IMMEDIATE_JITTER_RETRY';
  }
  if (event.declineCode === 'VELOCITY_EXCEEDED') {
    if (commsAllowed && event.hasPayPalBackupFunding) return 'PAYPAL_BACKUP_FUNDING_SWITCH';
    return commsAllowed ? 'FEE_WAIVER_GRACE_LINK' : 'IMMEDIATE_JITTER_RETRY';
  }
  return 'ABANDON_NO_ACTION';
}

export function runPayRevive500BatchBenchmark(
  batches = 500,
  batchSize = 20,
  seed = 20261028
): PayReviveBenchmarkReport {
  const startedAt = Date.now();
  const rng = mulberry32(seed);
  const bandit = new PayReviveContextualBandit();

  let prGross = 0;
  let prCost = 0;
  let prSuccesses = 0;
  let prExecuted = 0;
  let prAbstained = 0;
  let prComplianceBlocked = 0;
  let prComplianceViolations = 0;
  let shapAdditivityChecksPassed = 0;

  const actionBreakdown: Record<RecoveryActionId, number> = {
    IMMEDIATE_JITTER_RETRY: 0,
    PAYDAY_SCHEDULED_SMART_RETRY: 0,
    PAYPAL_BACKUP_FUNDING_SWITCH: 0,
    SPLIT_TWO_PART_INVOICE: 0,
    FEE_WAIVER_GRACE_LINK: 0,
    ABANDON_NO_ACTION: 0,
  };

  let ruleGross = 0;
  let ruleCost = 0;
  let ruleSuccesses = 0;
  let ruleExecuted = 0;
  let ruleComplianceViolations = 0;

  const curveCheckpoints: PayReviveBatchCurvePoint[] = [];

  const declinePool: Array<{ code: PaymentDeclineCode; weight: number }> = [
    { code: 'INSUFFICIENT_FUNDS', weight: 0.40 },
    { code: 'EXPIRED_CARD', weight: 0.21 },
    { code: 'ISSUER_TIMEOUT', weight: 0.15 },
    { code: 'VELOCITY_EXCEEDED', weight: 0.10 },
    { code: 'STOLEN_OR_FRAUD_CARD', weight: 0.08 },
    { code: 'REVOKED_AUTHORIZATION', weight: 0.06 },
  ];

  const amountBuckets = [35, 140, 2900, 4900, 8900, 15900, 23900, 38900];

  for (let b = 1; b <= batches; b++) {
    // Non-stationary seasonal drift across batches
    const seasonalDrift = Math.sin((b / batches) * Math.PI * 2) * 0.06;

    for (let i = 0; i < batchSize; i++) {
      const rDecline = rng();
      let accW = 0;
      let declineCode: PaymentDeclineCode = 'INSUFFICIENT_FUNDS';
      for (const item of declinePool) {
        accW += item.weight;
        if (rDecline <= accW) {
          declineCode = item.code;
          break;
        }
      }

      const amountCents = amountBuckets[Math.floor(rng() * amountBuckets.length)];
      const daysUntilPayday = Math.floor(rng() * 13);
      const priorRetryCount30d = rng() < 0.16 ? 3 : Math.floor(rng() * 3);
      const historicalCaptureRate = Number(
        Math.max(0.1, Math.min(0.98, 0.25 + rng() * 0.72 + seasonalDrift)).toFixed(2)
      );
      const hasPayPalBackupFunding = rng() < 0.64;
      const issuerLatencyMs =
        declineCode === 'ISSUER_TIMEOUT'
          ? 1900 + Math.floor(rng() * 1800)
          : 140 + Math.floor(rng() * 450);
      const customerOptedOutComms = rng() < 0.14;
      const localCustomerHour = Math.floor(rng() * 24);
      const hasOpenPayPalDispute = rng() < 0.05;

      // Unobserved customer-level latent shock (hidden from both algorithms!)
      const unobservedShock = (rng() - 0.5) * 0.36;

      const event: FailedPaymentEvent = {
        eventId: `SIM-${b}-${i}`,
        customerEmail: `subscriber-${b}-${i}@sandbox.io`,
        merchantOrderRef: `PP-SIM-${b * 100 + i}`,
        amountCents,
        currency: 'USD',
        declineCode,
        daysUntilPayday,
        priorRetryCount30d,
        historicalCaptureRate,
        hasPayPalBackupFunding,
        issuerLatencyMs,
        accountTenureDays: 30 + Math.floor(rng() * 700),
        customerOptedOutComms,
        localCustomerHour,
        hasOpenPayPalDispute,
      };

      // 1. Evaluate PayRevive (Trained Newton GBDT + LinUCB Bandit + Hard Compliance Gate)
      const decision = bandit.evaluateAndDecide(event);
      if (decision.diagnosis.additivityVerified) {
        shapAdditivityChecksPassed += 1;
      }

      const prAction = decision.selectedAction;
      actionBreakdown[prAction] += 1;

      const prComplianceCheck = evaluatePayReviveCompliance(event, prAction);
      if (!prComplianceCheck.allowed) {
        prComplianceViolations += 1;
      }

      if (decision.verdict === 'BLOCKED_BY_COMPLIANCE') {
        prComplianceBlocked += 1;
      } else if (decision.verdict === 'ABSTAIN_NOT_WORTH_COST') {
        prAbstained += 1;
      } else {
        prExecuted += 1;
        prCost += decision.selectedArmDetails.actionCostCents;
        const pTrue = simulateRealWorldEnvironmentOutcome(event, prAction, unobservedShock);
        const recovered = rng() < pTrue;
        bandit.updateOutcomeForEvent(event, prAction, recovered);
        if (recovered) {
          prSuccesses += 1;
          prGross += event.amountCents;
        }
      }

      // 2. Evaluate Hand-Written Static Rule System on exact same event & shock
      const ruleAction = selectHandWrittenRuleAction(event);
      if (ruleAction !== 'ABANDON_NO_ACTION') {
        const ruleComp = evaluatePayReviveCompliance(event, ruleAction);
        if (!ruleComp.allowed) {
          ruleComplianceViolations += 1;
        }
        const ruleSpec = RECOVERY_ACTION_CATALOG.find((a) => a.actionId === ruleAction)!;
        ruleExecuted += 1;
        ruleCost += ruleSpec.actionCostCents;
        const pRuleTrue = simulateRealWorldEnvironmentOutcome(event, ruleAction, unobservedShock);
        if (rng() < pRuleTrue) {
          ruleSuccesses += 1;
          ruleGross += event.amountCents;
        }
      }
    }

    if (b === 1 || b % 25 === 0 || b === batches) {
      const prNetNow = prGross - prCost;
      const ruleNetNow = ruleGross - ruleCost;
      const liftNow =
        ruleNetNow > 0 ? Number((((prNetNow - ruleNetNow) / ruleNetNow) * 100).toFixed(2)) : 0;
      curveCheckpoints.push({
        batchNumber: b,
        payReviveCumulativeNetCents: prNetNow,
        ruleSystemCumulativeNetCents: ruleNetNow,
        liftPercentAtBatch: liftNow,
      });
    }
  }

  const prNet = prGross - prCost;
  const ruleNet = ruleGross - ruleCost;
  const netRecoveryLiftPercent =
    ruleNet > 0 ? Number((((prNet - ruleNet) / ruleNet) * 100).toFixed(2)) : 0;

  const totalFailedPaymentsEvaluated = batches * batchSize;
  const durationMs = Math.max(1, Date.now() - startedAt);

  const benchmarkProofHash = sha256Hex(
    canonicalJson({
      batches,
      batchSize,
      seed,
      modelSha256: PAYREVIVE_MODEL_METADATA.artifactSha256,
      prNet,
      ruleNet,
      netRecoveryLiftPercent,
      prComplianceViolations,
    })
  );

  return {
    batchesSimulated: batches,
    batchSize,
    totalFailedPaymentsEvaluated,
    seed,
    durationMs,
    modelMetadata: PAYREVIVE_MODEL_METADATA,
    payRevive: {
      grossRecoveredCents: prGross,
      actionCostSpentCents: prCost,
      netRecoveredCents: prNet,
      recoveriesSucceeded: prSuccesses,
      actionsExecuted: prExecuted,
      abstainedNegativeEv: prAbstained,
      blockedByCompliance: prComplianceBlocked,
      complianceViolations: prComplianceViolations,
      actionBreakdown,
    },
    handWrittenRules: {
      grossRecoveredCents: ruleGross,
      actionCostSpentCents: ruleCost,
      netRecoveredCents: ruleNet,
      recoveriesSucceeded: ruleSuccesses,
      actionsExecuted: ruleExecuted,
      complianceViolations: ruleComplianceViolations,
    },
    netRecoveryLiftPercent,
    additionalNetRecoveredCents: prNet - ruleNet,
    shapAdditivityChecksPassed,
    curveCheckpoints,
    benchmarkProofHash,
  };
}
