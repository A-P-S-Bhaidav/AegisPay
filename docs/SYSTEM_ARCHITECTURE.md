# AegisPay v3.1 - System Architecture, Security & ML Specification

## 1. Separation of Concerns: Customer Product vs. Verification Lab

**AegisPay v3.1** enforces two architectural boundaries simultaneously:
1. **Execution Separation**: *"AI Proposes. Deterministic Code Decides. PayPal Moves the Money."*
2. **Experience Separation**: Customer-facing workflows (`LandingPage`, `WorkspaceOverview`, `PaySafelyView`, `MerchantRecoveryView`, `GetPaidView`, and `InteractiveTour`) present clear, plain-English financial controls, while all internal ML telemetry, adversarial fuzzers, tamper simulations, and audit benchmarks live inside the lazy-loaded **`DiagnosticsLab`** (`React.lazy`).

---

## 2. Three-Tier Technical Architecture

1. **Tier 01 - Multi-Provider Cognitive & Trained ML Layer (`server/gemini.ts`, `shared/payrevive.ts`, `shared/payreviveModelArtifact.ts`)**:
   - **Google Gemini + Groq Cloud LPU Failover**: Structured semantic fraud review, grounded policy compilation, multi-agent negotiation, vision defect telemetry, and automatic HTTP `429` failover guarded by `meta-llama/llama-prompt-guard-2-86m`.
   - **Trained 16-Tree Second-Order Newton GBDT + Exact TreeSHAP**: Offline trainer (`scripts/train-payrevive-gbdt.ts`) fits a 16-tree Newton GBDT ensemble (`Held-Out ROC-AUC = 0.8301`, `Brier Score = 0.1403`) with exact path-dependent TreeSHAP attribution (`additivityDelta < 1e-6`).
2. **Tier 02 - Deterministic Financial, LinUCB Bandit & Compliance Kernel (`shared/kernel.ts`, `shared/payrevive.ts`)**:
   - **Disjoint LinUCB Contextual Bandit & Hard Compliance Gate**: Per-arm ridge regression with exact `O(d^2)` Sherman-Morrison inverse updates (`theta_a = A_a^-1 b_a`). Executes an arm only when `ExpectedNetGainCents > 0` AND all deterministic compliance rules pass (`0` refused actions executed across `10,000` simulated failures). Arm weights update strictly on settlement confirmation (`POST /api/payrevive/confirm-settlement`).
   - **Monotonic Permits, Single-Use HMAC Tokens, Mandate Clamping & Hamilton Splits**: Enforces `ALLOW -> HOLD -> BLOCK` monotonicity, 5-minute single-use checkout tokens, ZOPA ceiling/floor clamps, per-tenant cent refund matrices, `20-35-50%` retention ladders, and `0-cent` drift milestone splits.
3. **Tier 03 - OWASP-Hardened Multi-Tenant Vault & PayPal Sandbox Execution (`server/security.ts`, `server/store.ts`, `server/paypal.ts`)**:
   - **Zero-Trust Auth, RBAC, CSRF & SSRF Guards**: Verified Google OAuth 2.0 + OAuth CSRF `state` cookie, `crypto.scryptSync` accounts, `HttpOnly; SameSite=Strict` cookies (zero `localStorage` tokens), Origin Allowlist CORS, `X-Requested-With` CSRF validation, SSRF URL blocking (`validateSafeExternalUrl`), `PRINCIPAL_ARCHITECT` RBAC, and non-blocking `fs.promises` `0o600` vault writes.
   - **Honest PayPal Sandbox Settlement & Verified Webhooks**: Tracks explicit settlement stages (`LIVE_PAYER_APPROVAL_READY` vs `LIVE_BUYER_CAPTURED`), isolates orders/invoices/vault/subscriptions per `ownerTenantId`, and verifies webhook signatures (`POST /api/paypal/webhook`).

---

## 3. End-to-End Execution Topology

```mermaid
flowchart TB
    subgraph Security["OWASP Edge & Multi-Tenant Vault (server/security.ts & server/store.ts)"]
        S1["Strict CSP (No Script Unsafe-Inline) + Origin Allowlist CORS + CSRF Guard"]
        S2["SSRF Guard + Prototype Sanitizer + Secret Redactor + 3-Tier Rate Limiter"]
        S3["Verified Google OAuth 2.0 + Scrypt + HttpOnly SameSite=Strict Cookie + RBAC"]
        S4["Per-Tenant Partitioned LRU Cache + Async 0o600 Vault (data/aegispay_store.json)"]
    end

    subgraph Product["Plain-English Customer Workspace (src/App.tsx)"]
        T0["5-Step Accessible Guided Tour (InteractiveTour.tsx)"]
        U1["Overview + Pay Safely (Invoices, Budget, Subscriptions, Limits)"]
        U2["Merchant Recovery (Failed Payments, Photo Refunds, Retention)"]
        U3["Get Paid (Exact-Cent Milestones, Live INV2 Invoices, Deals)"]
    end

    subgraph Lab["Isolated Lazy-Loaded Verification Lab (DiagnosticsLab.tsx)"]
        L1["500-Batch PayRevive Sim + Held-Out Model Card + TreeSHAP + LinUCB"]
        L2["1,000-Case Safety Fuzzer + 5-Attack Tamper Lab + 429 Failover Router"]
        L3["AG Grid Audit Ledger + Elastic NDJSON Export + Admin Gateway RBAC"]
    end

    subgraph PayPal["PayPal Developer Sandbox REST APIs (server/paypal.ts)"]
        P1["OAuth2 + Orders v2 (CAPTURE & AUTHORIZE) + Honest Settlement Stages"]
        P2["Vault v3 Setup Tokens & Subscriptions v1 (Per-Tenant Isolated)"]
        P3["Invoicing v2 (INV2-...) & Verified Partial Refunds"]
        P4["Signature-Verified Webhooks (/v1/notifications/verify-webhook-signature + HMAC)"]
    end

    Security --> Product
    Product -. "Separate Lazy Chunk" .-> Lab
    Product --> PayPal
    Lab --> PayPal
```
