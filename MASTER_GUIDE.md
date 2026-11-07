# AegisPay v3.1 - Master Setup, Security, Storage & Vercel Deployment Guide

This guide covers **Localhost (`http://localhost:8787`)**, **Live Vercel (`https://aegispay-orpin.vercel.app`)**, **Verified Google OAuth 2.0 & Scrypt Authentication**, **Interactive Guided Tour**, **Product vs. Verification Lab Separation**, and **One-Command PayRevive Benchmarking**.

---

## 1. Localhost Verification & Startup (`http://localhost:8787`)

Your local `.env` file is strictly git-ignored (`.gitignore` excludes `.env`, `.env.*`, `data/`, and `*.store.json`) and never exposed to client bundles, URLs, or `localStorage`.

```bash
npm install
npm test
npm run benchmark:payrevive
npm run build
npm start
```

Open **[http://localhost:8787](http://localhost:8787)**.

---

## 2. Product Workspace vs. Isolated Verification Lab

1. **Customer Workspace (`Overview`, `Pay Safely`, `Merchant Recovery`, `Get Paid`)**:
   - Designed for everyday buyers, freelancers, and merchants in plain English using the **Midnight Black (`#050507`) + Electric Cobalt (`#0047FF`) + Acid Lime (`#CCFF00`)** design system.
   - **5-Step Interactive Guided Tour**: Automatically opens on first sign-in (and can be replayed anytime via **Guided Tour** in the header) with live **Try Sample Action** buttons on every step.
2. **Verification Lab (`Verification Lab` header button)**:
   - Lazy-loaded via `React.lazy` (`src/components/DiagnosticsLab.tsx`) so engineering tools and `AG Grid` never weigh down the customer app.
   - Contains the **500-Batch PayRevive Benchmark**, **Trained Newton GBDT Model Card & TreeSHAP Waterfall**, **1,000-Case Safety Fuzzer**, **5-Attack Tamper Lab**, **Gemini -> Groq HTTP 429 Failover Tester**, **AG Grid Audit Ledger**, and **`PRINCIPAL_ARCHITECT` Admin Gateway Settings**.

---

## 3. Security, Session Transport & Multi-Tenant Storage

1. **Authentication & RBAC (`server/index.ts`, `server/security.ts`)**:
   - **Email Accounts**: Hashed via `crypto.scryptSync` (`N=16384, r=8, p=1`, 16B random salt) and verified via `crypto.timingSafeEqual`.
   - **Google OAuth 2.0**: Verified server-side against Google token endpoints (`aud` + `email_verified`) with a signed `aegis_oauth_state` CSRF cookie.
   - **Interactive Demo Sandbox**: `POST /api/auth/demo` provisions an isolated `DEMO_OPERATOR` workspace (`403 Forbidden` on admin `/api/credentials`).
   - **Session Transport**: `HttpOnly; SameSite=Strict` cookies + `X-Requested-With: AegisPay-Client` CSRF protection (zero `localStorage` tokens).
2. **Async Multi-Tenant Persistence (`server/store.ts`)**:
   - **Local / VM Node**: Non-blocking async atomic write-ahead vault at `data/aegispay_store.json` (`0o600` permissions, git-ignored) with persisted 256-bit HMAC secret generation when `AEGIS_KERNEL_SECRET` is unset.
   - **Serverless (Vercel)**: Stateless HMAC-SHA256 identity + per-tenant workspace isolation inside a bounded `2,000`-tenant LRU cache.

---

## 4. Vercel Environment Variables & Google OAuth Setup

Configure in **[Vercel Dashboard](https://vercel.com/dashboard)** -> **`aegispay`** -> **Settings** -> **Environment Variables**:

- `PAYPAL_CLIENT_ID`
- `PAYPAL_CLIENT_SECRET`
- `PAYPAL_WEBHOOK_ID` *(optional; enables live PayPal webhook signature verification)*
- `PAYPAL_ENV` = `sandbox`
- `GEMINI_API_KEY`
- `GEMINI_MODEL` = `gemini-3-flash-preview`
- `GROQ_API_KEY`
- `GROQ_TEXT_MODEL` = `openai/gpt-oss-120b`
- `GROQ_VISION_MODEL` = `qwen/qwen3.8-27b`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `AEGIS_KERNEL_SECRET` = `<random-32-byte-hex-secret>`

In **[Google Cloud Console -> Credentials](https://console.cloud.google.com/apis/credentials)**:
- **Authorized JavaScript origins**: `http://localhost:8787`, `https://aegispay-orpin.vercel.app`
- **Authorized redirect URIs**: `http://localhost:8787/api/auth/google/callback`, `https://aegispay-orpin.vercel.app/api/auth/google/callback`

---

## 5. Under-3-Minute Demo Flow (Target: 2:45)

1. **`0:00 - 0:35` | Clean Product Landing, Sign-In & Interactive Guided Tour**:
   - Open `https://aegispay-orpin.vercel.app`, launch the **Interactive Demo Tour** (or sign in with Google/Email), and run Step 1's live sample action inside the 5-step Guided Tour.
2. **`0:35 - 1:30` | Customer Product (`Pay Safely`, `Merchant Recovery`, `Get Paid`)**:
   - Verify a `$45` invoice in **Pay Safely** to unlock **PayPal Smart Buttons**, recover a `$240` expired-card renewal via a live **PayPal Backup Funding Link (`INV2-...`)** in **Merchant Recovery**, and send an exact-cent milestone invoice in **Get Paid**.
3. **`1:30 - 2:45` | Isolated `Verification Lab` (Separate from Customer UI)**:
   - Click **Verification Lab** in the header: run the **500-Batch PayRevive Simulation** (`+51.35%` net recovery lift, `0` compliance violations, `0.8301` held-out ROC-AUC), run the **1,000-Case Safety Fuzzer** (`0` violations), test **Gemini -> Groq 429 Failover**, and inspect the **AG Grid Audit Ledger**.
