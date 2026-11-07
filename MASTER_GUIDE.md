# AegisPay setup and judge testing guide

## Environment

Use Node.js 22.12+ in the 22 LTS line or Node.js 24 LTS. Run `npm ci`, copy `.env.example` to `.env`, and configure the following locally. Never commit credentials or paste them into a submission description.

| Variable | Purpose |
| --- | --- |
| `PAYPAL_ENV=sandbox` | Hackathon sandbox environment |
| `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET` | REST app belonging to a sandbox business account |
| `PAYPAL_WEBHOOK_ID` | Registered webhook ID for provider signature verification |
| `GEMINI_API_KEY`, `GEMINI_MODEL` | Primary semantic/image analysis provider and available model |
| `GROQ_API_KEY`, `GROQ_TEXT_MODEL`, `GROQ_VISION_MODEL` | Optional secondary provider and available models |
| `AEGIS_KERNEL_SECRET` | Unique random 32-byte hex secret, stable across server restarts |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI` | Optional verified Google sign-in |
| `PORT=8787` | Local server port |
| `ALLOW_DEMO_SANDBOX=true` | Opt in to an isolated practice workspace with fixture data |
| `ALLOWED_ORIGINS` | Additional explicitly trusted browser origins, comma-separated |

Model access varies by account and provider. The application reports actual execution telemetry. A configured key alone does not prove that a model responded. Production requests fail if an actual configured provider cannot complete the operation.

Generate the signing secret with:

```sh
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## Start and verify

```sh
npm ci
npm run check
npm start
```

Open [localhost:8787](http://localhost:8787). Create a new email account or use configured Google sign-in. Public, shared administrator credentials are not supported. Unauthenticated login/registration cannot attach a password to an existing Google-only account.

For development, `npm run dev` starts the API at port 8787 and Vite at port 5173. `npm run verify:providers` verifies real sandbox OAuth, creates USD 1 orders awaiting approval and an unsent invoice draft, and invokes the configured AI providers. It exits unsuccessfully if only deterministic fallback is available.

## Judge walkthrough using real providers

1. Sign into a newly created account. Inspect provider status and the empty activity history.
2. In **Pay Safely**, enter an invoice message, amount, and sandbox merchant recipient. Run the review and inspect actual provider/model telemetry.
3. After an allowed result, use **PayPal sandbox checkout**. Log into a separate sandbox personal buyer account and approve. Confirm the server reports a capture ID and completed capture. An approval URL alone is incomplete.
4. Edit the invoice amount or recipient. The prior review must no longer unlock checkout. Review again before creating a new order.
5. Enter an urgent request containing an instruction to ignore the safety policy. Check that the result holds or blocks checkout.
6. Create a project in **Get Paid** with a sandbox buyer recipient and a non-round total. Verify that milestone amounts sum exactly to the total. Issuing an invoice creates a payment request; it is not paid until PayPal confirms payment.
7. Inspect the **Verification Lab** audit ledger and exports. Explain each tested restriction with a specific recorded action.

Use only sandbox identities for invoice recipients and buyer approval. Never place sandbox passwords or API secrets in the public repository. If judges need hosted credentials, use the submission's appropriate private access mechanism or permit account creation.

## Google sign-in

Register exact redirect URIs, for example `http://localhost:8787/api/auth/google/callback` and `https://aegispay-orpin.vercel.app/api/auth/google/callback`, in Google Cloud. The callback verifies the configured client audience and positive verified-email claim. Email login must not auto-attach an arbitrary password to an existing account.

## MCP and extension

Run stdio MCP using:

```sh
AEGISPAY_API_URL=http://localhost:8787 npm run mcp
```

Provide the MCP client's supported authentication variables through its private configuration. Never hardcode a shared operator password. The MCP tests check initialization, discovery, and authenticated execution using temporary test accounts. HTTP MCP execution requires an authenticated application session or bearer credential.

The extension is rebuilt by `npm run build:extension`. It supports explicit email/password account sign-in, keeps its bearer token in session storage, and sends page text only to the selected endpoint. Passwords are not persisted. Chrome permission prompts and internal-page restrictions still apply. Automated worker contract tests do not replace testing the installed Chrome service worker and side panel.

## Deployment limits

- Local JSON workspace storage is plaintext with filesystem permissions. Restrict filesystem access and back up data.
- Vercel `/tmp` and in-memory payment maps are temporary and process-local. Cold starts and multiple instances can lose or disagree about ownership, replay protection, and revocation. Production money requires durable shared transactional storage.
- A Render blueprint is supplied. A deployment and persistent storage must actually be provisioned to claim Render usage. A free ephemeral filesystem is not durable payment storage.
- Register the PayPal webhook URL and set `PAYPAL_WEBHOOK_ID`. Test real sandbox events, signature failures, and delivery replay. A locally signed simulator event does not prove PayPal webhook delivery.
- There is no bank-data connection, PayPal-wide transaction import, licensed escrow, or automatic collaborator payout product. Describe manually entered balances, local limits, and planned allocations accurately.
- Synthetic recovery training and benchmark fixtures are experimental test tools, not customer evidence. Do not present those figures as live outcomes.
