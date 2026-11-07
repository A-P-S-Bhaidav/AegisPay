# AegisPay

A PayPal sandbox workspace for reviewing payment requests, applying spending limits, recovering failed payments, and billing project milestones. AI analyzes untrusted text and images; deterministic code enforces amounts, ownership, budgets, and approval requirements.

[Hosted application](https://aegispay-orpin.vercel.app) · [Setup](MASTER_GUIDE.md) · [Architecture](docs/SYSTEM_ARCHITECTURE.md) · [Verification report](docs/VERIFICATION.md) · [Submission materials](submission/README.md)

## Run locally

Use Node.js 22.12 or later in the 22 LTS line, or Node.js 24 LTS.

```sh
git clone https://github.com/A-P-S-Bhaidav/AegisPay.git
cd AegisPay
npm ci
cp .env.example .env
```

Set sandbox `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, and either `GEMINI_API_KEY` or `GROQ_API_KEY` in `.env`. Generate a unique signing secret:

```sh
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Put the result in `AEGIS_KERNEL_SECRET`. Keep `PAYPAL_ENV=sandbox`.

```sh
npm run check
npm start
```

Open [localhost:8787](http://localhost:8787). Create an account to use actual configured providers. Use a PayPal sandbox personal buyer account, distinct from the sandbox business merchant, for approval. No production money is required. The optional guided practice workspace is isolated and does not prove a PayPal transaction or a live AI call.

## Product workflows

- Payment request review combines semantic analysis with deterministic checks. A signed review binds the amount, currency, recipient, and tenant before order creation. PayPal buyer approval and server-side capture complete checkout.
- Spending permits bound agent purchases. Cashflow checks use the balance and commitments entered by the account owner; they do not connect to a bank.
- Failed-payment recovery evaluates retry and outreach restrictions, expected value, and operator-supplied payment context. A recovery link is not recovered revenue; settlement must be verified separately.
- Milestone plans and collaborator allocations use integer cents. PayPal invoices request payment; allocation calculations do not distribute collaborator payouts or constitute a regulated escrow service.
- Refund evaluation applies merchant policy to a claim. A real refund requires an owned, verified capture. Image analysis does not establish that a claim is truthful.
- AG Grid exposes the audit ledger in the Verification Lab. HTTP MCP, stdio MCP, WebMCP, a Postman collection, and a Manifest V3 extension expose related workflows.

## Verification

```sh
npm run typecheck
npm test
npm run build
npm audit
```

An opt-in provider check uses local credentials, creates unapproved USD 1 sandbox orders and an unsent invoice draft, checks recipient binding and replay behavior, and calls the configured AI providers:

```sh
npm run verify:providers
```

`npm run benchmark:payrevive` runs a reproducible **synthetic test benchmark**. The custom 16-tree Newton GBDT is trained on generated data. Its held-out scores and simulated recovery lift are engineering experiments, not measured merchant outcomes. Do not use them as claims about real-world revenue, regulatory compliance, or production model accuracy.

See [the verification report](docs/VERIFICATION.md) for tested boundaries and outstanding checks. Passing unit tests does not establish production payment readiness.

## Data and deployment

Secrets stay on the server. Local account/workspace data is stored in a permission-restricted JSON file under `data/`; this is not encrypted storage. Vercel's temporary filesystem and process memory are not a durable shared financial database. Do not use a multi-instance/serverless deployment for production funds until payment records, ownership, replay protection, revocation, and atomic accounting use durable shared storage.

The repository includes deployment configuration for Vercel, Render, and Docker. Configuration alone is not evidence of deployment to a sponsor's platform. Docker builds exclude local credentials and account data.

## License

[MIT](LICENSE). Third-party dependencies retain their respective licenses.
