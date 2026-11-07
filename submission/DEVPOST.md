# AegisPay

**Tagline**

Review payment requests with AI, enforce spending rules, and complete verified PayPal sandbox checkout.

**Inspiration**

A payment request can look ordinary while hiding a substituted recipient, an urgent scam, or a change to the amount. A business that lets an agent read invoices needs a clear record of what it reviewed, what it approved, and what the payment provider confirmed. AegisPay gives small teams one place to manage those steps.

**What it does**

AegisPay reads invoice text or images and evaluates the request with a configured AI provider. Deterministic checks can hold or block checkout. An allowed review binds the amount, currency, recipient, and workspace to a signed token. The server checks the actual PayPal order details against the reviewed request before giving the buyer a link. The buyer approves using a separate PayPal sandbox account. The app records capture only after PayPal confirms it.

The workspace also offers policy-based recovery recommendations for declined payments, refund evaluation for owned captures, and milestone plans that preserve the project budget to the cent. The AG Grid audit ledger shows the decision, amount, and reference from each recorded action.

**How it was built**

React and TypeScript power the workspace and Express API. PayPal sandbox OAuth, Orders v2, and Invoicing v2 handle provider operations. Gemini provides semantic analysis, with Groq as a secondary route. Deterministic TypeScript rules enforce limits and preserve exact amounts. AegisPay exposes authenticated MCP tools through its HTTP API and stdio adapter, with WebMCP available in a supported browser. The optional Manifest V3 extension submits selected invoice text through the same review API.

**What we verified**

A real PayPal sandbox order matched the reviewed amount, currency and recipient. A separate test verified that a different recipient could not open checkout. PayPal also returned an unsent sandbox invoice draft. The browser blocked a suspicious request, relocked checkout after an edit, and generated a $100.01 milestone plan. AG Grid rendered the audit entries from the test workspace.

**Built with**

PayPal Sandbox, PayPal Orders v2, PayPal Invoicing v2, PayPal JavaScript SDK, Google Gemini, Groq, AG Grid Community, React, TypeScript, Express, Vite, Vitest, Model Context Protocol, Chrome Manifest V3, Postman, Vercel.

**Submission fields**

- Public source and MIT license: https://github.com/A-P-S-Bhaidav/AegisPay
- Hosted application: https://aegispay-orpin.vercel.app
- Local functional build: follow the repository README and setup guide
- Public YouTube video: add the URL after recording and uploading

The strongest sponsor fit is AG Grid, which powers the interactive audit ledger. The repository contains a Render blueprint. Claim Render, APIMatic, Bryntum, or Channel3 sponsorship only if the submitted build demonstrates actual use of that sponsor's tool.
