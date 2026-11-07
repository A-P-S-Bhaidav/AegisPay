# AegisPay verification report

The baseline was commit `df95a3399684adf4372560782e96acce8ee1d14d`. Its 342 tests, TypeScript check and build passed. The audit still found that a public test password granted administrator access, unauthenticated password linking could take over Google-only accounts, and the checkout flow could report a settlement without confirming the recipient or capture. The initial hackathon assessment was **54/100**.

The revised build scores **78/100 for hackathon readiness** using the five equally weighted Devpost criteria. This is an engineering assessment. Judge outcomes depend on the final entry and its video.

| Criterion | Baseline | Revised | Evidence and remaining gap |
| --- | ---: | ---: | --- |
| Technology | 11/20 | 17/20 | Real AI calls, PayPal order and invoice verification, stricter authentication and financial boundaries. Buyer-approved capture and webhook delivery still require live sandbox exercises. |
| Design | 13/20 | 17/20 | Browser flows for onboarding, review, blocking, milestone planning and cashflow persistence. Pay Safely and the audit grid fit a 390 px viewport. |
| Impact | 10/20 | 13/20 | A specific payment integrity problem and reproducible checks. Merchant outcome data is still needed. |
| Innovation | 15/20 | 17/20 | AI review followed by recipient-bound PayPal checkout and inspectable decisions. |
| Presentation | 5/20 | 14/20 | Clear setup, working demo path and verified submission copy. Public video remains outstanding. |

[Official judging criteria](https://paypalaihackathon.devpost.com/rules)

## Evidence

| Area | Result |
| --- | --- |
| Automated | `npm run check` passed all 376 tests across six files. The suite covers the kernel, HTTP routes, stdio MCP, extension worker, tenant boundaries, and payment integrity. TypeScript and the production build passed. |
| Dependencies | `npm audit` reported zero known vulnerabilities at verification time. The vulnerable Vitest 3 dependency chain was upgraded to Vitest 5. |
| Provider smoke | Actual PayPal sandbox OAuth, order creation, idempotent replay, and reviewed recipient, currency and amount validation passed. PayPal returned an unsent Invoicing v2 draft. No provider capture was performed. |
| AI | Gemini returned a real semantic review during the baseline smoke. The revised smoke successfully routed to Groq `openai/gpt-oss-120b` when the primary path failed. An isolated forced-429 diagnostic also completed on Groq. |
| Real HTTP | A newly registered account had empty financial state. An unauthenticated MCP call returned 401, and the authenticated cashflow call returned a decision. PayPal order creation refused a mismatched provider recipient. A modified signed amount returned 403. |
| Browser | Verified registration, sign-in, keyboard dismissal, suspicious invoice block, legitimate invoice review, edited amount relocking checkout, hard-decline block, exact USD 100.01 milestone allocation, and persistence of a balance, reserve and bill after reload. |
| WebMCP and AG Grid | A browser tool called authenticated cashflow. The 1,000-case safety verifier passed 1,000 cases. AG Grid rendered actual audit rows from the QA tenant, including the plan and blocked recovery decision. |
| Extension | Eight tests ran the shipped Manifest V3 worker with Chrome API stubs and an isolated HTTP server. They exercised sign-in, token storage, review, order creation, capture contract, expiration, endpoint selection and sign-out. The packaged ZIP and JavaScript syntax checks passed. |
| Performance | 100 local `/api/health` requests at concurrency 10 all returned 200. The observed p50 was 7.36 ms and p95 was 47.56 ms. This covers loopback health responses. The main client bundle was approximately 112 kB gzip. AG Grid is a separate lazy chunk of approximately 266 kB gzip. |
| Recovery benchmark | The seeded benchmark and fuzzer passed using test fixtures. The recovery model uses generated training and test data. Live merchant revenue lift and model calibration remain unmeasured. |
| Security review | A source audit identified account takeover, default administrator access and tenant scoping gaps. The fixes have targeted regressions. The audit used partial source coverage. |

## Remaining verification

- Complete a buyer-approved sandbox checkout with a personal sandbox account, then confirm the capture ID in the browser. Repeat for an authorization/capture flow and an owned partial refund if those features will be shown.
- Install the unpacked extension in Chrome and verify actual side panel, permission, selection, and approval behavior.
- Configure `PAYPAL_WEBHOOK_ID` and test real signed webhook delivery. A separate Google test account is needed for interactive OAuth sign-in.
- Use durable shared transactional storage before production funds or multiple server instances. The revised app restores local PayPal ownership records from its JSON snapshot. Vercel function storage remains temporary.
- Supply an eligible public YouTube video under three minutes to complete the Devpost package.

Reproduce local checks with `npm ci`, `npm run check`, `npm run benchmark:payrevive`, and `npm audit`. Run `npm run verify:providers` with sandbox and AI credentials for provider verification.
