# Chrome Web Store Listing & Compliance - AegisPay Checkout Firewall

**Last Updated:** 2026-10-28  
**Extension Version:** 2.0.0  
**Manifest Version:** 3  

## 1. Store Listing Copy

- **Title:** AegisPay Pre-Payment Firewall & Agent Guard for PayPal
- **Short Description (132 chars max):** Scan invoices, payment links, and checkout requests on any webpage before opening PayPal. Blocks scams and prompt injections.
- **Detailed Description:**
  Protect every online invoice and payment request before you pay. Highlight any payment message, freelancer invoice, or checkout text on any webpage, right-click **"Scan Payment Text with AegisPay"**, and view an instant threat analysis in your browser's Side Panel.
  - **Pre-Payment Fraud & Prompt-Injection Detection:** Combines neural prompt-injection classification (`llama-prompt-guard-2-86m`), Gemini/Groq semantic reasoning, and 18 deterministic fraud rules before PayPal opens.
  - **Single-Use Cryptographic Review Token:** Binds your reviewed amount, currency, and recipient to a one-time HMAC-SHA256 token so altered checkout amounts are blocked.
  - **Automatic Cloud Failover:** Connects to your local AegisPay instance (`localhost:8787`) or automatically falls back to the hosted Vercel endpoint (`aegispay-orpin.vercel.app`).
  - **Zero Background Tracking:** Only scans text you explicitly select or enter into the Side Panel.

## 2. Permissions Justification

| Permission | Plain-English Justification for Chrome Web Store Review |
| :--- | :--- |
| `storage` | Saves the user's most recently selected payment text and recent scan history locally so the Side Panel can display them across sessions. |
| `contextMenus` | Adds the right-click menu item "Scan Payment Text with AegisPay" when a user highlights text on a webpage. |
| `sidePanel` | Opens the AegisPay verification interface in the browser Side Panel when the user clicks the extension icon or uses the context menu. |
| `scripting` | Displays a brief visual confirmation banner on the active webpage when the user triggers a right-click payment scan. |
| `tabs` | Reads the active tab's window ID and URL when the user initiates a context-menu scan so the Side Panel opens in the current window. |
| `host_permissions` (`localhost`, `*.vercel.app`, `*.onrender.com`, `*.paypal.com`) | Connects to the AegisPay verification service to evaluate selected invoice text and issue single-use review tokens. |

## 3. Privacy & Data Use Disclosure

- **Data Collection:** Only payment or invoice text explicitly highlighted and submitted by the user is sent to the AegisPay verification endpoint. No passive browsing history or keystrokes are collected.
- **Data Storage:** Scan history is stored locally on the user's device via `chrome.storage.local`.

## 4. Version History

- **2.0.0 (2026-10-28):** Added automatic localhost-to-Vercel endpoint failover, multi-currency invoice detection, and Llama Prompt Guard 2 telemetry.
- **1.0.0 (2026-10-23):** Initial Manifest V3 release with Side Panel verification, Context Menu text scanner, and single-use HMAC-SHA256 review tokens.
