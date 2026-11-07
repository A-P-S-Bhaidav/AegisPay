# AegisPay Chrome extension

The Manifest V3 extension reviews payment requests selected or entered in Chrome. It uses the same authenticated API and provider checks as the web application.

## Install for development

1. Run `npm run build:extension` and extract `public/extension.zip`.
2. In Chrome, open `chrome://extensions`, enable Developer mode, and choose **Load unpacked**. Select the extracted directory containing `manifest.json`.
3. Open the AegisPay side panel. Choose the local or hosted endpoint and sign in with an existing email/password account on that endpoint.
4. Enter or select invoice text, review the recipient and amount, then submit. A review that allows checkout can create an order for the configured PayPal sandbox merchant. Approve with a sandbox buyer and return to the panel to finish the payment.
5. Sign out and remove the unpacked extension when testing is complete.

Google-only accounts cannot sign in through the current extension. Use a test email/password account. Start the local server before selecting the localhost endpoint.

## Permissions and data

| Permission | Purpose |
| --- | --- |
| `activeTab`, `scripting` | Read text or show feedback in the current tab after a user action |
| `contextMenus`, `sidePanel` | Open the review panel from the toolbar or a selection menu |
| `storage` | Keep the endpoint setting and recent local selection/scan history. Keep authentication tokens in browser session storage |
| Localhost and the named hosted API origin | Send sign-in requests and selected payment data to the endpoint chosen in the side panel |

The extension sends selected payment text only after an explicit action and uses the chosen API endpoint. The endpoint may send supplied text to configured AI providers for semantic analysis. The extension stores recent selected text and scan history on the device. It clears the password field after sign-in and keeps no stored password. Restarting Chrome clears the session token. Avoid using confidential invoices when testing.

The packaged worker has automated HTTP integration coverage. Chrome installation and side panel interaction require a browser session with the unpacked extension loaded.
