# AegisPay demo script and shot list

Record this after completing the browser sandbox buyer approval and confirming the capture ID. Use the tested build and a separate sandbox buyer. Target runtime is 2:35.

| Time | On screen | Narration |
| --- | --- | --- |
| 0:00–0:18 | Open the signed-in workspace. Show PayPal sandbox status. | An AI agent can read an invoice in seconds. The dangerous part is giving it permission to pay the wrong recipient. AegisPay gives small teams a way to check the request and verify what PayPal actually received. |
| 0:18–0:45 | Enter a suspicious request in Pay Safely. Run the review and show the block. | This request uses urgency and a lookalike support address. The AI explains the signals. The policy blocks checkout, so there is no order to approve. |
| 0:45–1:21 | Review a legitimate USD 1 request addressed to the configured sandbox merchant. Show the actual provider explanation, reviewed amount and recipient. Create the PayPal sandbox order. | This request passes review. The server signs the amount, currency and recipient, then compares those fields with the order returned by PayPal. The checkout link opens only after they match. |
| 1:21–1:57 | Approve using the sandbox buyer. Return to AegisPay and finish capture. Show the confirmed ID. | The buyer approves on PayPal. AegisPay checks the provider response before marking the order captured. Here is the sandbox capture reference. |
| 1:57–2:21 | Open Verification Lab and AG Grid. Filter to payment review and capture rows. | This ledger shows which request was blocked, which order was approved, and the PayPal reference that confirms capture. A reviewer can follow the decision from input to payment. |
| 2:21–2:35 | End on the workspace and the AegisPay project name. | AegisPay connects AI payment review to a PayPal sandbox action with a traceable approval and outcome. The public repository includes the build, tests, and judge walkthrough. |

Record application and PayPal sandbox footage at a legible resolution. Pause capture while entering sandbox credentials. Keep the real approval and confirmation visible, and remove pauses or login entry in editing. Publish the final video publicly on YouTube and add its URL to Devpost. Use only material you have rights to show.
