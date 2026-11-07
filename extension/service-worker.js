// AegisPay Agentic Firewall & PayPal Guard Manifest V3 Service Worker (v3.2.0)
// Connects automatically to http://localhost:8787 or https://aegispay-orpin.vercel.app

const DEFAULT_ENDPOINTS = ['http://localhost:8787', 'https://aegispay-orpin.vercel.app'];

chrome.runtime.onInstalled.addListener(async () => {
  await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });

  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: 'aegispay-scan-selection',
      title: 'AegisPay: Scan Selected Invoice / Payment Text',
      contexts: ['selection'],
    });
    chrome.contextMenus.create({
      id: 'aegispay-ingest-selection',
      title: 'AegisPay: 1-Click Autonomous Agent Action on Selection',
      contexts: ['selection'],
    });
  });

  const existing = await chrome.storage.local.get(['apiBaseUrl', 'scanHistory']);
  if (!existing.apiBaseUrl) {
    await chrome.storage.local.set({
      apiBaseUrl: 'http://localhost:8787',
      scanHistory: [],
    });
  }
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!info.selectionText) return;

  const selectedText = info.selectionText.trim();
  await chrome.storage.local.set({
    lastSelectedText: selectedText,
    lastSelectedUrl: tab?.url || '',
    lastSelectedAt: new Date().toISOString(),
    lastActionMode: info.menuItemId === 'aegispay-ingest-selection' ? 'AGENT_INGEST' : 'SCAN',
  });

  if (tab?.windowId) {
    try {
      await chrome.sidePanel.open({ windowId: tab.windowId });
    } catch (err) {
      console.error('Could not open side panel:', err);
    }
  }

  if (tab?.id) {
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: (snippet) => {
          const toast = document.createElement('div');
          toast.textContent = `[AEGISPAY AGENT] Analyzing "${snippet.slice(0, 44)}..." in Side Panel`;
          Object.assign(toast.style, {
            position: 'fixed',
            bottom: '20px',
            right: '20px',
            zIndex: '2147483647',
            background: '#050507',
            color: '#F8FAFC',
            padding: '12px 18px',
            borderRadius: '2px',
            fontFamily: 'monospace',
            fontSize: '12px',
            fontWeight: '700',
            boxShadow: '4px 4px 0 #CCFF00',
            border: '1.5px solid #0047FF',
          });
          document.body.appendChild(toast);
          setTimeout(() => toast.remove(), 3200);
        },
        args: [selectedText],
      });
    } catch (err) {
      console.warn('Toast injection skipped on restricted page:', err);
    }
  }
});

async function getOrMintSessionToken(base) {
  const { operatorTokenMap = {} } = await chrome.storage.local.get('operatorTokenMap');
  if (operatorTokenMap[base]) {
    return operatorTokenMap[base];
  }
  const loginRes = await fetch(`${base}/api/auth/login`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'AegisPay-Client',
    },
    body: JSON.stringify({
      email: 'operator@aegispay.io',
      password: 'AegisPay2026!',
    }),
  });
  if (loginRes.ok) {
    const data = await loginRes.json();
    if (data.token) {
      operatorTokenMap[base] = data.token;
      await chrome.storage.local.set({ operatorTokenMap });
      return data.token;
    }
  }
  return '';
}

async function fetchWithEndpointFailover(path, payload, method = 'POST') {
  let lastError = null;
  for (const base of DEFAULT_ENDPOINTS) {
    try {
      let token = await getOrMintSessionToken(base);
      const init = {
        method,
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'AegisPay-Client',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        ...(method === 'POST' ? { body: JSON.stringify(payload || {}) } : {}),
      };
      let response = await fetch(`${base}${path}`, init);
      if (response.status === 401) {
        const { operatorTokenMap = {} } = await chrome.storage.local.get('operatorTokenMap');
        delete operatorTokenMap[base];
        await chrome.storage.local.set({ operatorTokenMap });
        token = await getOrMintSessionToken(base);
        init.headers = {
          'Content-Type': 'application/json',
          'X-Requested-With': 'AegisPay-Client',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        };
        response = await fetch(`${base}${path}`, init);
      }
      if (response.ok) {
        const data = await response.json();
        return { data, endpointUsed: base };
      }
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError || new Error('Could not reach localhost:8787 or aegispay-orpin.vercel.app');
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    try {
      if (message?.type === 'AEGISPAY_RUN_REVIEW') {
        const { data, endpointUsed } = await fetchWithEndpointFailover(
          '/api/scamshield/review',
          message.payload
        );
        const { scanHistory = [] } = await chrome.storage.local.get('scanHistory');
        const updatedHistory = [
          {
            timestampIso: new Date().toISOString(),
            verdict: data.finalVerdict,
            riskScore: data.combinedRiskScore,
            payee: message.payload.payeeIdentifier,
            amountCents: message.payload.claimedAmountCents,
            tokenId: data.signedToken?.payload?.tokenId,
            endpointUsed,
          },
          ...scanHistory.slice(0, 19),
        ];
        await chrome.storage.local.set({ scanHistory: updatedHistory, lastReviewResult: data });
        await chrome.action.setBadgeText({ text: data.finalVerdict === 'BLOCK' ? 'BLK' : 'OK' });
        await chrome.action.setBadgeBackgroundColor({
          color: data.finalVerdict === 'BLOCK' ? '#FF3355' : '#CCFF00',
        });
        sendResponse({ ok: true, data, endpointUsed });
        return;
      }

      if (message?.type === 'AEGISPAY_CREATE_PAYPAL_ORDER') {
        const { data, endpointUsed } = await fetchWithEndpointFailover(
          '/api/scamshield/create-paypal-order',
          message.payload
        );
        sendResponse({ ok: true, data, endpointUsed });
        return;
      }

      if (message?.type === 'AEGISPAY_AGENT_INGEST') {
        const { data, endpointUsed } = await fetchWithEndpointFailover(
          '/api/agent/ingest',
          message.payload
        );
        sendResponse({ ok: true, data, endpointUsed });
        return;
      }

      sendResponse({ ok: false, error: 'Unknown message type' });
    } catch (err) {
      sendResponse({ ok: false, error: String(err) });
    }
  })();
  return true;
});
