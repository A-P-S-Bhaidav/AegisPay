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

  await chrome.storage.local.remove('operatorTokenMap');
  await chrome.storage.session.remove('demoTokenMap');
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

async function getSelectedEndpoint() {
  const { apiBaseUrl = DEFAULT_ENDPOINTS[0] } = await chrome.storage.local.get('apiBaseUrl');
  if (!DEFAULT_ENDPOINTS.includes(apiBaseUrl)) throw new Error('Choose a supported API endpoint in the side panel.');
  return apiBaseUrl;
}

async function fetchWithEndpointFailover(path, payload, method = 'POST') {
  const apiBaseUrl = await getSelectedEndpoint();
  const { accountTokenMap = {} } = await chrome.storage.session.get('accountTokenMap');
  const session = accountTokenMap[apiBaseUrl];
  if (!session?.token) throw new Error('Sign in to your AegisPay account in the side panel first.');
  // Use only the selected endpoint: page content never silently falls back to a remote host.
  const response = await fetch(`${apiBaseUrl}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'AegisPay-Client',
      Authorization: `Bearer ${session.token}`,
    },
    ...(method === 'POST' ? { body: JSON.stringify(payload || {}) } : {}),
    signal: AbortSignal.timeout(60000),
  });
  const data = await response.json();
  if (response.status === 401) {
    delete accountTokenMap[apiBaseUrl];
    await chrome.storage.session.set({ accountTokenMap });
    throw new Error('Your session expired. Sign in again in the side panel.');
  }
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
  return { data, endpointUsed: apiBaseUrl };
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    try {
      if (message?.type === 'AEGISPAY_AUTH_STATUS') {
        const base = await getSelectedEndpoint();
        const { accountTokenMap = {} } = await chrome.storage.session.get('accountTokenMap');
        sendResponse({ ok: true, authenticated: Boolean(accountTokenMap[base]?.token), email: accountTokenMap[base]?.email || '' });
        return;
      }
      if (message?.type === 'AEGISPAY_SIGN_IN') {
        const base = await getSelectedEndpoint();
        const email = String(message.payload?.email || '').trim();
        const password = String(message.payload?.password || '');
        if (!email || !password) throw new Error('Enter your account email and password.');
        const response = await fetch(`${base}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'AegisPay-Client' },
          body: JSON.stringify({ email, password }),
          signal: AbortSignal.timeout(30000),
        });
        const data = await response.json();
        if (!response.ok || !data.token) throw new Error(data.error || 'Sign-in failed.');
        const { accountTokenMap = {} } = await chrome.storage.session.get('accountTokenMap');
        accountTokenMap[base] = { token: data.token, email: data.operator?.email || email };
        await chrome.storage.session.set({ accountTokenMap });
        sendResponse({ ok: true, email: accountTokenMap[base].email });
        return;
      }
      if (message?.type === 'AEGISPAY_SIGN_OUT') {
        const base = await getSelectedEndpoint();
        try { await fetchWithEndpointFailover('/api/auth/logout', {}); } catch {}
        const { accountTokenMap = {} } = await chrome.storage.session.get('accountTokenMap');
        delete accountTokenMap[base];
        await chrome.storage.session.set({ accountTokenMap });
        sendResponse({ ok: true });
        return;
      }
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

      if (message?.type === 'AEGISPAY_CAPTURE_PAYPAL_ORDER') {
        const { data, endpointUsed } = await fetchWithEndpointFailover('/api/scamshield/capture-paypal-order', message.payload);
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
