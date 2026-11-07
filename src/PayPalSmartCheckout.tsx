import React, { useEffect, useRef, useState } from 'react';
import { apiFetch, fmtUsd } from './api';

type PayPalButtons = {
  render: (element: HTMLElement) => Promise<void>;
  close?: () => void | Promise<void>;
};
type PayPalSdk = { Buttons: (configuration: Record<string, unknown>) => PayPalButtons };
type CheckoutOrder = {
  orderId: string;
  approvalUrl?: string;
  order?: { mode?: string };
};
type CaptureResult = { orderId: string; captureId: string; captured: boolean; mode?: string };

const sdkLoads = new Map<string, Promise<PayPalSdk>>();
let sdkNamespaceSequence = 0;

function loadPayPalSdk(clientId: string, currency: string): Promise<PayPalSdk> {
  const key = `${clientId}:${currency}`;
  const existing = sdkLoads.get(key);
  if (existing) return existing;
  const namespace = `aegisPayPal${sdkNamespaceSequence++}`;
  const pending = new Promise<PayPalSdk>((resolve, reject) => {
    const script = document.createElement('script');
    const timeout = window.setTimeout(() => {
      script.remove();
      reject(new Error('PayPal checkout took too long to load. Use the checkout link below.'));
    }, 20000);
    script.src = `https://www.paypal.com/sdk/js?client-id=${encodeURIComponent(clientId)}&currency=${encodeURIComponent(currency)}&intent=capture`;
    script.async = true;
    script.dataset.namespace = namespace;
    script.onload = () => {
      window.clearTimeout(timeout);
      const sdk = (window as unknown as Partial<Record<string, PayPalSdk>>)[namespace];
      if (sdk?.Buttons) resolve(sdk);
      else reject(new Error('PayPal checkout is unavailable. Use the checkout link below.'));
    };
    script.onerror = () => {
      window.clearTimeout(timeout);
      script.remove();
      reject(new Error('PayPal checkout could not load. Use the checkout link below.'));
    };
    document.body.appendChild(script);
  });
  sdkLoads.set(key, pending);
  pending.catch(() => sdkLoads.delete(key));
  return pending;
}

interface PayPalSmartCheckoutProps {
  publicClientId: string;
  signedToken: unknown;
  amountCents: number;
  currency: string;
  payeeIdentifier: string;
  liveSandbox: boolean;
  onCaptured: (result: CaptureResult) => void;
}

export const PayPalSmartCheckout: React.FC<PayPalSmartCheckoutProps> = ({
  publicClientId,
  signedToken,
  amountCents,
  currency,
  payeeIdentifier,
  liveSandbox,
  onCaptured,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const orderPromiseRef = useRef<Promise<CheckoutOrder> | null>(null);
  const captureCallbackRef = useRef(onCaptured);
  captureCallbackRef.current = onCaptured;
  const [order, setOrder] = useState<CheckoutOrder | null>(null);
  const [busy, setBusy] = useState(false);
  const [captured, setCaptured] = useState(false);
  const [error, setError] = useState('');
  const [sdkNote, setSdkNote] = useState('');
  const [statusMessage, setStatusMessage] = useState('');

  const createOrderRef = useRef<() => Promise<CheckoutOrder>>(null);
  createOrderRef.current = async () => {
    if (!orderPromiseRef.current) {
      orderPromiseRef.current = apiFetch<CheckoutOrder>('/api/scamshield/create-paypal-order', {
        method: 'POST',
        body: JSON.stringify({ signedToken }),
      }).then((data) => {
        if (!data.orderId) throw new Error('PayPal did not return an order. Check the invoice again.');
        setOrder(data);
        return data;
      }).catch((err) => {
        orderPromiseRef.current = null;
        throw err;
      });
    }
    return orderPromiseRef.current;
  };

  const captureOrderRef = useRef<(orderId: string) => Promise<void>>(null);
  captureOrderRef.current = async (orderId: string) => {
    setBusy(true);
    setError('');
    try {
      const result = await apiFetch<CaptureResult>('/api/scamshield/capture-paypal-order', {
        method: 'POST',
        body: JSON.stringify({ orderId, signedToken }),
      });
      if (!result.captured) throw new Error('Payment has not completed. Approve the order in PayPal, then try again.');
      setCaptured(true);
      setStatusMessage(`Sandbox payment captured. Reference: ${result.captureId}`);
      captureCallbackRef.current(result);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    orderPromiseRef.current = null;
    setOrder(null);
    setCaptured(false);
    setStatusMessage('');
    setError('');
  }, [signedToken]);

  useEffect(() => {
    if (!liveSandbox || !publicClientId) return;
    let cancelled = false;
    let buttons: PayPalButtons | undefined;
    setSdkNote('Loading PayPal checkout...');
    loadPayPalSdk(publicClientId, currency).then(async (sdk) => {
      if (cancelled || !containerRef.current) return;
      buttons = sdk.Buttons({
        style: { layout: 'vertical', color: 'blue', shape: 'rect', label: 'pay', height: 42 },
        createOrder: async () => {
          setError('');
          const next = await createOrderRef.current!();
          return next.orderId;
        },
        onApprove: async (data: { orderID: string }) => {
          if (!cancelled) await captureOrderRef.current!(data.orderID);
        },
        onCancel: () => {
          if (!cancelled) setStatusMessage('Checkout cancelled. No payment was captured.');
        },
        onError: () => {
          if (!cancelled) setError('PayPal checkout could not finish. Use the checkout link or check the invoice again.');
        },
      });
      await buttons.render(containerRef.current);
      if (!cancelled) setSdkNote('');
    }).catch((err) => {
      if (!cancelled) setSdkNote((err as Error).message);
    });
    return () => {
      cancelled = true;
      void Promise.resolve(buttons?.close?.()).catch(() => {});
    };
  }, [liveSandbox, publicClientId, currency, signedToken]);

  const handleCreateLink = async () => {
    setBusy(true);
    setError('');
    try {
      await createOrderRef.current!();
      setStatusMessage(liveSandbox ? 'Order created. Payment awaits your approval in PayPal.' : 'Simulated order created. No PayPal payment was made.');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="border border-[#0047FF] bg-[#06080F] p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-semibold text-sm">{liveSandbox ? 'PayPal sandbox checkout' : 'Simulated checkout'}</h3>
        <span className="text-xs font-mono">{currency === 'USD' ? fmtUsd(amountCents) : `${(amountCents / 100).toFixed(2)} ${currency}`}</span>
      </div>
      <p className="text-xs text-slate-300 break-words">Reviewed recipient: {payeeIdentifier}</p>
      <p className="text-xs text-slate-400">{liveSandbox ? 'Sandbox test funds only. Approve with a PayPal sandbox buyer account.' : 'PayPal credentials are unavailable. This preview cannot move funds.'}</p>
      {!captured && liveSandbox && <div ref={containerRef} className="min-h-[42px]" />}
      {!captured && <div className="flex flex-wrap items-center gap-2">
        <button type="button" disabled={busy} onClick={handleCreateLink} className="btn-ghost-brutal px-3 py-2 text-xs">
          {busy ? 'Processing...' : order ? 'Reuse checkout order' : liveSandbox ? 'Create checkout link' : 'Preview simulated order'}
        </button>
        {liveSandbox && order?.approvalUrl && <>
          <a href={order.approvalUrl} target="_blank" rel="noreferrer" className="btn-cobalt px-3 py-2 text-xs">Open PayPal sandbox</a>
          <button type="button" disabled={busy} onClick={() => void captureOrderRef.current!(order.orderId)} className="btn-acid px-3 py-2 text-xs">Finish approved payment</button>
        </>}
      </div>}
      {order && <p className="text-xs text-slate-400 break-all">Order: {order.orderId}</p>}
      {sdkNote && <p className="text-xs text-slate-400">{sdkNote}</p>}
      {error && <p role="alert" className="text-xs text-red-200">{error}</p>}
      {statusMessage && <p role="status" className="text-xs text-[#CCFF00]">{statusMessage}</p>}
    </div>
  );
};
