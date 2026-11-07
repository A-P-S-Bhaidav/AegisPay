import React, { useEffect, useRef, useState } from 'react';
import { ExternalLink, CheckCircle2, ShieldCheck } from 'lucide-react';

declare global {
  interface Window {
    paypal?: {
      Buttons?: (config: Record<string, unknown>) => {
        render: (el: HTMLElement) => Promise<void>;
        close?: () => void;
      };
    };
  }
}

interface PayPalSmartCheckoutProps {
  publicClientId: string;
  signedToken: unknown;
  amountCents: number;
  currency: string;
  payeeIdentifier: string;
  apiFetch: (url: string, options?: RequestInit) => Promise<Response>;
  onCaptured: (result: { orderId: string; captureId: string }) => void;
}

export const PayPalSmartCheckout: React.FC<PayPalSmartCheckoutProps> = ({
  publicClientId,
  signedToken,
  amountCents,
  currency,
  payeeIdentifier,
  apiFetch,
  onCaptured,
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [sdkReady, setSdkReady] = useState(false);
  const [sdkError, setSdkError] = useState<string | null>(null);
  const [createdApprovalUrl, setCreatedApprovalUrl] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!publicClientId) {
      setSdkReady(false);
      return;
    }

    const existingScript = document.querySelector<HTMLScriptElement>(
      'script[data-aegis-paypal-sdk="true"]'
    );
    if (existingScript && window.paypal?.Buttons) {
      setSdkReady(true);
      return;
    }

    const script = document.createElement('script');
    script.src = `https://www.paypal.com/sdk/js?client-id=${encodeURIComponent(
      publicClientId
    )}&currency=${encodeURIComponent(currency || 'USD')}&intent=capture`;
    script.async = true;
    script.dataset.aegisPaypalSdk = 'true';
    script.onload = () => setSdkReady(true);
    script.onerror = () =>
      setSdkError('PayPal JS SDK blocked by browser privacy shield; direct Sandbox link ready.');
    document.body.appendChild(script);
  }, [publicClientId, currency]);

  useEffect(() => {
    if (!sdkReady || !window.paypal?.Buttons || !containerRef.current || !signedToken) {
      return;
    }

    containerRef.current.innerHTML = '';
    let cancelled = false;

    const buttons = window.paypal.Buttons({
      style: {
        layout: 'horizontal',
        color: 'blue',
        shape: 'rect',
        label: 'pay',
        height: 40,
        tagline: false,
      },
      createOrder: async () => {
        setStatusMessage('Creating live PayPal Sandbox Order v2...');
        const res = await apiFetch('/api/scamshield/create-paypal-order', {
          method: 'POST',
          body: JSON.stringify({ signedToken }),
        });
        const data = await res.json();
        if (!res.ok || !data.orderId) {
          throw new Error(data.error || 'Could not create PayPal order');
        }
        if (data.approvalUrl) {
          setCreatedApprovalUrl(data.approvalUrl);
        }
        setStatusMessage(`Live PayPal Order ${data.orderId} ready.`);
        return data.orderId;
      },
      onApprove: async (data: { orderID: string }) => {
        setStatusMessage(`Capturing Order ${data.orderID}...`);
        const res = await apiFetch('/api/scamshield/capture-paypal-order', {
          method: 'POST',
          body: JSON.stringify({ orderId: data.orderID, signedToken }),
        });
        const cap = await res.json();
        if (!cancelled && cap.captured) {
          setStatusMessage(`Captured Order ${cap.orderId} (${cap.captureId}).`);
          onCaptured({ orderId: cap.orderId, captureId: cap.captureId });
        }
      },
      onError: (err: unknown) => {
        if (!cancelled) {
          setStatusMessage(`PayPal SDK note: ${String(err)}`);
        }
      },
    });

    buttons.render(containerRef.current).catch(() => {
      if (!cancelled) {
        setSdkError('Direct PayPal Checkout link available below.');
      }
    });

    return () => {
      cancelled = true;
    };
  }, [sdkReady, signedToken, amountCents, payeeIdentifier]);

  const handleGenerateDirectSandboxLink = async () => {
    setStatusMessage('Minting PayPal Sandbox Checkout URL...');
    const res = await apiFetch('/api/scamshield/create-paypal-order', {
      method: 'POST',
      body: JSON.stringify({ signedToken }),
    });
    const data = await res.json();
    if (data.approvalUrl) {
      setCreatedApprovalUrl(data.approvalUrl);
      setStatusMessage(`Sandbox Order ${data.orderId} ready.`);
    }
  };

  return (
    <div className="border border-[#0047FF] bg-[#06080F] p-4 space-y-3 corner-ticks">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 font-mono text-[11px] font-bold uppercase tracking-wider text-[#CCFF00]">
          <ShieldCheck className="w-4 h-4 text-[#CCFF00]" />
          <span>Firewall-Unlocked PayPal Checkout</span>
        </div>
        <span className="text-xs font-mono font-bold text-[#F8FAFC] tabular-nums">
          ${(amountCents / 100).toFixed(2)} {currency}
        </span>
      </div>

      {publicClientId ? (
        <div ref={containerRef} className="min-h-[42px]" />
      ) : (
        <div className="text-xs text-[#94A3B8]">
          Server-side PayPal Sandbox capture unlocked below.
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 pt-1">
        <button
          type="button"
          onClick={handleGenerateDirectSandboxLink}
          className="btn-ghost-brutal px-3 py-1.5 text-xs"
        >
          <span>Mint Sandbox Checkout Link</span>
          <ExternalLink className="w-3.5 h-3.5" />
        </button>

        {createdApprovalUrl && (
          <a
            href={createdApprovalUrl}
            target="_blank"
            rel="noreferrer"
            className="btn-cobalt px-3 py-1.5 text-xs"
          >
            <span>Open sandbox.paypal.com</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        )}
      </div>

      {sdkError && <p className="text-xs font-mono text-[#94A3B8]">{sdkError}</p>}
      {statusMessage && (
        <div className="flex items-center gap-1.5 text-xs font-mono text-[#CCFF00]">
          <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
          <span>{statusMessage}</span>
        </div>
      )}
    </div>
  );
};
