/**
 * Browser-Native WebMCP (Web Model Context Protocol) & Global Agent Bridge (v3.2.0)
 * Exposes all 13 AegisPay tools to Chromium WebMCP (`navigator.modelContext`) and
 * `window.aegisPayMcp` so any browser agent, console script, or extension can invoke them directly.
 */

export type WorkspaceSectionId = 'overview' | 'protect' | 'merchant' | 'getpaid';

export interface AegisWebMcpBridge {
  version: string;
  endpoint: string;
  listTools: () => Promise<unknown>;
  callTool: (name: string, args?: Record<string, unknown>) => Promise<unknown>;
  navigateSection: (section: WorkspaceSectionId | 'diagnostics') => void;
  verifySafetyInvariants: () => Promise<unknown>;
}

declare global {
  interface Window {
    aegisPayMcp?: AegisWebMcpBridge;
  }
}

export function registerAegisWebMcpTools(
  onNavigateSection: (section: WorkspaceSectionId | 'diagnostics') => void,
  onTriggerFuzzer: () => Promise<unknown>
): () => void {
  const controller = new AbortController();

  const bridge: AegisWebMcpBridge = {
    version: '3.2.0',
    endpoint: '/api/mcp',
    async listTools() {
      const res = await fetch('/api/mcp', { credentials: 'include' });
      return res.json();
    },
    async callTool(name: string, args: Record<string, unknown> = {}) {
      const res = await fetch('/api/mcp', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: Date.now(),
          method: 'tools/call',
          params: { name, arguments: args },
        }),
      });
      return res.json();
    },
    navigateSection(section) {
      onNavigateSection(section);
    },
    async verifySafetyInvariants() {
      return onTriggerFuzzer();
    },
  };

  if (typeof window !== 'undefined') {
    window.aegisPayMcp = bridge;
  }

  const navAny = navigator as unknown as {
    modelContext?: {
      registerTool?: (tool: Record<string, unknown>, options?: { signal?: AbortSignal }) => void;
    };
  };
  const docAny = document as unknown as {
    modelContext?: {
      registerTool?: (tool: Record<string, unknown>, options?: { signal?: AbortSignal }) => void;
    };
  };

  const ctx = navAny.modelContext || docAny.modelContext;
  if (!ctx || typeof ctx.registerTool !== 'function') {
    return () => controller.abort();
  }

  try {
    ctx.registerTool(
      {
        name: 'open-aegispay-section',
        description:
          'Switch the active AegisPay workspace view between Overview, Pay Safely, Recover & Retain, Get Paid, or the Verification Lab.',
        inputSchema: {
          type: 'object',
          properties: {
            section: {
              type: 'string',
              enum: ['overview', 'protect', 'merchant', 'getpaid', 'diagnostics'],
              description: 'Target workspace section to display.',
            },
          },
          required: ['section'],
        },
        async execute(args: { section: WorkspaceSectionId | 'diagnostics' }) {
          onNavigateSection(args.section);
          return { status: 'switched', activeSection: args.section };
        },
        annotations: { readOnlyHint: true },
      },
      { signal: controller.signal }
    );

    ctx.registerTool(
      {
        name: 'verify-safety-invariants',
        description: 'Run the 1,000-case property-based safety verifier in the Verification Lab.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
        async execute() {
          const result = await onTriggerFuzzer();
          return result;
        },
        annotations: { readOnlyHint: true },
      },
      { signal: controller.signal }
    );

    ctx.registerTool(
      {
        name: 'aegispay-call-mcp-tool',
        description:
          'Invoke any of the 13 AegisPay HTTP MCP server tools (cashflow check, subscription cleanup, invoice scam scan, failed payment recovery, partial refund, churn saver, milestone planner, or deal negotiation).',
        inputSchema: {
          type: 'object',
          properties: {
            toolName: { type: 'string' },
            arguments: { type: 'object' },
          },
          required: ['toolName'],
        },
        async execute(args: { toolName: string; arguments?: Record<string, unknown> }) {
          return bridge.callTool(args.toolName, args.arguments || {});
        },
      },
      { signal: controller.signal }
    );
  } catch {
    // WebMCP is progressive enhancement on Chromium 146+
  }

  return () => controller.abort();
}
