import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

/**
 * Frontend <-> backend contract guard.
 *
 * Every `/api/...` path that any client (React app, Chrome extension, MCP bridge,
 * Postman collection) references must be a route the Express server really registers.
 * This catches renamed/removed endpoints at CI time instead of in front of a user.
 */

const ROOT = path.resolve(__dirname, '..');

function walk(dir: string, exts: RegExp): string[] {
  if (!fs.existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'dist') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full, exts));
    else if (exts.test(entry.name)) out.push(full);
  }
  return out;
}

const serverSource = fs.readFileSync(path.join(ROOT, 'server', 'index.ts'), 'utf8');
const registeredRoutes = new Set(
  [...serverSource.matchAll(/app\.(?:get|post|put|patch|delete)\(\s*'(\/api\/[^']+)'/g)].map(
    (m) => m[1]
  )
);

function referencedApiPaths(files: string[]): Map<string, string[]> {
  const refs = new Map<string, string[]>();
  for (const file of files) {
    const text = fs.readFileSync(file, 'utf8');
    for (const m of text.matchAll(/(\/api\/[A-Za-z0-9_\-/]+)/g)) {
      const p = m[1].replace(/\/$/, '') || m[1];
      const list = refs.get(p) ?? [];
      list.push(path.relative(ROOT, file));
      refs.set(p, list);
    }
  }
  return refs;
}

function isRegistered(p: string): boolean {
  if (registeredRoutes.has(p)) return true;
  // Dynamic suffixes (e.g. `/api/foo/${id}`) leave a prefix; accept any route under it.
  return [...registeredRoutes].some((r) => r.startsWith(`${p}/`));
}

describe('frontend/backend API contract', () => {
  it('discovers a realistic number of server routes (guards the regex itself)', () => {
    expect(registeredRoutes.size).toBeGreaterThanOrEqual(50);
  });

  const clients: Array<[string, string[]]> = [
    ['React app (src/)', walk(path.join(ROOT, 'src'), /\.(ts|tsx)$/)],
    ['Chrome extension (extension/)', walk(path.join(ROOT, 'extension'), /\.(js|html)$/)],
    ['MCP stdio bridge (mcp-server/)', walk(path.join(ROOT, 'mcp-server'), /\.(mjs|js)$/)],
    ['Postman collection (postman/)', walk(path.join(ROOT, 'postman'), /\.json$/)],
  ];

  for (const [label, files] of clients) {
    it(`${label} only calls routes the server registers`, () => {
      expect(files.length).toBeGreaterThan(0);
      const refs = referencedApiPaths(files);
      const missing = [...refs.entries()]
        .filter(([p]) => !isRegistered(p))
        .map(([p, where]) => `${p}  (in ${[...new Set(where)].join(', ')})`);
      expect(missing, `Unregistered API routes referenced:\n${missing.join('\n')}`).toEqual([]);
    });
  }
});

describe('Chrome extension manifest (Manifest V3 store readiness)', () => {
  const manifest = JSON.parse(
    fs.readFileSync(path.join(ROOT, 'extension', 'manifest.json'), 'utf8')
  );

  it('is Manifest V3 with a service worker and a side panel', () => {
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.background?.service_worker).toBe('service-worker.js');
    expect(manifest.side_panel?.default_path).toBeDefined();
  });

  it('references only files that exist in the extension folder', () => {
    const files = [
      manifest.background.service_worker,
      manifest.side_panel.default_path,
      ...Object.values(manifest.icons ?? {}),
    ] as string[];
    for (const f of files) {
      expect(fs.existsSync(path.join(ROOT, 'extension', f)), `missing ${f}`).toBe(true);
    }
  });

  it('declares every Chrome API permission its scripts actually use', () => {
    const code = ['service-worker.js', 'sidepanel.js']
      .map((f) => fs.readFileSync(path.join(ROOT, 'extension', f), 'utf8'))
      .join('\n');
    const used: Record<string, string> = {
      storage: 'chrome.storage',
      contextMenus: 'chrome.contextMenus',
      sidePanel: 'chrome.sidePanel',
      scripting: 'chrome.scripting',
      tabs: 'chrome.tabs',
    };
    for (const [permission, api] of Object.entries(used)) {
      if (code.includes(api)) {
        expect(manifest.permissions, `${api} used but "${permission}" not declared`).toContain(
          permission
        );
      }
    }
  });
});
