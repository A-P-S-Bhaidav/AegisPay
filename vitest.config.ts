import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Only the Vitest suites live in tests/*.test.ts. Browser specs under tests/browser
    // are Playwright's responsibility and must never be collected by Vitest.
    include: ['tests/*.test.ts'],
    exclude: ['tests/browser/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
    // The 500-batch PayRevive simulations are CPU heavy (~4s) and slower under v8 coverage
    // and on shared CI runners; the 5s default made them flaky.
    testTimeout: 60_000,
    hookTimeout: 60_000,
    coverage: {
      provider: 'v8',
      reporter: ['text-summary', 'lcov', 'json-summary'],
      reportsDirectory: 'coverage',
      include: ['server/**/*.ts', 'shared/**/*.ts'],
      // embeddedAssets.ts is a generated base64 blob; vercel-entry.ts is a 3-line adapter.
      exclude: ['server/embeddedAssets.ts', 'server/vercel-entry.ts'],
      // Regression guard set just under the measured baseline (80.7 / 65.5 / 95.5 / 80.7).
      thresholds: { statements: 78, branches: 62, functions: 92, lines: 78 },
    },
  },
});
