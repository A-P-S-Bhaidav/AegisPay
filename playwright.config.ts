import { defineConfig, devices } from '@playwright/test';

const PORT = Number(process.env.E2E_PORT) || 4173;
const BASE_URL = `http://127.0.0.1:${PORT}`;

/**
 * Real-browser end-to-end tests. They drive the production build served by the real
 * Express server (npm start), exactly as a judge or user would experience it.
 * No API keys are provided on purpose: the server then uses its deterministic
 * fallbacks, which keeps the suite hermetic and non-flaky in CI.
 */
export default defineConfig({
  testDir: 'tests/browser',
  timeout: 45_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI
    ? [['github'], ['html', { open: 'never' }]]
    : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: BASE_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    viewport: { width: 1440, height: 900 },
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'npm start',
    url: `${BASE_URL}/api/health`,
    reuseExistingServer: !process.env.CI,
    timeout: 90_000,
    env: {
      PORT: String(PORT),
      ALLOW_DEMO_SANDBOX: 'true',
      PAYPAL_CLIENT_ID: '',
      PAYPAL_CLIENT_SECRET: '',
      GEMINI_API_KEY: '',
      GROQ_API_KEY: '',
    },
  },
});
