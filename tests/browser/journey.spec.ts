import { expect, test, type Page } from '@playwright/test';
import { randomUUID } from 'node:crypto';

// Smallest valid 1x1 PNG. A random trailer makes every run's photo unique so the
// server-side SHA-256 anti-replay guard never rejects a legitimately fresh upload.
const TINY_PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
  'base64'
);
const uniquePng = () => Buffer.concat([TINY_PNG, Buffer.from(randomUUID())]);

async function launchDemoWorkspace(page: Page) {
  await page.goto('/');
  await page
    .getByRole('button', { name: /Launch 1-Click Guided Workspace/i })
    .first()
    .click();
  const nav = page.getByRole('navigation', { name: 'Workspace Sections' });
  await expect(nav).toBeVisible();
  // First visit of a workspace opens the guided tour; later visits do not.
  const skip = page.getByRole('button', { name: /Skip Tour/i });
  if (await skip.isVisible({ timeout: 2_500 }).catch(() => false)) {
    await skip.click();
  }
  return nav;
}

test.describe('AegisPay in a real browser', () => {
  test('landing page renders the product promise and primary call to action', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText(/AegisPay/i).first()).toBeVisible();
    await expect(
      page.getByRole('button', { name: /Launch 1-Click Guided Workspace/i }).first()
    ).toBeVisible();
    await expect(page.getByText(/Sign In/i).first()).toBeVisible();
  });

  test('one click opens a signed-in workspace with all three pillars', async ({ page }) => {
    const nav = await launchDemoWorkspace(page);
    for (const pillar of ['Overview', 'Pay Safely', 'Recover & Retain', 'Get Paid']) {
      await expect(nav.getByRole('button', { name: pillar })).toBeVisible();
    }
  });

  test('regression: session survives a reload (no "session expired" loop)', async ({ page }) => {
    const nav = await launchDemoWorkspace(page);
    await page.reload();
    await expect(nav).toBeVisible();
    await expect(page.getByText(/session expired/i)).toHaveCount(0);
  });

  test('universal device agent routes plain English to the right workflow', async ({ page }) => {
    await launchDemoWorkspace(page);
    const agent = page.getByLabel('Universal Agentic Device Command Bar');
    await expect(agent).toBeVisible();
    await page
      .getByPlaceholder(/Ask anything or paste an invoice/i)
      .fill('Can I afford a $420 ergonomic chair this week with my current checking balance?');
    await page.getByRole('button', { name: /Execute with AI Agent/i }).click();
    await expect(page.getByText('ROUTED: CASHFLOW_CHECK')).toBeVisible();
  });

  test('instant partial refund blocks submission until a damage photo is uploaded', async ({
    page,
  }) => {
    const nav = await launchDemoWorkspace(page);
    await nav.getByRole('button', { name: 'Recover & Retain' }).click();

    const submit = page.getByRole('button', { name: /Calculate & Issue Partial Refund/i });
    await submit.scrollIntoViewIfNeeded();
    await submit.click();
    await expect(page.getByText(/Compulsory Photo Required/i)).toBeVisible();

    // 1. Mismatched photo (cat selfie for a stoneware mug claim) must be rejected
    await page
      .locator('input[type="file"][accept="image/*"][required]')
      .setInputFiles({ name: 'cat_selfie.png', mimeType: 'image/png', buffer: uniquePng() });
    await expect(page.getByText(/VERIFIED PHOTO: cat_selfie\.png/i)).toBeVisible();
    await submit.click();
    await expect(page.getByText(/MISMATCH: PHOTO != CLAIM/i)).toBeVisible();
    await expect(page.getByText(/Claim Declined \/ Photo Rejected/i)).toBeVisible();

    // 2. Matching photo for the claimed item is approved
    await page
      .locator('input[type="file"][accept="image/*"][required]')
      .setInputFiles({ name: 'damaged-item.png', mimeType: 'image/png', buffer: uniquePng() });
    await expect(page.getByText(/VERIFIED PHOTO: damaged-item\.png/i)).toBeVisible();

    await submit.click();
    await expect(page.getByText(/Compulsory Photo Required/i)).toHaveCount(0);
    await expect(page.getByText(/MATCHED CLAIM/i)).toBeVisible();
    await expect(page.getByText(/Approved \d+% Refund/i).first()).toBeVisible();
  });

  test('chrome extension and postman collection are downloadable from the browser', async ({
    page,
  }) => {
    await page.goto('/');
    const ext = await page.request.get('/api/download/extension');
    expect(ext.status()).toBe(200);
    expect(ext.headers()['content-disposition']).toContain('attachment');
    const body = await ext.body();
    expect(body.subarray(0, 2).toString('utf8')).toBe('PK'); // ZIP magic bytes
    expect(body.length).toBeGreaterThan(2_000);

    const postman = await page.request.get('/api/download/postman');
    expect(postman.status()).toBe(200);
    expect((await postman.json()).info.name).toContain('AegisPay');
  });
});
