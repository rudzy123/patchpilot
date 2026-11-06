/**
 * One release smoke for the composed MVP path.
 *
 * The browser does not upload an SBOM. There is no SBOM upload page, and the
 * legal Finding fixture needs object storage and the controlled-creation
 * transaction. The smoke setup prepares that synthetic asset, product-match
 * evidence, and open Finding before the browser starts. The browser then signs
 * in, opens the prepared asset and product-match page, reads the Finding
 * explanation, calculates priority, opens the queue, and downloads the server
 * export. It does not build the file locally.
 *
 * The API process for this run keeps INTELLIGENCE_KEV_ENABLED and
 * INTELLIGENCE_OSV_ENABLED false. The worker is not started.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { expect, test, type Page } from '@playwright/test';

type ReleaseSmokeState = {
  email: string;
  password: string;
  assetId: string;
  assetName: string;
  findingId: string;
  vulnerabilityPublicId: string;
};

test('signs in, calculates prepared priority, and downloads the queue export', async ({ page }) => {
  const state = loadState();
  await rejectOffLoopback(page);
  const health = await page.request.get('http://127.0.0.1:3001/health/live');
  expect(health.ok()).toBe(true);

  await page.goto('/login');
  await page.getByLabel('Email').fill(state.email);
  await page.getByLabel('Password').fill(state.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Signed in' })).toBeVisible();

  await page.goto(`/assets/${state.assetId}`);
  await expect(page.getByText(state.assetName)).toBeVisible();
  await page.goto(`/assets/${state.assetId}/product-match-evaluations`);
  await expect(page.getByRole('heading', { name: 'Product match evidence' })).toBeVisible();
  await expect(page.getByText('Product match candidates are available to an owner.')).toHaveCount(
    0,
  );

  await page.goto(`/findings/${state.findingId}`);
  await expect(
    page.getByText('This Finding was recorded from affected product-match evidence.'),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Calculate priority' }).click();
  await expect(page.getByText('Comparable with the published built-in policy.')).toBeVisible();

  await page.goto('/remediation-queue');
  await expect(page.getByRole('link', { name: state.vulnerabilityPublicId })).toBeVisible();
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export JSON' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('remediation-queue.json');
  const downloadPath = await download.path();
  expect(downloadPath).not.toBeNull();
  const body = readFileSync(downloadPath ?? '', 'utf8');
  expect(body.startsWith('{"schemaVersion":"remediation_queue_export_v1","format":"json"')).toBe(
    true,
  );
  expect(body).toContain(state.vulnerabilityPublicId);
  expect(body).not.toContain(state.email);
});

function loadState(): ReleaseSmokeState {
  const parsed: unknown = JSON.parse(
    readFileSync(fileURLToPath(new URL('./.state.json', import.meta.url)), 'utf8'),
  );
  if (!isState(parsed)) {
    throw new Error('release smoke state is incomplete');
  }
  return parsed;
}

function isState(value: unknown): value is ReleaseSmokeState {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const state = value as Record<string, unknown>;
  return (
    typeof state.email === 'string' &&
    typeof state.password === 'string' &&
    typeof state.assetId === 'string' &&
    typeof state.assetName === 'string' &&
    typeof state.findingId === 'string' &&
    typeof state.vulnerabilityPublicId === 'string'
  );
}

async function rejectOffLoopback(page: Page): Promise<void> {
  await page.route('**/*', async (route) => {
    const target = route.request().url();
    if (!staysOnLoopback(target)) {
      throw new Error(`release smoke left loopback for ${hostOf(target)}`);
    }
    await route.continue();
  });
}

function staysOnLoopback(value: string): boolean {
  if (value.startsWith('data:') || value.startsWith('blob:') || value.startsWith('about:')) {
    return true;
  }
  return (
    hostOf(value) === '127.0.0.1' || hostOf(value) === 'localhost' || hostOf(value) === '[::1]'
  );
}

function hostOf(value: string): string {
  try {
    return new URL(value).hostname;
  } catch {
    return 'unparsed';
  }
}
