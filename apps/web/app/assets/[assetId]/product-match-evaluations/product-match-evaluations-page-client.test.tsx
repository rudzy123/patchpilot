import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import {
  CSRF_TOKEN_FIXTURE,
  createFakeAuthApi,
  publicOrganizationFixture,
  sessionFixture,
} from '../../../../test/auth-fixtures';
import { renderWithAuth } from '../../../../test/render-with-auth';

import { ProductMatchEvaluationsPageClient } from './product-match-evaluations-page-client';

const ASSET_ID = '44444444-4444-4444-8444-444444444444';
const INGESTION_ID = '66666666-6666-4666-8666-666666666666';
const REVISION_ID = '77777777-7777-4777-8777-777777777777';

function ownerApi(overrides: Parameters<typeof createFakeAuthApi>[0] = {}) {
  return createFakeAuthApi({
    readSession: vi.fn(async () =>
      sessionFixture({
        organization: { ...publicOrganizationFixture, role: 'owner' },
      }),
    ),
    ...overrides,
  });
}

function candidatePage(
  packageName = 'reviewed-npm-widget',
  ingestionId: string | null = INGESTION_ID,
) {
  return {
    schemaVersion: 'product_match_candidates_v1' as const,
    assetId: ASSET_ID,
    ingestionId,
    candidates: [
      {
        advisoryRevisionId: REVISION_ID,
        ecosystem: 'npm' as const,
        packageNamespace: null,
        packageName,
        matchedOccurrenceCount: 2,
        evaluationState: 'not_evaluated' as const,
      },
    ],
    nextCursor: null,
  };
}

function evaluationResponse(status: 'evaluated' | 'already_applied', ingestionId = INGESTION_ID) {
  return {
    schemaVersion: 'deliberate_product_match_evaluation_response_v1' as const,
    status,
    assetId: ASSET_ID,
    advisoryRevisionId: REVISION_ID,
    ingestionId,
    selectedCount: 1,
    evaluatedCount: status === 'evaluated' ? 1 : 0,
    insertedCount: status === 'evaluated' ? 1 : 0,
    replayedCount: status === 'already_applied' ? 1 : 0,
    skippedCount: 0,
    skippedByReason: { version_not_known: 0, version_unrepresentable: 0 },
    outcomeCounts: { affected: 0, unaffected: 0, unknown: 1 },
    findingCreation: 'unavailable' as const,
  };
}

describe('ProductMatchEvaluationsPageClient', () => {
  it('shows one candidate as text and does not render the ingestion id', async () => {
    const authApi = ownerApi({
      listProductMatchCandidates: vi.fn(async () => candidatePage('<script>alert(1)</script>')),
    });
    const { container } = renderWithAuth(<ProductMatchEvaluationsPageClient assetId={ASSET_ID} />, {
      authApi,
    });
    expect(await screen.findByText('<script>alert(1)</script>')).toBeInTheDocument();
    expect(container.querySelector('script')).toBeNull();
    expect(screen.getByText('Occurrences in this ingestion: 2')).toBeInTheDocument();
    expect(screen.getByText('Not evaluated')).toBeInTheDocument();
    expect(container.textContent).not.toContain(INGESTION_ID);
    expect(authApi.listProductMatchCandidates).toHaveBeenCalledTimes(1);
    expect(authApi.createControlledFinding).not.toHaveBeenCalled();
  });

  it('states when there is nothing to evaluate', async () => {
    const authApi = ownerApi();
    renderWithAuth(<ProductMatchEvaluationsPageClient assetId={ASSET_ID} />, { authApi });
    expect(
      await screen.findByText('There is nothing to evaluate for this asset.'),
    ).toBeInTheDocument();
  });

  it('confirms one revision and links to Finding targets after evaluation', async () => {
    const authApi = ownerApi({
      listProductMatchCandidates: vi.fn(async () => candidatePage()),
      evaluateProductMatch: vi.fn(async () => evaluationResponse('evaluated')),
    });
    const user = userEvent.setup();
    renderWithAuth(<ProductMatchEvaluationsPageClient assetId={ASSET_ID} />, { authApi });
    await user.click(await screen.findByRole('button', { name: 'Evaluate' }));
    await user.click(screen.getByRole('button', { name: 'Record product match evidence' }));
    await waitFor(() => {
      expect(authApi.evaluateProductMatch).toHaveBeenCalledTimes(1);
    });
    expect(authApi.evaluateProductMatch).toHaveBeenCalledWith(
      ASSET_ID,
      { advisoryRevisionId: REVISION_ID },
      CSRF_TOKEN_FIXTURE,
    );
    expect(Object.keys(authApi.evaluateProductMatch.mock.calls[0]?.[1] ?? {})).toEqual([
      'advisoryRevisionId',
    ]);
    const targets = await screen.findByRole('link', { name: 'Review controlled Finding targets' });
    expect(targets).toHaveAttribute('href', `/assets/${ASSET_ID}/findings/targets`);
    expect(authApi.createControlledFinding).not.toHaveBeenCalled();
    expect(screen.queryByText(/affected/i)).not.toBeInTheDocument();
  });

  it('discards the list when the ingestion changed and does not post again', async () => {
    const authApi = ownerApi({
      listProductMatchCandidates: vi.fn(async () => candidatePage()),
      evaluateProductMatch: vi.fn(async () =>
        evaluationResponse('evaluated', '88888888-8888-4888-8888-888888888888'),
      ),
    });
    const user = userEvent.setup();
    renderWithAuth(<ProductMatchEvaluationsPageClient assetId={ASSET_ID} />, { authApi });
    await user.click(await screen.findByRole('button', { name: 'Evaluate' }));
    await user.click(screen.getByRole('button', { name: 'Record product match evidence' }));
    expect(await screen.findByText(/this list was discarded/i)).toBeInTheDocument();
    expect(screen.queryByText('reviewed-npm-widget')).not.toBeInTheDocument();
    expect(authApi.evaluateProductMatch).toHaveBeenCalledTimes(1);
  });

  it('shows commit uncertainty once and does not retry', async () => {
    const authApi = ownerApi({
      listProductMatchCandidates: vi.fn(async () => candidatePage()),
      evaluateProductMatch: vi.fn(async () => {
        throw { status: 500, code: 'internal', message: 'An internal error occurred.' };
      }),
    });
    const user = userEvent.setup();
    renderWithAuth(<ProductMatchEvaluationsPageClient assetId={ASSET_ID} />, { authApi });
    await user.click(await screen.findByRole('button', { name: 'Evaluate' }));
    await user.click(screen.getByRole('button', { name: 'Record product match evidence' }));
    expect(await screen.findByText(/result is uncertain/i)).toBeInTheDocument();
    expect(authApi.evaluateProductMatch).toHaveBeenCalledTimes(1);
    expect(authApi.createControlledFinding).not.toHaveBeenCalled();
  });

  it('does not load candidates for an admin', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () =>
        sessionFixture({
          organization: { ...publicOrganizationFixture, role: 'admin' },
        }),
      ),
    });
    renderWithAuth(<ProductMatchEvaluationsPageClient assetId={ASSET_ID} />, { authApi });
    expect(await screen.findByText(/available to an owner/i)).toBeInTheDocument();
    expect(authApi.listProductMatchCandidates).not.toHaveBeenCalled();
  });

  it('reads the CSRF token at submit time and does not create a Finding', () => {
    const source = readFileSync(
      join(
        process.cwd(),
        'app/assets/[assetId]/product-match-evaluations/product-match-evaluations-page-client.tsx',
      ),
      'utf8',
    );
    expect(source).toContain('getCsrfToken()');
    expect(source).not.toContain('createControlledFinding');
    expect(source).not.toContain("'/findings'");
    expect(source).not.toContain('"/findings"');
    expect(source).not.toMatch(/useState\([^)]*csrf/i);
  });
});
