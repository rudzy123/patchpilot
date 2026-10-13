import { useState, type ReactElement } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/react';

import type { ControlledFindingLatestObservationResponse } from '@patchpilot/contracts';

import { OrganizationSelector } from '../../../components/organization-selector';
import {
  CREATION_SOURCE_TEXT,
  GRAPH_COMPLETENESS_TEXT,
  KNOWN_VERSIONS_TRUNCATED,
  LATEST_OBSERVATION_HEADING,
  LATEST_OBSERVATION_LOADING,
  LATEST_OBSERVATION_NOT_FOUND,
  LATEST_OBSERVATION_RATE_LIMITED,
  LATEST_OBSERVATION_REFRESH,
  LATEST_OBSERVATION_UNAVAILABLE,
  LATEST_REPEATED_SOURCE_TEXT,
  NO_DEPENDENCIES_TEXT,
  OBSERVATION_RECORDED_LABEL,
} from '../../../lib/finding-latest-observation';
import { CONTROLLED_FINDING_UNAVAILABLE } from '../../../lib/finding-workflow';
import { GENERIC_SESSION_EXPIRED } from '../../../lib/auth-api';
import {
  createFakeAuthApi,
  ownerOrganizationFixture,
  publicOrganizationFixture,
  secondOrganizationFixture,
  sessionFixture,
} from '../../../test/auth-fixtures';
import {
  FINDING_ID,
  FINDING_ID_2,
  LATEST_OBSERVED_AT,
  componentAbsentLatestObservation,
  creationLatestObservation,
  latestOccurrenceObservation,
} from '../../../test/finding-fixtures';
import { inspectionFixture } from '../../../test/finding-fixtures';
import { renderWithAuth } from '../../../test/render-with-auth';
import { navigationMocks } from '../../../test/router-mock';

import { FindingInspectionPageClient } from './finding-inspection-page-client';

const LIFECYCLE_WORDS = [
  'resolved',
  'remediated',
  'verified',
  'safe',
  'closed',
  'priority',
  'exploit',
  'assignment',
  'urgency',
  'reopen',
  'recurrence',
  'stale',
  'risk',
];

function ownerApi(overrides: Parameters<typeof createFakeAuthApi>[0] = {}) {
  return createFakeAuthApi({
    readSession: vi.fn(async () => sessionFixture({ organization: ownerOrganizationFixture })),
    inspectControlledFinding: vi.fn(async () => inspectionFixture),
    inspectControlledFindingLatestObservation: vi.fn(async () => creationLatestObservation()),
    ...overrides,
  });
}

function adminApi(overrides: Parameters<typeof createFakeAuthApi>[0] = {}) {
  return createFakeAuthApi({
    readSession: vi.fn(async () =>
      sessionFixture({ organization: { ...publicOrganizationFixture, role: 'admin' } }),
    ),
    inspectControlledFinding: vi.fn(async () => inspectionFixture),
    inspectControlledFindingLatestObservation: vi.fn(async () => creationLatestObservation()),
    ...overrides,
  });
}

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve: (value: T) => void = () => {
    throw new Error('deferred resolve was not initialized');
  };
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

function repeatedObservation(
  aggregate: 'affected' | 'unaffected' | 'unknown',
  input: {
    findingId?: string;
    affectedSupportCount?: number;
    unaffectedSupportCount?: number;
    unknownSupportCount?: number;
    unknownVersionSupportCount?: number;
    values?: string[];
    truncated?: boolean;
    omittedDistinctCount?: number;
    distinctCount?: number;
  } = {},
): ControlledFindingLatestObservationResponse {
  const values = input.values ?? ['1.0.0'];
  return latestOccurrenceObservation({
    findingId: input.findingId ?? FINDING_ID,
    observationSource: 'latest_repeated',
    aggregate,
    affectedSupportCount: input.affectedSupportCount ?? (aggregate === 'affected' ? 1 : 0),
    unaffectedSupportCount: input.unaffectedSupportCount ?? 0,
    unknownSupportCount: input.unknownSupportCount ?? 0,
    unknownVersionSupportCount: input.unknownVersionSupportCount ?? 0,
    knownVersions: {
      values,
      truncated: input.truncated ?? false,
      omittedDistinctCount: input.omittedDistinctCount ?? 0,
      distinctCount: input.distinctCount ?? values.length,
    },
  });
}

function latestRegion(): HTMLElement {
  return screen.getByRole('region', { name: LATEST_OBSERVATION_HEADING });
}

function expectNonLifecycle(section: HTMLElement): void {
  const text = (section.textContent ?? '').toLowerCase();
  for (const word of LIFECYCLE_WORDS) {
    expect(text).not.toContain(word);
  }
  expect(text).not.toContain('current finding');
  expect(text).not.toContain('currently');
  expect(text).not.toContain('observation history');
}

describe('Finding latest-observation section', () => {
  it('shows the section to an owner and an admin and withholds it from member and viewer', async () => {
    const owner = ownerApi();
    const ownerView = renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, {
      authApi: owner,
    });
    expect(
      await screen.findByRole('heading', { level: 2, name: LATEST_OBSERVATION_HEADING }),
    ).toBeInTheDocument();
    expect(await screen.findByText(CREATION_SOURCE_TEXT)).toBeInTheDocument();
    expect(screen.getByText('<component>')).toBeInTheDocument();
    expect(owner.inspectControlledFinding).toHaveBeenCalledWith(FINDING_ID);
    expect(owner.inspectControlledFindingLatestObservation).toHaveBeenCalledTimes(1);
    expect(owner.inspectControlledFindingLatestObservation.mock.calls[0]).toEqual([FINDING_ID]);
    expect(owner.createControlledFinding).not.toHaveBeenCalled();
    ownerView.unmount();

    const admin = adminApi();
    const adminView = renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, {
      authApi: admin,
    });
    expect(
      await screen.findByRole('heading', { level: 2, name: LATEST_OBSERVATION_HEADING }),
    ).toBeInTheDocument();
    expect(admin.inspectControlledFindingLatestObservation).toHaveBeenCalledTimes(1);
    adminView.unmount();

    for (const role of ['member', 'viewer'] as const) {
      const authApi = createFakeAuthApi({
        readSession: vi.fn(async () =>
          sessionFixture({ organization: { ...publicOrganizationFixture, role } }),
        ),
      });
      const view = renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, {
        authApi,
      });
      expect(await screen.findByText(CONTROLLED_FINDING_UNAVAILABLE)).toBeInTheDocument();
      expect(
        screen.queryByRole('heading', { level: 2, name: LATEST_OBSERVATION_HEADING }),
      ).not.toBeInTheDocument();
      await waitFor(() => {
        expect(authApi.inspectControlledFinding).not.toHaveBeenCalled();
        expect(authApi.inspectControlledFindingLatestObservation).not.toHaveBeenCalled();
      });
      view.unmount();
    }
  });

  it('does not request latest observation without an active organization', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture({ organization: null })),
    });
    renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, { authApi });
    expect(
      await screen.findByRole('heading', { name: 'Organization context is required' }),
    ).toBeInTheDocument();
    expect(authApi.inspectControlledFinding).not.toHaveBeenCalled();
    expect(authApi.inspectControlledFindingLatestObservation).not.toHaveBeenCalled();
  });

  it('keeps creation inspection visible while latest observation loads and after it arrives', async () => {
    const latest = deferred<ControlledFindingLatestObservationResponse>();
    const creation = deferred<typeof inspectionFixture>();
    const authApi = ownerApi({
      inspectControlledFinding: vi.fn(() => creation.promise),
      inspectControlledFindingLatestObservation: vi.fn(() => latest.promise),
    });
    renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, { authApi });

    expect(await screen.findByText('Loading Finding')).toBeInTheDocument();
    expect(screen.getByText(LATEST_OBSERVATION_LOADING)).toBeInTheDocument();
    expect(latestRegion()).toHaveAttribute('aria-busy', 'true');
    expect(screen.getByRole('button', { name: LATEST_OBSERVATION_REFRESH })).toBeDisabled();

    latest.resolve(creationLatestObservation());
    expect(await screen.findByText(CREATION_SOURCE_TEXT)).toBeInTheDocument();
    expect(screen.getByText('Loading Finding')).toBeInTheDocument();
    expect(screen.queryByText('<component>')).not.toBeInTheDocument();

    creation.resolve(inspectionFixture);
    expect(await screen.findByText('<component>')).toBeInTheDocument();
    expect(screen.getByText(CREATION_SOURCE_TEXT)).toBeInTheDocument();
    expect(screen.getByText(/unavailable in this workflow/)).toBeInTheDocument();
    expect(latestRegion()).toHaveAttribute('aria-busy', 'false');
    expect(screen.getByRole('button', { name: LATEST_OBSERVATION_REFRESH })).toBeEnabled();
    expect(authApi.inspectControlledFindingLatestObservation).toHaveBeenCalledTimes(1);
  });

  it('renders creation evidence when creation inspection finishes first', async () => {
    const latest = deferred<ControlledFindingLatestObservationResponse>();
    const authApi = ownerApi({
      inspectControlledFindingLatestObservation: vi.fn(() => latest.promise),
    });
    renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, { authApi });
    expect(await screen.findByText('<component>')).toBeInTheDocument();
    expect(screen.getByText(LATEST_OBSERVATION_LOADING)).toBeInTheDocument();
    latest.resolve(
      repeatedObservation('affected', {
        affectedSupportCount: 2,
        unaffectedSupportCount: 1,
        unknownSupportCount: 3,
        unknownVersionSupportCount: 4,
        values: ['10.0.0', '2.0.0'],
      }),
    );
    expect(await screen.findByText(LATEST_REPEATED_SOURCE_TEXT)).toBeInTheDocument();
    expect(screen.getByText('<component>')).toBeInTheDocument();
    expect(screen.getByText('Historical')).toBeInTheDocument();
  });

  it('uses honest non-lifecycle wording for every aggregate', async () => {
    const cases = [
      {
        observation: creationLatestObservation(),
        source: CREATION_SOURCE_TEXT,
        label: 'Affected evidence',
        explanation: 'The selected observation contains governed affected evidence.',
        absent: LATEST_REPEATED_SOURCE_TEXT,
      },
      {
        observation: repeatedObservation('affected', { affectedSupportCount: 2 }),
        source: LATEST_REPEATED_SOURCE_TEXT,
        label: 'Affected evidence',
        explanation: 'The selected observation contains governed affected evidence.',
        absent: CREATION_SOURCE_TEXT,
      },
      {
        observation: repeatedObservation('unaffected', { unaffectedSupportCount: 2 }),
        source: LATEST_REPEATED_SOURCE_TEXT,
        label: 'Unaffected evidence',
        explanation:
          'All relevant present occurrences were legally classified as unaffected in the selected ingestion.',
        absent: 'Creation evidence is the latest available',
      },
      {
        observation: repeatedObservation('unknown', { unknownSupportCount: 3 }),
        source: LATEST_REPEATED_SOURCE_TEXT,
        label: 'Unknown evidence',
        explanation:
          'The evidence could not establish affected or unaffected for every relevant occurrence.',
        absent: 'safe',
      },
    ];

    for (const entry of cases) {
      const authApi = ownerApi({
        inspectControlledFindingLatestObservation: vi.fn(async () => entry.observation),
      });
      const view = renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, {
        authApi,
      });
      expect(await screen.findByText(entry.source)).toBeInTheDocument();
      const section = latestRegion();
      expect(within(section).getByRole('heading', { level: 3, name: entry.label })).toBeVisible();
      expect(within(section).getByText(entry.explanation)).toBeVisible();
      expect(within(section).getByText(OBSERVATION_RECORDED_LABEL)).toBeVisible();
      expect(within(section).getByText(`${LATEST_OBSERVED_AT} UTC`)).toBeVisible();
      expect(section).not.toHaveTextContent(entry.absent);
      expect(
        within(section).queryByText(/resolved at|remediated at|verified at|reopened at/i),
      ).toBeNull();
      expectNonLifecycle(section);
      expect(screen.getByText('<component>')).toBeInTheDocument();
      view.unmount();
    }
  });

  it('renders support counts, ordered escaped versions, and truncation text', async () => {
    const authApi = ownerApi({
      inspectControlledFindingLatestObservation: vi.fn(async () =>
        repeatedObservation('affected', {
          affectedSupportCount: 2,
          unaffectedSupportCount: 1,
          unknownSupportCount: 3,
          unknownVersionSupportCount: 4,
          values: ['1', '2', '3', '4', '5', '6', '7', '<script>alert(1)</script>'],
          truncated: true,
          omittedDistinctCount: 2,
          distinctCount: 10,
        }),
      ),
    });
    const { container } = renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, {
      authApi,
    });
    expect(await screen.findByText('Affected support')).toBeInTheDocument();
    const section = latestRegion();
    expect(within(section).getByText('Affected support').parentElement).toHaveTextContent('2');
    expect(within(section).getByText('Unaffected support').parentElement).toHaveTextContent('1');
    expect(within(section).getByText('Unknown support').parentElement).toHaveTextContent('3');
    expect(within(section).getByText('Unknown-version support').parentElement).toHaveTextContent(
      '4',
    );
    const versions = within(section).getAllByRole('listitem');
    expect(versions.map((item) => item.textContent)).toEqual([
      '1',
      '2',
      '3',
      '4',
      '5',
      '6',
      '7',
      '<script>alert(1)</script>',
    ]);
    expect(within(section).getByText(KNOWN_VERSIONS_TRUNCATED)).toBeVisible();
    expect(within(section).getByText('Omitted distinct versions: 2')).toBeVisible();
    expect(within(section).getByText('Distinct known versions: 10')).toBeVisible();
    expect(
      within(section).getByRole('heading', { name: 'Known versions represented' }),
    ).toBeVisible();
    expect(within(section).queryByRole('link')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('img')).toBeNull();
    expect(screen.getByText('<component>')).toBeInTheDocument();
  });

  it('preserves API version order instead of sorting numerically', async () => {
    const authApi = ownerApi({
      inspectControlledFindingLatestObservation: vi.fn(async () =>
        repeatedObservation('unknown', {
          unknownSupportCount: 1,
          values: ['10.0.0', '2.0.0'],
        }),
      ),
    });
    renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, { authApi });
    expect(await screen.findByText('10.0.0')).toBeInTheDocument();
    const section = latestRegion();
    expect(
      within(section)
        .getAllByRole('listitem')
        .map((item) => item.textContent),
    ).toEqual(['10.0.0', '2.0.0']);
    expectNonLifecycle(section);
  });

  it('renders component absence without support counts or closure language', async () => {
    for (const graph of ['complete', 'no_dependencies'] as const) {
      const authApi = ownerApi({
        inspectControlledFindingLatestObservation: vi.fn(async () =>
          componentAbsentLatestObservation(graph),
        ),
      });
      const view = renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, {
        authApi,
      });
      expect(
        await screen.findByRole('heading', {
          level: 3,
          name: 'Component absent in selected ingestion',
        }),
      ).toBeVisible();
      const section = latestRegion();
      expect(
        within(section).getByText(
          'Governed evidence found no occurrence of the Component in the selected ingestion graph.',
        ),
      ).toBeVisible();
      expect(within(section).getByText('Graph completeness').parentElement).toHaveTextContent(
        graph,
      );
      expect(within(section).getByText(GRAPH_COMPLETENESS_TEXT)).toBeVisible();
      if (graph === 'no_dependencies') {
        expect(within(section).getByText(NO_DEPENDENCIES_TEXT)).toBeVisible();
      }
      expect(within(section).queryByText('Affected support')).toBeNull();
      expect(within(section).queryByText(/fingerprint|componentCount|dependencyEdge/i)).toBeNull();
      expectNonLifecycle(section);
      expect(screen.getByRole('link', { name: 'Open asset' })).toBeInTheDocument();
      view.unmount();
    }
  });

  it('keeps creation inspection when latest observation is not found, limited, or unavailable', async () => {
    const failures = [
      {
        error: { status: 404, code: 'not_found', message: 'Not found.' },
        text: LATEST_OBSERVATION_NOT_FOUND,
      },
      {
        error: {
          status: 429,
          code: 'rate_limited',
          message: 'Too many requests. Try again later.',
        },
        text: LATEST_OBSERVATION_RATE_LIMITED,
      },
      {
        error: {
          status: 503,
          code: 'internal',
          message: 'Finding operator is temporarily unavailable.',
        },
        text: LATEST_OBSERVATION_UNAVAILABLE,
      },
      {
        error: new Error('SELECT secret-marker-value'),
        text: LATEST_OBSERVATION_UNAVAILABLE,
      },
      {
        error: {
          status: 400,
          code: 'validation',
          message: 'Invalid request. secret-marker-value',
        },
        text: LATEST_OBSERVATION_UNAVAILABLE,
      },
    ];

    for (const failure of failures) {
      const authApi = ownerApi({
        inspectControlledFindingLatestObservation: vi.fn(async () => {
          throw failure.error;
        }),
      });
      const view = renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, {
        authApi,
      });
      expect(await screen.findByText('<component>')).toBeInTheDocument();
      const section = latestRegion();
      expect(within(section).getByRole('alert')).toHaveTextContent(failure.text);
      expect(screen.getByRole('link', { name: 'Review controlled Finding targets' })).toBeVisible();
      expect(screen.queryByText('secret-marker-value')).not.toBeInTheDocument();
      expect(screen.queryByText(/SELECT/)).not.toBeInTheDocument();
      expect(
        screen.queryByText('Finding operator is temporarily unavailable.'),
      ).not.toBeInTheDocument();
      expect(authApi.inspectControlledFindingLatestObservation).toHaveBeenCalledTimes(1);
      expect(authApi.createControlledFinding).not.toHaveBeenCalled();
      view.unmount();
    }
  });

  it('keeps a malformed latest response inside the section', async () => {
    const authApi = ownerApi({
      inspectControlledFindingLatestObservation: vi.fn(async () => {
        const malformed = {
          schemaVersion: 'finding_latest_observation_transport_v1',
          findingId: FINDING_ID,
          observationSource: 'creation',
          observedAt: 'not-a-timestamp',
          aggregate: 'affected',
          mappedResult: 'present',
          observations: ['secret-history-version'],
          evidence: { kind: 'occurrence_support', secretMarker: 'secret-marker-value' },
        };
        return malformed as unknown as ControlledFindingLatestObservationResponse;
      }),
    });
    renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, { authApi });
    expect(await screen.findByText('<component>')).toBeInTheDocument();
    expect(within(latestRegion()).getByRole('alert')).toHaveTextContent(
      LATEST_OBSERVATION_UNAVAILABLE,
    );
    expect(screen.queryByText('secret-history-version')).not.toBeInTheDocument();
    expect(screen.queryByText('secret-marker-value')).not.toBeInTheDocument();
    expect(screen.queryByText('not-a-timestamp')).not.toBeInTheDocument();
  });

  it('does not let a latest success replace a failed creation inspection', async () => {
    const authApi = ownerApi({
      inspectControlledFinding: vi.fn(async () => {
        throw { status: 404, code: 'not_found', message: 'Not found.' };
      }),
      inspectControlledFindingLatestObservation: vi.fn(async () => creationLatestObservation()),
    });
    renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, { authApi });
    expect(await screen.findByText('Not found.')).toBeInTheDocument();
    expect(await screen.findByText(CREATION_SOURCE_TEXT)).toBeInTheDocument();
    expect(screen.queryByText('<component>')).not.toBeInTheDocument();
    expect(screen.queryByText('Historical')).not.toBeInTheDocument();
  });

  it('clears latest data for 403 and leaves a 401 inside the section', async () => {
    let latestCalls = 0;
    const authApi = ownerApi({
      inspectControlledFindingLatestObservation: vi.fn(async () => {
        latestCalls += 1;
        if (latestCalls === 1) {
          return repeatedObservation('affected', { values: ['latest-only-version'] });
        }
        throw { status: 403, code: 'forbidden', message: 'Permission denied.' };
      }),
    });
    const forbiddenView = renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, {
      authApi,
    });
    expect(await screen.findByText('latest-only-version')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: LATEST_OBSERVATION_REFRESH }));
    expect(await within(latestRegion()).findByRole('alert')).toHaveTextContent(
      CONTROLLED_FINDING_UNAVAILABLE,
    );
    expect(screen.queryByText('latest-only-version')).not.toBeInTheDocument();
    expect(screen.getByText('<component>')).toBeInTheDocument();
    expect(navigationMocks.replace).not.toHaveBeenCalled();
    forbiddenView.unmount();

    const expired = ownerApi({
      inspectControlledFindingLatestObservation: vi.fn(async () => {
        throw { status: 401, code: 'unauthorized', message: 'Authentication required.' };
      }),
    });
    renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, { authApi: expired });
    expect(await screen.findByText('<component>')).toBeInTheDocument();
    expect(within(latestRegion()).getByRole('alert')).toHaveTextContent(GENERIC_SESSION_EXPIRED);
    expect(screen.getByRole('button', { name: LATEST_OBSERVATION_REFRESH })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: LATEST_OBSERVATION_REFRESH }));
    expect(expired.inspectControlledFindingLatestObservation).toHaveBeenCalledTimes(1);
    expect(navigationMocks.replace).not.toHaveBeenCalled();
    expect(screen.getByText('<component>')).toBeInTheDocument();
  });

  it('still sends creation inspection to the session-expired page when that request is unauthorized', async () => {
    const authApi = ownerApi({
      inspectControlledFinding: vi.fn(async () => {
        throw { status: 401, code: 'unauthorized', message: 'expired' };
      }),
      inspectControlledFindingLatestObservation: vi.fn(async () => {
        throw { status: 401, code: 'unauthorized', message: 'expired' };
      }),
    });
    renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, { authApi });
    await waitFor(() => {
      expect(navigationMocks.replace).toHaveBeenCalledWith('/session-expired');
    });
    expect(authApi.inspectControlledFindingLatestObservation).toHaveBeenCalledTimes(1);
  });

  it('refreshes once when asked and does not retry a rate limit', async () => {
    const second = deferred<ControlledFindingLatestObservationResponse>();
    let calls = 0;
    const authApi = ownerApi({
      inspectControlledFindingLatestObservation: vi.fn(() => {
        calls += 1;
        if (calls === 1) {
          return Promise.resolve(repeatedObservation('affected', { values: ['first-version'] }));
        }
        return second.promise;
      }),
    });
    renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, { authApi });
    expect(await screen.findByText('first-version')).toBeInTheDocument();
    const button = screen.getByRole('button', { name: LATEST_OBSERVATION_REFRESH });
    button.focus();
    expect(button).toHaveFocus();
    expect(button).toHaveAttribute('type', 'button');
    fireEvent.click(button);
    expect(button).toBeDisabled();
    expect(screen.getByText(LATEST_OBSERVATION_LOADING)).toBeInTheDocument();
    expect(screen.queryByText('first-version')).not.toBeInTheDocument();
    expect(screen.getByText('<component>')).toBeInTheDocument();
    expect(calls).toBe(2);
    second.resolve(
      repeatedObservation('unaffected', { unaffectedSupportCount: 1, values: ['second-version'] }),
    );
    expect(await screen.findByText('second-version')).toBeInTheDocument();
    expect(screen.getByText(LATEST_REPEATED_SOURCE_TEXT)).toBeInTheDocument();
    expect(screen.queryByText('first-version')).not.toBeInTheDocument();
    expect(calls).toBe(2);
    expect(authApi.createControlledFinding).not.toHaveBeenCalled();
    expect(screen.getByText('<component>')).toBeInTheDocument();
  });

  it('ignores a stale latest response after the Finding route changes', async () => {
    const first = deferred<ControlledFindingLatestObservationResponse>();
    let calls = 0;
    const authApi = ownerApi({
      inspectControlledFinding: vi.fn(async (findingId: string) => ({
        ...inspectionFixture,
        findingId,
      })),
      inspectControlledFindingLatestObservation: vi.fn((findingId: string) => {
        calls += 1;
        if (calls === 1) {
          return first.promise;
        }
        return Promise.resolve(
          repeatedObservation('affected', { findingId, values: ['route-b-only'] }),
        );
      }),
    });
    function SwitchFinding(): ReactElement {
      const [findingId, setFindingId] = useState(FINDING_ID);
      return (
        <>
          <button type="button" onClick={() => setFindingId(FINDING_ID_2)}>
            Switch fixture finding
          </button>
          <FindingInspectionPageClient findingId={findingId} />
        </>
      );
    }
    renderWithAuth(<SwitchFinding />, { authApi });
    await waitFor(() => {
      expect(calls).toBe(1);
    });
    fireEvent.click(screen.getByRole('button', { name: 'Switch fixture finding' }));
    expect(await screen.findByText('route-b-only')).toBeInTheDocument();
    first.resolve(repeatedObservation('affected', { values: ['route-a-only'] }));
    await waitFor(() => {
      expect(screen.queryByText('route-a-only')).not.toBeInTheDocument();
    });
    expect(screen.getByText('route-b-only')).toBeInTheDocument();
    expect(screen.getByText('<component>')).toBeInTheDocument();
  });

  it('drops the previous organization response when the active organization changes', async () => {
    const first = deferred<ControlledFindingLatestObservationResponse>();
    let calls = 0;
    const ownerB = { ...secondOrganizationFixture, role: 'owner' as const };
    const authApi = ownerApi({
      listOrganizations: vi.fn(async () => ({
        organizations: [ownerOrganizationFixture, ownerB],
      })),
      selectOrganization: vi.fn(async () => sessionFixture({ organization: ownerB })),
      inspectControlledFindingLatestObservation: vi.fn(() => {
        calls += 1;
        if (calls === 1) {
          return first.promise;
        }
        return Promise.resolve(repeatedObservation('affected', { values: ['tenant-b-only'] }));
      }),
    });
    renderWithAuth(
      <>
        <OrganizationSelector onSelected={() => undefined} />
        <FindingInspectionPageClient findingId={FINDING_ID} />
      </>,
      { authApi },
    );
    await waitFor(() => {
      expect(calls).toBe(1);
    });
    fireEvent.change(screen.getByLabelText('Organization'), { target: { value: ownerB.id } });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByText('tenant-b-only')).toBeInTheDocument();
    first.resolve(repeatedObservation('affected', { values: ['tenant-a-only'] }));
    await waitFor(() => {
      expect(screen.queryByText('tenant-a-only')).not.toBeInTheDocument();
    });
    expect(screen.getByText('tenant-b-only')).toBeInTheDocument();
    expect(screen.getByText('<component>')).toBeInTheDocument();
  });

  it('keeps latest observation out of browser storage and does not add history or lifecycle controls', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    const indexedOpen =
      typeof window.indexedDB?.open === 'function' ? vi.spyOn(window.indexedDB, 'open') : null;
    const authApi = ownerApi({
      inspectControlledFindingLatestObservation: vi.fn(async () =>
        repeatedObservation('affected', { values: ['<svg/onload=alert(1)>'] }),
      ),
    });
    const { container, unmount } = renderWithAuth(
      <FindingInspectionPageClient findingId={FINDING_ID} />,
      { authApi },
    );
    expect(await screen.findByText('<svg/onload=alert(1)>')).toBeInTheDocument();
    const section = latestRegion();
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('svg')).toBeNull();
    expect(setItem).not.toHaveBeenCalled();
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
    if (indexedOpen !== null) {
      expect(indexedOpen).not.toHaveBeenCalled();
    }
    expect(within(section).queryByText(/observation history/i)).toBeNull();
    expect(
      screen.queryByRole('button', { name: /close|reopen|suppress|assign|remediat|verify/i }),
    ).not.toBeInTheDocument();
    expect(navigationMocks.push).not.toHaveBeenCalled();
    expect(section).toHaveClass('finding-latest-observation');
    unmount();
    expect(screen.queryByText('<svg/onload=alert(1)>')).not.toBeInTheDocument();
    setItem.mockRestore();
    indexedOpen?.mockRestore();
  });
});
