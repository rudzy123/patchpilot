'use client';

import Link from 'next/link';
import { useEffect, useState, type ReactElement } from 'react';

import type { RemediationQueueResponse } from '@patchpilot/contracts';

import { useAuth } from '../../components/auth-provider';
import { RequireAuth } from '../../components/require-auth';
import { SignedInShell } from '../../components/signed-in-shell';
import { isAuthRequestError } from '../../lib/auth-api';
import { canPresentRemediationQueue } from '../../lib/finding-permissions';
import {
  QUEUE_COMPARISON_MESSAGE,
  QUEUE_FORBIDDEN,
  QUEUE_HEADING,
  QUEUE_INCOMPARABLE_HEADING,
  QUEUE_INCOMPARABLE_NOTE,
  QUEUE_LOAD_MORE,
  QUEUE_LOADING,
  QUEUE_NOT_A_SNAPSHOT,
  QUEUE_NOT_CALCULATED_HEADING,
  QUEUE_NOT_CALCULATED_NOTE,
  QUEUE_POLICY_UNAVAILABLE,
  QUEUE_RANKED_HEADING,
  QUEUE_RATE_LIMITED,
  QUEUE_UNAVAILABLE,
  type RemediationQueueSection,
} from '../../lib/remediation-queue';

const SECTIONS = ['ranked', 'incomparable', 'not_calculated'] as const;

const HEADINGS: Record<RemediationQueueSection, string> = {
  ranked: QUEUE_RANKED_HEADING,
  incomparable: QUEUE_INCOMPARABLE_HEADING,
  not_calculated: QUEUE_NOT_CALCULATED_HEADING,
};

type PanelState = {
  readonly response: RemediationQueueResponse;
  readonly rows: readonly RemediationQueueResponse['rows'][number][];
  readonly loadingMore: boolean;
  readonly error: string | null;
};

type QueueView =
  | { readonly status: 'loading' }
  | { readonly status: 'denied' }
  | { readonly status: 'policy_unavailable' }
  | { readonly status: 'unavailable'; readonly message: string }
  | { readonly status: 'ready'; readonly panels: Record<RemediationQueueSection, PanelState> };

export function RemediationQueuePageClient(): ReactElement {
  return (
    <RequireAuth>
      <SignedInShell>
        <QueueOrganization />
      </SignedInShell>
    </RequireAuth>
  );
}

function QueueOrganization(): ReactElement {
  const { organization } = useAuth();
  return <QueuePanels key={organization?.id ?? 'none'} />;
}

function QueuePanels(): ReactElement {
  const { organization, api } = useAuth();
  const [view, setView] = useState<QueueView>({ status: 'loading' });
  const canRead = organization !== null && canPresentRemediationQueue(organization.role);

  useEffect(() => {
    if (!canRead) {
      setView({ status: 'denied' });
      return;
    }
    let cancelled = false;
    setView({ status: 'loading' });
    void Promise.all(
      SECTIONS.map(async (section) => {
        try {
          const page = await api.readRemediationQueue({ section });
          return { section, ok: true as const, page };
        } catch (error) {
          return { section, ok: false as const, error };
        }
      }),
    ).then((results) => {
      if (cancelled) {
        return;
      }
      if (results.some((result) => !result.ok && isPolicy(result.error))) {
        setView({ status: 'policy_unavailable' });
        return;
      }
      if (results.some((result) => !result.ok && isDenied(result.error))) {
        setView({ status: 'denied' });
        return;
      }
      if (results.some((result) => !result.ok)) {
        const failed = results.find((result) => !result.ok);
        setView({
          status: 'unavailable',
          message:
            failed !== undefined && !failed.ok ? messageFor(failed.error) : QUEUE_UNAVAILABLE,
        });
        return;
      }
      const panels = {} as Record<RemediationQueueSection, PanelState>;
      for (const result of results) {
        if (!result.ok) {
          return;
        }
        panels[result.section] = {
          response: result.page,
          rows: result.page.rows,
          loadingMore: false,
          error: null,
        };
      }
      setView({ status: 'ready', panels });
    });
    return () => {
      cancelled = true;
    };
  }, [api, canRead]);

  async function loadMore(section: RemediationQueueSection): Promise<void> {
    if (view.status !== 'ready') {
      return;
    }
    const panel = view.panels[section];
    const cursor = panel.response.nextCursor;
    if (cursor === null || panel.loadingMore) {
      return;
    }
    setView({
      status: 'ready',
      panels: {
        ...view.panels,
        [section]: { ...panel, loadingMore: true, error: null },
      },
    });
    try {
      const page = await api.readRemediationQueue({ section, cursor });
      setView((current) => replacePanel(current, section, page, true));
    } catch (error) {
      if (isAuthRequestError(error) && error.status === 409) {
        try {
          const page = await api.readRemediationQueue({ section });
          setView((current) => replacePanel(current, section, page, false));
          return;
        } catch (refreshError) {
          setView((current) => panelError(current, section, messageFor(refreshError)));
          return;
        }
      }
      if (isPolicy(error)) {
        setView({ status: 'policy_unavailable' });
        return;
      }
      setView((current) => panelError(current, section, messageFor(error)));
    }
  }

  return (
    <main>
      <h1>{QUEUE_HEADING}</h1>
      <p>{QUEUE_NOT_A_SNAPSHOT}</p>
      {view.status === 'loading' ? <p role="status">{QUEUE_LOADING}</p> : null}
      {view.status === 'denied' ? <p role="status">{QUEUE_FORBIDDEN}</p> : null}
      {view.status === 'policy_unavailable' ? (
        <p role="status">{QUEUE_POLICY_UNAVAILABLE}</p>
      ) : null}
      {view.status === 'unavailable' ? <p role="status">{view.message}</p> : null}
      {view.status === 'ready' ? (
        <>
          {SECTIONS.map((section) => (
            <QueuePanel
              key={section}
              section={section}
              panel={view.panels[section]}
              onLoadMore={() => void loadMore(section)}
            />
          ))}
        </>
      ) : null}
    </main>
  );
}

function QueuePanel({
  section,
  panel,
  onLoadMore,
}: {
  section: RemediationQueueSection;
  panel: PanelState;
  onLoadMore: () => void;
}): ReactElement {
  const headingId = `remediation-queue-${section}`;
  return (
    <section className="asset-fieldset" aria-labelledby={headingId}>
      <h2 id={headingId}>{HEADINGS[section]}</h2>
      {section === 'incomparable' ? <p>{QUEUE_INCOMPARABLE_NOTE}</p> : null}
      {section === 'not_calculated' ? <p>{QUEUE_NOT_CALCULATED_NOTE}</p> : null}
      <p>
        {panel.response.counts[section]} Findings. As of {panel.response.asOf}.
      </p>
      {panel.rows.length === 0 ? <p>No Findings in this section.</p> : null}
      <ul>
        {panel.rows.map((row) => (
          <li key={row.findingId}>
            <Link href={`/findings/${row.findingId}`}>{row.vulnerabilityPublicId}</Link>
            <p>{row.assetName}</p>
            <p>{row.componentName}</p>
            <p>{row.componentVersion}</p>
            {section !== 'not_calculated' && 'priorityBand' in row ? (
              <>
                <p>
                  {row.priorityBand} {row.priority}
                </p>
                <p>
                  {row.policy.policyKey} version {row.policy.policyVersion}
                </p>
                <p>Calculated {row.calculatedAt}</p>
                <p>
                  {row.inputsChanged.status === 'detected'
                    ? 'Stored identifiers changed.'
                    : 'No stored-identifier change was detected.'}
                </p>
                {section === 'incomparable' ? <p>{QUEUE_COMPARISON_MESSAGE}</p> : null}
              </>
            ) : null}
            <p>No priority review is recorded.</p>
          </li>
        ))}
      </ul>
      {panel.error !== null ? <p role="status">{panel.error}</p> : null}
      {panel.response.nextCursor !== null ? (
        <button type="button" onClick={onLoadMore} disabled={panel.loadingMore}>
          {QUEUE_LOAD_MORE}
        </button>
      ) : null}
    </section>
  );
}

function replacePanel(
  current: QueueView,
  section: RemediationQueueSection,
  page: RemediationQueueResponse,
  append: boolean,
): QueueView {
  if (current.status !== 'ready' || page.section !== section) {
    return { status: 'unavailable', message: QUEUE_UNAVAILABLE };
  }
  const panel = current.panels[section];
  return {
    status: 'ready',
    panels: {
      ...current.panels,
      [section]: {
        response: page,
        rows: append ? [...panel.rows, ...page.rows] : page.rows,
        loadingMore: false,
        error: null,
      },
    },
  };
}

function panelError(
  current: QueueView,
  section: RemediationQueueSection,
  message: string,
): QueueView {
  if (current.status !== 'ready') {
    return current;
  }
  return {
    status: 'ready',
    panels: {
      ...current.panels,
      [section]: { ...current.panels[section], loadingMore: false, error: message },
    },
  };
}

function isPolicy(error: unknown): boolean {
  return isAuthRequestError(error) && error.message === QUEUE_POLICY_UNAVAILABLE;
}

function isDenied(error: unknown): boolean {
  return isAuthRequestError(error) && error.status === 403;
}

function messageFor(error: unknown): string {
  if (!isAuthRequestError(error)) {
    return QUEUE_UNAVAILABLE;
  }
  if (error.status === 429 || error.code === 'rate_limited') {
    return QUEUE_RATE_LIMITED;
  }
  if (error.message === QUEUE_POLICY_UNAVAILABLE) {
    return QUEUE_POLICY_UNAVAILABLE;
  }
  if (error.message === QUEUE_UNAVAILABLE) {
    return QUEUE_UNAVAILABLE;
  }
  return QUEUE_UNAVAILABLE;
}
