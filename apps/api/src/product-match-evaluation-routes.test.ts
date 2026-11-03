import { randomUUID } from 'node:crypto';

import type { SessionResponse } from '@patchpilot/contracts';
import { DELIBERATE_PRODUCT_MATCH_EVALUATION_RESPONSE_SCHEMA_VERSION as CONTRACT_VERSION } from '@patchpilot/contracts';
import { FINDING_INSPECTION_RESULT_SCHEMA_VERSION } from '@patchpilot/domain';
import {
  DELIBERATE_PRODUCT_MATCH_EVALUATION_FAILURE_STATUSES,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_RESPONSE_SCHEMA_VERSION as SERVICE_VERSION,
} from '@patchpilot/vulnerability-intelligence/deliberate-product-match-evaluation';
import type { FastifyInstance, InjectOptions } from 'fastify';
import { describe, expect, it } from 'vitest';

import type { AuthTestHarness } from './auth-test-harness.js';
import {
  TEST_ORIGIN,
  VALID_PASSWORD,
  buildTestApi,
  createAuthTestHarness,
} from './auth-test-harness.js';
import type { FindingOperatorRuntime } from './finding-runtime.js';
import type { FindingOrganizationRateLimiter } from './finding-rate-limit.js';
import { PRODUCT_MATCH_EVALUATION_ROUTE } from './product-match-evaluation-routes.js';
import type {
  ProductMatchEvaluationExecuteInput,
  ProductMatchEvaluationRuntime,
  ProductMatchEvaluationRuntimeResult,
} from './product-match-evaluation-runtime.js';

const ASSET = '44444444-4444-4444-8444-444444444444';
const REVISION = '55555555-5555-4555-8555-555555555555';
const INGESTION = '66666666-6666-4666-8666-666666666666';
const FOREIGN_ASSET = '99999999-9999-4999-8999-999999999999';
const REQUEST_ID = 'req-product-match-1';
const CORRELATION_ID = '77777777-7777-4777-8777-777777777777';
const SECRET = 'evidence-secret-marker';
const LOGIN_IP = '192.0.2.10';

const HIDDEN_TOKENS = [
  'invalid_command',
  'authority_required',
  'authority_rejected',
  'advisory_not_eligible',
  'no_successful_ingestion',
  'ingestion_not_evaluable',
  'capacity_exceeded',
  'immutable_conflict',
  'malformed_persisted_state',
  'transaction_aborted',
  'internal_failure',
  'database_unavailable',
  'timeout',
  'withdrawn',
  'quarantined',
  SECRET,
] as const;

const PUBLIC_FAILURES: Record<
  (typeof DELIBERATE_PRODUCT_MATCH_EVALUATION_FAILURE_STATUSES)[number],
  { readonly statusCode: number; readonly code: string; readonly message: string }
> = {
  invalid_command: { statusCode: 400, code: 'validation', message: 'Invalid request.' },
  authority_required: { statusCode: 403, code: 'forbidden', message: 'Permission denied.' },
  authority_rejected: { statusCode: 403, code: 'forbidden', message: 'Permission denied.' },
  not_found: { statusCode: 404, code: 'not_found', message: 'Not found.' },
  advisory_not_eligible: {
    statusCode: 422,
    code: 'unprocessable_evidence',
    message: 'The advisory revision cannot be evaluated.',
  },
  no_successful_ingestion: {
    statusCode: 422,
    code: 'unprocessable_evidence',
    message: 'The asset has no evaluable ingestion.',
  },
  ingestion_not_evaluable: {
    statusCode: 422,
    code: 'unprocessable_evidence',
    message: 'The asset has no evaluable ingestion.',
  },
  capacity_exceeded: {
    statusCode: 422,
    code: 'unprocessable_evidence',
    message: 'The asset exceeds the evaluation occurrence limit.',
  },
  immutable_conflict: {
    statusCode: 409,
    code: 'conflict',
    message: 'The request conflicts with stored evidence.',
  },
  malformed_persisted_state: {
    statusCode: 500,
    code: 'internal',
    message: 'An internal error occurred.',
  },
  transaction_aborted: {
    statusCode: 500,
    code: 'internal',
    message: 'An internal error occurred.',
  },
  internal_failure: {
    statusCode: 500,
    code: 'internal',
    message: 'An internal error occurred.',
  },
  timeout: {
    statusCode: 503,
    code: 'internal',
    message: 'Product Match Evidence evaluation is temporarily unavailable.',
  },
  database_unavailable: {
    statusCode: 503,
    code: 'internal',
    message: 'Product Match Evidence evaluation is temporarily unavailable.',
  },
};

type RoleName = 'owner' | 'admin' | 'member' | 'viewer';

type EvaluationCall = ProductMatchEvaluationExecuteInput;

function evaluatedBody(patch: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: CONTRACT_VERSION,
    status: 'evaluated',
    assetId: ASSET,
    advisoryRevisionId: REVISION,
    ingestionId: INGESTION,
    selectedCount: 3,
    evaluatedCount: 2,
    insertedCount: 2,
    replayedCount: 0,
    skippedCount: 1,
    skippedByReason: { version_not_known: 1, version_unrepresentable: 0 },
    outcomeCounts: { affected: 1, unaffected: 1, unknown: 0 },
    findingCreation: 'unavailable',
    findingWrites: 0,
    matchEvidenceId: SECRET,
    ...patch,
  };
}

function scriptedEvaluation(initial: Record<string, unknown> = evaluatedBody()): {
  runtime: ProductMatchEvaluationRuntime;
  calls: EvaluationCall[];
  set(next: Record<string, unknown>): void;
} {
  const calls: EvaluationCall[] = [];
  let next = initial;
  return {
    calls,
    set(value) {
      next = value;
    },
    runtime: {
      async execute(input) {
        calls.push(input);
        return next as ProductMatchEvaluationRuntimeResult;
      },
    },
  };
}

function findingSpy(): { runtime: FindingOperatorRuntime; calls: number } {
  const state = { calls: 0 };
  return {
    get calls() {
      return state.calls;
    },
    runtime: {
      creation: {
        async execute() {
          state.calls += 1;
          return { status: 'authority_required' };
        },
      },
      inspection: {
        async execute() {
          state.calls += 1;
          return {
            schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
            status: 'not_found' as const,
          };
        },
      },
      latestObservation: {
        async execute() {
          state.calls += 1;
          return { status: 'authority_required' };
        },
      },
    },
  };
}

describe('deliberate product match evaluation route', () => {
  it('uses the same public response version as the application service', () => {
    expect(CONTRACT_VERSION).toBe(SERVICE_VERSION);
    expect(Object.keys(PUBLIC_FAILURES)).toEqual([
      ...DELIBERATE_PRODUCT_MATCH_EVALUATION_FAILURE_STATUSES,
    ]);
  });

  it('rejects an unauthenticated caller and stores no cache', async () => {
    const script = scriptedEvaluation();
    const { app } = await boot('owner', { productMatchEvaluation: script.runtime });
    const response = await post(app, null, { advisoryRevisionId: REVISION }, '198.51.100.1');
    expect(response.statusCode).toBe(401);
    expect(response.headers['cache-control']).toBe('private, no-store');
    expectEnvelope(response, 'unauthorized', 'Authentication required.');
    expect(script.calls).toHaveLength(0);
    await app.close();
  });

  it('rejects a session without an active organization', async () => {
    const script = scriptedEvaluation();
    const { app, session } = await boot('owner', {
      membershipCount: 2,
      productMatchEvaluation: script.runtime,
    });
    const response = await post(app, session, { advisoryRevisionId: REVISION }, '198.51.100.2');
    expect(response.statusCode).toBe(403);
    expectEnvelope(response, 'forbidden', 'Organization context is required.');
    expect(script.calls).toHaveLength(0);
    await app.close();
  });

  it('requires JSON, an allowed origin, CSRF, and no query string', async () => {
    const script = scriptedEvaluation();
    const { app, session } = await boot('owner', { productMatchEvaluation: script.runtime });
    const text = await post(app, session, { advisoryRevisionId: REVISION }, '198.51.100.3', {
      'content-type': 'text/plain',
    });
    const charset = await post(app, session, { advisoryRevisionId: REVISION }, '198.51.100.4', {
      'content-type': 'application/json; charset=utf-16',
    });
    const missingOrigin = await app.inject({
      method: 'POST',
      url: evaluationUrl(ASSET),
      remoteAddress: '198.51.100.5',
      headers: {
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': session.csrf,
      },
      payload: { advisoryRevisionId: REVISION },
    });
    const badOrigin = await post(app, session, { advisoryRevisionId: REVISION }, '198.51.100.6', {
      origin: 'https://evil.example',
    });
    const missingCsrf = await app.inject({
      method: 'POST',
      url: evaluationUrl(ASSET),
      remoteAddress: '198.51.100.7',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: session.cookie,
      },
      payload: { advisoryRevisionId: REVISION },
    });
    const anonymousQuery = await app.inject({
      method: 'POST',
      url: `${evaluationUrl(ASSET)}?advisoryRevisionId=${REVISION}`,
      remoteAddress: '198.51.100.8',
      headers: { origin: TEST_ORIGIN, 'content-type': 'application/json' },
      payload: { advisoryRevisionId: REVISION },
    });
    const authenticatedQuery = await app.inject({
      method: 'POST',
      url: `${evaluationUrl(ASSET)}?ignored=1`,
      remoteAddress: '198.51.100.9',
      headers: mutationHeaders(session),
      payload: { advisoryRevisionId: REVISION },
    });
    expect(text.statusCode).toBe(400);
    expect(charset.statusCode).toBe(400);
    expect(missingOrigin.statusCode).toBe(403);
    expect(badOrigin.statusCode).toBe(403);
    expect(missingCsrf.statusCode).toBe(401);
    expect(anonymousQuery.statusCode).toBe(400);
    expect(authenticatedQuery.statusCode).toBe(400);
    expectEnvelope(text, 'validation', 'Invalid request.');
    expectEnvelope(anonymousQuery, 'validation', 'Invalid request.');
    expectEnvelope(missingOrigin, 'forbidden', 'Origin is not allowed.');
    expectEnvelope(missingCsrf, 'unauthorized', 'Authentication required.');
    expect(anonymousQuery.headers['cache-control']).toBe('private, no-store');
    expect(script.calls).toHaveLength(0);
    await app.close();
  });

  it('rejects a repeated origin or CSRF header', async () => {
    const script = scriptedEvaluation();
    const { app, session } = await boot('owner', { productMatchEvaluation: script.runtime });
    const origins = await app.inject({
      method: 'POST',
      url: evaluationUrl(ASSET),
      remoteAddress: '198.51.100.10',
      headers: repeatedHeader({
        origin: [TEST_ORIGIN, 'https://evil.example'],
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': session.csrf,
      }),
      payload: { advisoryRevisionId: REVISION },
    });
    const csrf = await app.inject({
      method: 'POST',
      url: evaluationUrl(ASSET),
      remoteAddress: '198.51.100.11',
      headers: repeatedHeader({
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': [session.csrf, 'other-token'],
      }),
      payload: { advisoryRevisionId: REVISION },
    });
    expect(origins.statusCode).toBe(403);
    expect(csrf.statusCode).toBe(401);
    expectEnvelope(origins, 'forbidden', 'Origin is not allowed.');
    expectEnvelope(csrf, 'unauthorized', 'Authentication required.');
    expect(script.calls).toHaveLength(0);
    await app.close();
  });

  it('rejects an oversized or invalid content length before the runtime', async () => {
    const script = scriptedEvaluation();
    const { app, session } = await boot('owner', { productMatchEvaluation: script.runtime });
    const oversized = await app.inject({
      method: 'POST',
      url: evaluationUrl(ASSET),
      remoteAddress: '198.51.100.12',
      headers: {
        ...mutationHeaders(session),
        'content-length': '1025',
      },
      payload: 'x'.repeat(1025),
    });
    const invalidLength = await app.inject({
      method: 'POST',
      url: evaluationUrl(ASSET),
      remoteAddress: '198.51.100.13',
      headers: {
        ...mutationHeaders(session),
        'content-length': '1024abc',
      },
      payload: { advisoryRevisionId: REVISION },
    });
    expect(oversized.statusCode).toBe(400);
    expect(invalidLength.statusCode).toBe(400);
    expectEnvelope(oversized, 'validation', 'Invalid request.');
    expect(oversized.headers['cache-control']).toBe('private, no-store');
    expect(script.calls).toHaveLength(0);
    await app.close();
  });

  it('keeps evaluation owner-only and does not spend organization budget on denial', async () => {
    const script = scriptedEvaluation();
    const findings = findingSpy();
    let consumed = 0;
    const seen: string[] = [];
    const { app, session, harness } = await boot('owner', {
      productMatchEvaluation: script.runtime,
      findings: findings.runtime,
      productMatchEvaluationOrganizationLimiter: {
        consume(organizationId) {
          consumed += 1;
          seen.push(organizationId);
          return 'allowed';
        },
      },
    });
    for (const role of ['admin', 'member', 'viewer'] as const) {
      setRole(harness, role);
      const denied = await post(app, session, { advisoryRevisionId: REVISION }, randomAddress());
      expect(denied.statusCode).toBe(403);
      expectEnvelope(denied, 'forbidden', 'Permission denied.');
    }
    expect(consumed).toBe(0);
    expect(script.calls).toHaveLength(0);
    setRole(harness, 'owner');
    const granted = await post(
      app,
      session,
      { advisoryRevisionId: REVISION, organizationId: randomUUID() },
      '198.51.100.20',
    );
    expect(granted.statusCode).toBe(400);
    const header = await post(app, session, { advisoryRevisionId: REVISION }, '198.51.100.21', {
      'x-organization-id': randomUUID(),
      'x-instance-operator': 'grant',
    });
    expect(header.statusCode).toBe(400);
    expect(consumed).toBe(0);
    const created = await post(app, session, { advisoryRevisionId: REVISION }, '198.51.100.22', {
      'content-type': 'application/json; charset=utf-8',
      'x-request-id': REQUEST_ID,
      'x-correlation-id': CORRELATION_ID,
    });
    expect(created.statusCode).toBe(201);
    expect(created.headers['cache-control']).toBe('private, no-store');
    expect(created.json()).toEqual({
      schemaVersion: 'deliberate_product_match_evaluation_response_v1',
      status: 'evaluated',
      assetId: ASSET,
      advisoryRevisionId: REVISION,
      ingestionId: INGESTION,
      selectedCount: 3,
      evaluatedCount: 2,
      insertedCount: 2,
      replayedCount: 0,
      skippedCount: 1,
      skippedByReason: { version_not_known: 1, version_unrepresentable: 0 },
      outcomeCounts: { affected: 1, unaffected: 1, unknown: 0 },
      findingCreation: 'unavailable',
    });
    expect(JSON.stringify(created.json())).not.toContain(SECRET);
    expect(JSON.stringify(created.json())).not.toContain('findingWrites');
    expect(created.json()).not.toHaveProperty('organizationId');
    const home = harness.organizations[0]?.id;
    expect(home).toEqual(expect.any(String));
    expect(JSON.stringify(created.json())).not.toContain(home);
    expect(script.calls).toEqual([
      expect.objectContaining({
        assetId: ASSET,
        advisoryRevisionId: REVISION,
        requestId: REQUEST_ID,
        correlationId: CORRELATION_ID,
        actor: expect.objectContaining({
          organizationId: home,
          userId: harness.user.id,
          role: 'owner',
        }),
      }),
    ]);
    expect(seen).toEqual([home]);
    expect(findings.calls).toBe(0);
    const logs = harness.logs();
    expect(logs).toContain(home);
    expect(logs).toContain(harness.user.id);
    expect(logs).toContain('evaluated');
    expect(logs).not.toContain(ASSET);
    expect(logs).not.toContain(REVISION);
    expect(logs).not.toContain(SECRET);
    await app.close();
  });

  it('returns replay and empty selections without evidence identifiers', async () => {
    const script = scriptedEvaluation();
    const { app, session } = await boot('owner', { productMatchEvaluation: script.runtime });
    script.set(
      evaluatedBody({
        status: 'already_applied',
        selectedCount: 2,
        evaluatedCount: 2,
        insertedCount: 0,
        replayedCount: 2,
        skippedCount: 0,
        skippedByReason: { version_not_known: 0, version_unrepresentable: 0 },
        outcomeCounts: { affected: 1, unaffected: 1, unknown: 0 },
      }),
    );
    const replayed = await post(app, session, { advisoryRevisionId: REVISION }, '198.51.100.30');
    script.set(
      evaluatedBody({
        status: 'no_relevant_occurrence',
        selectedCount: 0,
        evaluatedCount: 0,
        insertedCount: 0,
        replayedCount: 0,
        skippedCount: 0,
        skippedByReason: { version_not_known: 0, version_unrepresentable: 0 },
        outcomeCounts: { affected: 0, unaffected: 0, unknown: 0 },
      }),
    );
    const none = await post(app, session, { advisoryRevisionId: REVISION }, '198.51.100.31');
    script.set(
      evaluatedBody({
        status: 'no_evaluable_occurrence',
        selectedCount: 1,
        evaluatedCount: 0,
        insertedCount: 0,
        replayedCount: 0,
        skippedCount: 1,
        skippedByReason: { version_not_known: 0, version_unrepresentable: 1 },
        outcomeCounts: { affected: 0, unaffected: 0, unknown: 0 },
      }),
    );
    const skipped = await post(app, session, { advisoryRevisionId: REVISION }, '198.51.100.32');
    expect(replayed.statusCode).toBe(200);
    expect(replayed.json()).toMatchObject({
      status: 'already_applied',
      findingCreation: 'unavailable',
    });
    expect(none.statusCode).toBe(200);
    expect(none.json()).toMatchObject({ status: 'no_relevant_occurrence', selectedCount: 0 });
    expect(skipped.statusCode).toBe(200);
    expect(skipped.json()).toMatchObject({
      status: 'no_evaluable_occurrence',
      skippedByReason: { version_unrepresentable: 1 },
    });
    for (const response of [replayed, none, skipped]) {
      expect(response.headers['cache-control']).toBe('private, no-store');
      expect(JSON.stringify(response.json())).not.toContain(SECRET);
    }
    await app.close();
  });

  it('maps the closed failure taxonomy to one public body per class', async () => {
    const script = scriptedEvaluation({ status: 'not_found' });
    const { app, session, harness } = await boot('owner', {
      productMatchEvaluation: script.runtime,
      productMatchEvaluationOrganizationLimiter: { consume: () => 'allowed' },
    });
    const seen = new Map<string, { code: string; message: string }>();
    for (const [index, status] of DELIBERATE_PRODUCT_MATCH_EVALUATION_FAILURE_STATUSES.entries()) {
      script.set({ status });
      const response = await post(
        app,
        session,
        { advisoryRevisionId: REVISION },
        `203.0.113.${index + 1}`,
      );
      const expected = PUBLIC_FAILURES[status];
      expect(response.statusCode, status).toBe(expected.statusCode);
      expectEnvelope(response, expected.code, expected.message);
      expect(response.headers['cache-control']).toBe('private, no-store');
      const serialized = JSON.stringify(response.json());
      expect(serialized).not.toContain(ASSET);
      expect(serialized).not.toContain(REVISION);
      for (const token of HIDDEN_TOKENS) {
        if (token === status) {
          expect(serialized, status).not.toContain(token);
        }
      }
      seen.set(status, {
        code: response.json().error.code,
        message: response.json().error.message,
      });
    }
    expect(seen.get('no_successful_ingestion')).toEqual(seen.get('ingestion_not_evaluable'));
    expect(seen.get('authority_required')).toEqual(seen.get('authority_rejected'));
    expect(seen.get('timeout')).toEqual(seen.get('database_unavailable'));
    expect(seen.get('malformed_persisted_state')).toEqual(seen.get('internal_failure'));
    expect(seen.get('advisory_not_eligible')).not.toEqual(seen.get('capacity_exceeded'));
    expect(seen.get('advisory_not_eligible')).not.toEqual(seen.get('no_successful_ingestion'));
    expect(harness.logs()).toContain('advisory_not_eligible');
    expect(harness.logs()).not.toContain(REVISION);
    script.set({ status: 'withdrawn' });
    const unknown = await post(app, session, { advisoryRevisionId: REVISION }, '203.0.113.40');
    expect(unknown.statusCode).toBe(500);
    expectEnvelope(unknown, 'internal', 'An internal error occurred.');
    expect(JSON.stringify(unknown.json())).not.toContain('withdrawn');
    await app.close();
  });

  it('hides an inconsistent or foreign success body', async () => {
    const script = scriptedEvaluation(evaluatedBody({ insertedCount: 0, replayedCount: 2 }));
    const { app, session } = await boot('owner', { productMatchEvaluation: script.runtime });
    const inconsistent = await post(
      app,
      session,
      { advisoryRevisionId: REVISION },
      '198.51.100.40',
    );
    script.set(evaluatedBody({ assetId: FOREIGN_ASSET }));
    const foreign = await post(app, session, { advisoryRevisionId: REVISION }, '198.51.100.41');
    script.set(evaluatedBody({ findingCreation: 'available' }));
    const promoted = await post(app, session, { advisoryRevisionId: REVISION }, '198.51.100.42');
    for (const response of [inconsistent, foreign, promoted]) {
      expect(response.statusCode).toBe(500);
      expectEnvelope(response, 'internal', 'An internal error occurred.');
      expect(JSON.stringify(response.json())).not.toContain(FOREIGN_ASSET);
      expect(JSON.stringify(response.json())).not.toContain('available');
    }
    await app.close();
  });

  it('limits the direct peer before authentication and ignores X-Forwarded-For', async () => {
    const { app } = await boot('owner');
    const peer = '198.51.100.50';
    for (let index = 0; index < 5; index += 1) {
      const response = await app.inject({
        method: 'POST',
        url: evaluationUrl(ASSET),
        remoteAddress: peer,
        headers: {
          origin: TEST_ORIGIN,
          'content-type': 'application/json',
          'x-forwarded-for': '203.0.113.99',
        },
        payload: { advisoryRevisionId: REVISION },
      });
      expect(response.statusCode).toBe(401);
    }
    const limited = await app.inject({
      method: 'POST',
      url: evaluationUrl(ASSET),
      remoteAddress: peer,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        'x-forwarded-for': '203.0.113.99',
      },
      payload: { advisoryRevisionId: REVISION },
    });
    const otherPeer = await app.inject({
      method: 'POST',
      url: evaluationUrl(ASSET),
      remoteAddress: '198.51.100.51',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        'x-forwarded-for': peer,
      },
      payload: { advisoryRevisionId: REVISION },
    });
    expect(limited.statusCode).toBe(429);
    expectEnvelope(limited, 'rate_limited', 'Too many requests. Try again later.');
    expect(limited.headers['cache-control']).toBe('private, no-store');
    expect(otherPeer.statusCode).toBe(401);
    await app.close();
  });

  it('limits an organization after permission and stops calling the runtime', async () => {
    const script = scriptedEvaluation();
    const { app, session } = await boot('owner', { productMatchEvaluation: script.runtime });
    for (let index = 0; index < 5; index += 1) {
      const response = await post(
        app,
        session,
        { advisoryRevisionId: REVISION },
        `198.51.100.${60 + index}`,
      );
      expect(response.statusCode).toBe(201);
    }
    const limited = await post(app, session, { advisoryRevisionId: REVISION }, '198.51.100.70');
    expect(limited.statusCode).toBe(429);
    expectEnvelope(limited, 'rate_limited', 'Too many requests. Try again later.');
    expect(script.calls).toHaveLength(5);
    await app.close();
  });

  it('fails closed when the organization limiter throws', async () => {
    const script = scriptedEvaluation();
    const { app, session } = await boot('owner', {
      productMatchEvaluation: script.runtime,
      productMatchEvaluationOrganizationLimiter: {
        consume() {
          throw new Error('limiter redis secret reviewed-npm-widget');
        },
      },
    });
    const response = await post(app, session, { advisoryRevisionId: REVISION }, '198.51.100.80');
    expect(response.statusCode).toBe(503);
    expectEnvelope(
      response,
      'internal',
      'Product Match Evidence evaluation is temporarily unavailable.',
    );
    expect(response.headers['cache-control']).toBe('private, no-store');
    expect(JSON.stringify(response.json())).not.toContain('redis');
    expect(JSON.stringify(response.json())).not.toContain('reviewed-npm-widget');
    expect(script.calls).toHaveLength(0);
    await app.close();
  });

  it('does not publish a thrown runtime error', async () => {
    const runtime: ProductMatchEvaluationRuntime = {
      async execute() {
        throw new Error('SELECT package reviewed-npm-widget');
      },
    };
    const { app, session, harness } = await boot('owner', { productMatchEvaluation: runtime });
    const response = await post(app, session, { advisoryRevisionId: REVISION }, '198.51.100.90');
    expect(response.statusCode).toBe(500);
    expectEnvelope(response, 'internal', 'An internal error occurred.');
    expect(JSON.stringify(response.json())).not.toContain('SELECT');
    expect(JSON.stringify(response.json())).not.toContain('reviewed-npm-widget');
    expect(harness.logs()).not.toContain('SELECT');
    expect(harness.logs()).not.toContain('reviewed-npm-widget');
    await app.close();
  });
});

let addressOctet = 100;

function randomAddress(): string {
  addressOctet += 1;
  return `198.51.100.${addressOctet}`;
}

async function boot(
  role: RoleName,
  options?: {
    membershipCount?: 1 | 2;
    productMatchEvaluation?: ProductMatchEvaluationRuntime;
    productMatchEvaluationOrganizationLimiter?: FindingOrganizationRateLimiter;
    findings?: FindingOperatorRuntime;
  },
) {
  const harness = createAuthTestHarness({
    membershipCount: options?.membershipCount ?? 1,
    primaryRole: role,
  });
  const built = await buildTestApi({
    harness,
    ...(options?.productMatchEvaluation === undefined
      ? {}
      : { productMatchEvaluation: options.productMatchEvaluation }),
    ...(options?.productMatchEvaluationOrganizationLimiter === undefined
      ? {}
      : {
          productMatchEvaluationOrganizationLimiter:
            options.productMatchEvaluationOrganizationLimiter,
        }),
    ...(options?.findings === undefined ? {} : { findings: options.findings }),
  });
  const loggedIn = await built.app.inject({
    method: 'POST',
    url: '/auth/login',
    remoteAddress: LOGIN_IP,
    headers: { origin: TEST_ORIGIN, 'content-type': 'application/json' },
    payload: { email: harness.user.email, password: VALID_PASSWORD },
  });
  expect(loggedIn.statusCode).toBe(200);
  return {
    app: built.app,
    harness,
    session: sessionFrom(loggedIn, harness.config.auth.cookieName),
  };
}

function setRole(harness: AuthTestHarness, role: RoleName): void {
  const row = harness.memberships.rows[0];
  if (row === undefined) {
    throw new Error('expected a membership');
  }
  row.membership.role = role;
}

function evaluationUrl(assetId: string): string {
  return PRODUCT_MATCH_EVALUATION_ROUTE.replace(':assetId', assetId);
}

async function post(
  app: FastifyInstance,
  session: { cookie: string; csrf: string } | null,
  payload: Record<string, unknown>,
  remoteAddress: string,
  headers?: Record<string, string | string[]>,
) {
  return app.inject({
    method: 'POST',
    url: evaluationUrl(ASSET),
    remoteAddress,
    headers: {
      ...(session === null
        ? { origin: TEST_ORIGIN, 'content-type': 'application/json' }
        : mutationHeaders(session)),
      ...headers,
    },
    payload,
  });
}

function repeatedHeader(
  headers: Record<string, string | string[]>,
): NonNullable<InjectOptions['headers']> {
  return headers as NonNullable<InjectOptions['headers']>;
}

function mutationHeaders(session: { cookie: string; csrf: string }): Record<string, string> {
  return {
    origin: TEST_ORIGIN,
    'content-type': 'application/json',
    cookie: session.cookie,
    'x-csrf-token': session.csrf,
  };
}

function sessionFrom(
  response: { headers: { [key: string]: unknown }; json: () => unknown },
  cookieName: string,
): { cookie: string; csrf: string } {
  const header = response.headers['set-cookie'];
  const setCookie =
    typeof header === 'string' ? header : Array.isArray(header) ? header[0] : undefined;
  if (typeof setCookie !== 'string') {
    throw new Error('expected Set-Cookie');
  }
  const part = setCookie.split(';', 1)[0];
  const prefix = `${cookieName}=`;
  if (part === undefined || !part.startsWith(prefix)) {
    throw new Error('cookie name mismatch');
  }
  return {
    cookie: `${cookieName}=${part.slice(prefix.length)}`,
    csrf: (response.json() as SessionResponse).csrfToken,
  };
}

function expectEnvelope(
  response: { json: () => { error?: { code?: string; message?: string; requestId?: string } } },
  code: string,
  message: string,
): void {
  const body = response.json();
  expect(body.error?.code).toBe(code);
  expect(body.error?.message).toBe(message);
  expect(typeof body.error?.requestId).toBe('string');
}
