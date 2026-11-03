import { describe, expect, it } from 'vitest';

import {
  bindProductMatchEvaluationRuntime,
  type ProductMatchEvaluationExecuteInput,
} from './product-match-evaluation-runtime.js';

const ORG = '11111111-1111-4111-8111-111111111111';
const USER = '22222222-2222-4222-8222-222222222222';
const MEMBERSHIP = '33333333-3333-4333-8333-333333333333';
const ASSET = '44444444-4444-4444-8444-444444444444';
const REVISION = '55555555-5555-4555-8555-555555555555';

describe('product match evaluation runtime binding', () => {
  it('seals the actor, path asset, and HTTP transport without an operation id', async () => {
    const seen: unknown[] = [];
    const runtime = bindProductMatchEvaluationRuntime(async (input) => {
      seen.push(input);
      return { status: 'not_found' };
    });
    const input: ProductMatchEvaluationExecuteInput = {
      actor: {
        userId: USER,
        sessionId: 'session-1',
        organizationId: ORG,
        membershipId: MEMBERSHIP,
        role: 'admin',
      },
      assetId: ASSET,
      advisoryRevisionId: REVISION,
      requestId: 'req-1',
      correlationId: 'corr-http-1',
    };
    await expect(runtime.execute(input)).resolves.toEqual({ status: 'not_found' });
    expect(seen).toEqual([
      {
        actor: {
          userId: USER,
          sessionId: 'session-1',
          organizationId: ORG,
          membershipId: MEMBERSHIP,
          role: 'admin',
        },
        request: {
          assetId: ASSET,
          advisoryRevisionId: REVISION,
        },
        transport: {
          requestId: 'req-1',
          correlationId: 'corr-http-1',
        },
      },
    ]);
    const envelope = seen[0];
    expect(Object.keys(envelope as object).sort()).toEqual(['actor', 'request', 'transport']);
  });
});
