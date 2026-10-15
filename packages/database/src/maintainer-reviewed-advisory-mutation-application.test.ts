import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const here = path.dirname(fileURLToPath(import.meta.url));

describe('maintainer-reviewed advisory mutation application', () => {
  it('delegates to the committed parsers and adapters and does not mint a capability', () => {
    const source = readFileSync(
      path.join(here, 'maintainer-reviewed-advisory-mutation-application.ts'),
      'utf8',
    );
    expect(source).toContain('parseMaintainerReviewedAdvisorySubmissionCommand');
    expect(source).toContain('parseMaintainerReviewedAdvisoryApprovalApplicationCommand');
    expect(source).toContain('createMaintainerReviewedAdvisorySubmissionPersistence');
    expect(source).toContain('createMaintainerReviewedAdvisoryApprovalApplicationPersistence');
    expect(source).not.toContain('sealMaintainerReviewedAdvisoryApprovalCapability');
    expect(source).not.toContain('capability.js');
    expect(source).not.toContain('createReviewerCapabilityIssuer');
    expect(source).not.toContain('INSERT INTO');
    expect(source).not.toContain('$transaction');
    expect(source).not.toContain('product_match_evaluation_evidence');
    expect(source).not.toContain('finding_observation');
    const barrel = readFileSync(path.join(here, 'index.ts'), 'utf8');
    expect(barrel).not.toContain('createMaintainerReviewedAdvisoryMutationApplication');
    expect(barrel).not.toContain('maintainer-reviewed-advisory-mutation-application');
  });
});
