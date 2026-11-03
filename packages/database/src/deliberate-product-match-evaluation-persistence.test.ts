/**
 * Source boundary for the uncomposed deliberate evaluation adapter.
 * Production startup does not construct it. This slice adds no migration.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const directory = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(directory, '..');

describe('deliberate product match evaluation persistence boundary', () => {
  it('stays off the database barrel and adds no migration', () => {
    const barrel = readFileSync(join(directory, 'index.ts'), 'utf8');
    expect(barrel).not.toContain('createDeliberateProductMatchEvaluationPersistence');
    expect(barrel).not.toContain('deliberate-product-match-evaluation');
    const manifest = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8')) as {
      readonly exports: Record<string, unknown>;
    };
    expect(manifest.exports['./deliberate-product-match-evaluation-persistence']).toEqual({
      types: './dist/deliberate-product-match-evaluation-persistence.d.ts',
      import: './dist/deliberate-product-match-evaluation-persistence.js',
    });
    const migrations = readdirSync(join(packageRoot, 'prisma/migrations')).filter((name) =>
      /^\d/.test(name),
    );
    expect(migrations).toHaveLength(27);
  });

  it('locks one asset and does not write Findings or call a provider', () => {
    const source = readFileSync(
      join(directory, 'deliberate-product-match-evaluation-persistence.ts'),
      'utf8',
    );
    expect(source).toContain('pg_advisory_xact_lock');
    expect(source).toContain('hashtextextended');
    expect(source).toContain('FOR UPDATE');
    expect(source).toContain('FOR SHARE');
    expect(source).toContain("set_config('statement_timeout', '5000', true)");
    expect(source).toContain("set_config('lock_timeout', '2000', true)");
    expect(source).toContain('DELIBERATE_PRODUCT_MATCH_EVALUATION_AUDIT_ACTION');
    expect(source).toContain('writeProductMatchEvaluationEvidence');
    expect(source).toContain('LIMIT 17');
    expect(source).not.toContain('INSERT INTO "finding"');
    expect(source).not.toContain('riskCalculation');
    expect(source).not.toContain('@patchpilot/policy-engine');
    expect(source).not.toContain('fetch(');
    expect(source).not.toContain('osv.dev');
    expect(source).not.toContain('storage.googleapis.com');
    expect(source).not.toContain('LOCK TABLE');
    expect(source).not.toContain('advisory_revision_explicit_version');
    expect(source).not.toContain('instance_advisory_authority_grant');
    const singleOccurrence = readFileSync(
      join(directory, 'product-match-evaluation-persistence.ts'),
      'utf8',
    );
    expect(singleOccurrence).toContain('AND "id" = ${input.command.componentOccurrenceId}::uuid');
    expect(singleOccurrence).toContain('export async function writeProductMatchEvaluationEvidence');
    expect(singleOccurrence).not.toContain('deliberate-product-match-evaluation');
  });
});
