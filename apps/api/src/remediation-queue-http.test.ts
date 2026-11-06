import { describe, expect, it } from 'vitest';

import {
  BUILTIN_PRIORITY_POLICY_KEY,
  BUILTIN_PRIORITY_POLICY_VERSION,
  PRIORITY_CALCULATION_ENGINE_VERSION,
  REMEDIATION_QUEUE_COMPARISON_MESSAGE,
  REMEDIATION_QUEUE_EXPORT_CAP,
  type RemediationQueueExportDocument,
} from '@patchpilot/domain';

import {
  REMEDIATION_QUEUE_EXPORT_CSV_HEADER,
  serializeRemediationQueueExport,
} from './remediation-queue-http.js';

const FINDING = 'abababab-abab-4bab-8bab-abababababab';
const ASSET = 'cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd';
const OTHER = 'efefefef-efef-4fef-8fef-efefefefefef';
const THIRD = '12121212-1212-4121-8121-121212121212';
const POLICY = '34343434-3434-4434-8434-343434343434';
const HASH = 'ab'.repeat(32);
const AT = '2026-11-04T18:00:00.000Z';

describe('remediation queue export serialization', () => {
  it('emits the JSON envelope and equivalent CSV columns from one snapshot', () => {
    const document = fixture();
    const jsonBytes = serializeRemediationQueueExport({ ...document, format: 'json' });
    const csvBytes = serializeRemediationQueueExport({ ...document, format: 'csv' });
    expect(jsonBytes[0]).not.toBe(0xef);
    expect(csvBytes[0]).not.toBe(0xef);
    const json = JSON.parse(Buffer.from(jsonBytes).toString('utf8')) as {
      schemaVersion: string;
      format: string;
      sections: {
        ranked: Record<string, unknown>[];
        incomparable: Record<string, unknown>[];
        not_calculated: Record<string, unknown>[];
      };
    };
    expect(Object.keys(json)).toEqual([
      'schemaVersion',
      'format',
      'asOf',
      'reference',
      'counts',
      'rowCount',
      'cap',
      'sections',
    ]);
    expect(json.schemaVersion).toBe('remediation_queue_export_v1');
    expect(json.format).toBe('json');
    expect(json.sections.not_calculated[0]).not.toHaveProperty('priorityBand');
    expect(json.sections.ranked[0]?.['priorityBand']).toBe('P2');
    expect(json.sections.ranked[0]?.['humanReview']).toMatchObject({
      status: 'corrected',
      correctedBand: 'P4',
    });
    expect(json.sections.incomparable[0]?.['comparisonMessage']).toBe(
      REMEDIATION_QUEUE_COMPARISON_MESSAGE,
    );
    expect(json.sections.ranked.map((row) => row['findingId'])).toEqual([FINDING]);
    expect(json.sections.incomparable.map((row) => row['findingId'])).toEqual([OTHER]);
    const csv = Buffer.from(csvBytes).toString('utf8');
    expect(csv.startsWith(`${REMEDIATION_QUEUE_EXPORT_CSV_HEADER}\n`)).toBe(true);
    expect(csv.endsWith('\n')).toBe(true);
    expect(csv.includes('\r\n')).toBe(false);
    const rows = parseCsv(csv);
    expect(rows[0]).toEqual(REMEDIATION_QUEUE_EXPORT_CSV_HEADER.split(','));
    expect(rows).toHaveLength(4);
    expect(rows[1]?.[0]).toBe('ranked');
    expect(rows[2]?.[0]).toBe('incomparable');
    expect(rows[3]?.[0]).toBe('not_calculated');
    expect(rows[3]?.[12]).toBe('');
    expect(rows[3]?.[13]).toBe('');
    expect(rows[1]?.[13]).toBe('68');
    expect(rows[1]?.[7]).toBe('corrected');
    expect(rows[1]?.[10]).toBe('P4');
    expect(rows[1]?.[21]).toBe('');
    expect(rows[2]?.[21]).toBe(REMEDIATION_QUEUE_COMPARISON_MESSAGE);
    expect(rows[1]?.[20]).toBe('policy_superseded,kev_generation_changed');
    expect(rows[1]?.[3]).toBe("'=queue");
    expect(rows[2]?.[3]).toBe("'+queue");
    expect(rows[2]?.[4]).toBe("'-widget");
    expect(rows[3]?.[3]).toBe("'@queue");
    expect(rows[3]?.[4]).toBe("'\twidget");
    expect(rows[3]?.[5]).toBe("'\r1.0.0");
    expect(rows[1]?.[5]).toBe('say "1.1.0", next');
    expect(rows[2]?.[6]).toBe('OSV\n2');
    expect(rows[1]?.[6]).toBe('队列-1');
  });
});

function fixture(): RemediationQueueExportDocument {
  return {
    format: 'json',
    asOf: AT,
    reference: {
      policyKey: BUILTIN_PRIORITY_POLICY_KEY,
      policyVersion: BUILTIN_PRIORITY_POLICY_VERSION,
      policyDefinitionSha256: HASH,
      engineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
    },
    counts: { ranked: 1, incomparable: 1, not_calculated: 1 },
    rowCount: 3,
    cap: REMEDIATION_QUEUE_EXPORT_CAP,
    sections: {
      ranked: [
        {
          findingId: FINDING,
          assetId: ASSET,
          assetName: '=queue',
          componentName: 'reviewed-npm-widget',
          componentVersion: 'say "1.1.0", next',
          vulnerabilityPublicId: '队列-1',
          priorityBand: 'P2',
          priority: 68,
          policy: {
            riskPolicyId: POLICY,
            policyKey: BUILTIN_PRIORITY_POLICY_KEY,
            policyVersion: BUILTIN_PRIORITY_POLICY_VERSION,
            policyDefinitionSha256: HASH,
          },
          calculatedAt: AT,
          inputsChanged: {
            status: 'detected',
            signals: ['policy_superseded', 'kev_generation_changed'],
          },
          humanReview: {
            status: 'corrected',
            priorReviewExists: true,
            reviewId: FINDING,
            correctedBand: 'P4',
            expiresAt: AT,
          },
        },
      ],
      incomparable: [
        {
          findingId: OTHER,
          assetId: ASSET,
          assetName: '+queue',
          componentName: '-widget',
          componentVersion: '1.0.0',
          vulnerabilityPublicId: 'OSV\n2',
          priorityBand: 'P3',
          priority: 40,
          policy: {
            riskPolicyId: POLICY,
            policyKey: 'historical.policy',
            policyVersion: 1,
            policyDefinitionSha256: HASH,
          },
          calculatedAt: AT,
          inputsChanged: { status: 'none_detected', signals: [] },
          humanReview: { status: 'none', priorReviewExists: false },
          comparisonMessage: REMEDIATION_QUEUE_COMPARISON_MESSAGE,
        },
      ],
      not_calculated: [
        {
          findingId: THIRD,
          assetId: ASSET,
          assetName: '@queue',
          componentName: '\twidget',
          componentVersion: '\r1.0.0',
          vulnerabilityPublicId: 'OSV-3',
          humanReview: { status: 'none', priorReviewExists: false },
        },
      ],
    },
  };
}

function parseCsv(value: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let quoted = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (quoted) {
      if (character === '"') {
        if (value[index + 1] === '"') {
          cell += '"';
          index += 1;
        } else {
          quoted = false;
        }
      } else {
        cell += character ?? '';
      }
      continue;
    }
    if (character === '"') {
      quoted = true;
    } else if (character === ',') {
      row.push(cell);
      cell = '';
    } else if (character === '\n') {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = '';
    } else {
      cell += character ?? '';
    }
  }
  return rows;
}
