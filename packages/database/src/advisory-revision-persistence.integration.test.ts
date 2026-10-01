/**
 * Disposable PostgreSQL proof for immutable advisory revisions and
 * reviewed Vulnerability bindings. Synthetic identifiers only.
 */

import { PrismaClient } from '@prisma/client';
import {
  ADVISORY_REVISION_INSPECTION_SCHEMA_VERSION,
  ADVISORY_REVISION_PERSISTENCE_COMMAND_SCHEMA_VERSION,
  ADVISORY_REVISION_ZERO_COUNTS,
  ADVISORY_VULNERABILITY_BINDING_COMMAND_SCHEMA_VERSION,
  ADVISORY_VULNERABILITY_BINDING_INSPECTION_SCHEMA_VERSION,
  EXACT_MAPPING_METHOD,
  FIRST_ECOSYSTEM_EVALUATOR_VERSION,
  FIRST_ECOSYSTEM_MATCHING_POLICY_ID,
  SELECTED_FIRST_ECOSYSTEM,
  SUPERSESSION_NONE,
  SYNTHETIC_PROVIDER_GENERATION,
  SYNTHETIC_RETRIEVAL_TOKEN,
  VULNERABILITY_MAPPING_POLICY_ID,
  classifyNpmPackageIdentityFromParts,
  parseAdvisoryRevisionCommand,
  productAffectedRangeFingerprint,
  productContentFingerprint,
  session14RangeFingerprint,
  type PersistAdvisoryRevisionResult,
} from '@patchpilot/vulnerability-intelligence';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createAdvisoryRevisionPersistence } from './advisory-revision-persistence.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const RETRIEVAL_ID = '33333333-3333-4333-8333-333333333333';
const COMMAND_RANGES = [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.3' }] }];
const CANONICAL_RANGES = [
  {
    type: 'SEMVER' as const,
    events: [
      { name: 'introduced' as const, value: '0' },
      { name: 'fixed' as const, value: '1.2.3' },
    ],
  },
];

type RevisionSpec = {
  readonly source?: string;
  readonly advisoryId?: string;
  readonly origin?: string;
  readonly trustClassification?: string;
  readonly withdrawalClassification?: string;
  readonly quarantineClassification?: string;
  readonly supersedesRevisionDigest?: string;
  readonly providerGeneration?: string;
  readonly retrievalClassification?: string;
  readonly retrievalEvidenceId?: string;
  readonly spdxLicenseId?: string | null;
  readonly aliases?: readonly string[];
  readonly name?: string;
};

function revisionCommand(spec: RevisionSpec = {}): Record<string, unknown> {
  const source = spec.source ?? 'synthetic_fixture';
  const advisoryId = spec.advisoryId ?? 'SYNTHETICADV1';
  const origin = spec.origin ?? 'synthetic_fixture';
  const withdrawalClassification = spec.withdrawalClassification ?? 'not_withdrawn';
  const spdxLicenseId = spec.spdxLicenseId === undefined ? null : spec.spdxLicenseId;
  const aliases = spec.aliases ?? [];
  const name = spec.name ?? 'left-pad';
  const identity = classifyNpmPackageIdentityFromParts({
    ecosystem: SELECTED_FIRST_ECOSYSTEM,
    observedNamespace: null,
    observedName: name,
    observedIdentity: name,
  });
  if (identity.classification !== 'valid') {
    throw new Error('synthetic package identity was rejected');
  }
  const session14 = session14RangeFingerprint(CANONICAL_RANGES, []);
  const content = productContentFingerprint({
    source,
    advisoryId,
    schemaVersion: 'v1.9.0',
    schemaCommit: 'f3f826310aeca8e324baabd195632f2229952abe',
    withdrawalClassification,
    spdxLicenseId,
    aliases,
    session14RangeFingerprint: session14,
    ecosystem: SELECTED_FIRST_ECOSYSTEM,
    packageIdentityKey: identity.identityKey,
  });
  const product = productAffectedRangeFingerprint({
    ecosystem: SELECTED_FIRST_ECOSYSTEM,
    packageIdentityKey: identity.identityKey,
    session14RangeFingerprint: session14,
    parserId: 'osv_advisory_parser_protocol_v1',
    parserResourcePolicy: 'osv_advisory_parser_resource_policy_v1',
    matchingPolicyId: FIRST_ECOSYSTEM_MATCHING_POLICY_ID,
    evaluatorVersion: FIRST_ECOSYSTEM_EVALUATOR_VERSION,
    schemaVersion: 'v1.9.0',
  });
  return {
    commandSchemaVersion: ADVISORY_REVISION_PERSISTENCE_COMMAND_SCHEMA_VERSION,
    source,
    advisoryId,
    providerGeneration: spec.providerGeneration ?? SYNTHETIC_PROVIDER_GENERATION,
    origin,
    trustClassification: spec.trustClassification ?? 'not_applicable_synthetic',
    withdrawalClassification,
    quarantineClassification: spec.quarantineClassification ?? 'not_quarantined',
    supersedesRevisionDigest: spec.supersedesRevisionDigest ?? SUPERSESSION_NONE,
    retrievalClassification: spec.retrievalClassification ?? 'synthetic_not_retrieved',
    retrievalEvidenceId: spec.retrievalEvidenceId ?? SYNTHETIC_RETRIEVAL_TOKEN,
    spdxLicenseId,
    ecosystem: SELECTED_FIRST_ECOSYSTEM,
    namespace: null,
    name,
    observedIdentity: name,
    affectedRanges: COMMAND_RANGES,
    explicitAffectedVersions: [],
    aliases,
    evaluatorVersion: FIRST_ECOSYSTEM_EVALUATOR_VERSION,
    matchingPolicyId: FIRST_ECOSYSTEM_MATCHING_POLICY_ID,
    contentFingerprint: content,
    session14RangeFingerprint: session14,
    productRangeFingerprint: product,
  };
}

function providerCommand(spec: RevisionSpec = {}): Record<string, unknown> {
  return revisionCommand({
    source: 'github_advisory_database',
    advisoryId: 'GHSA-SYNTH-0001-0001',
    origin: 'provider_derived',
    trustClassification: 'reviewed',
    providerGeneration: '17',
    retrievalClassification: 'recorded_reference',
    retrievalEvidenceId: RETRIEVAL_ID,
    spdxLicenseId: 'CC-BY-4.0',
    aliases: ['CVE-2099-1001'],
    ...spec,
  });
}

function bindingCommand(revisionDigest: string, advisoryId: string, vulnerabilityId: string) {
  return {
    commandSchemaVersion: ADVISORY_VULNERABILITY_BINDING_COMMAND_SCHEMA_VERSION,
    revisionDigest,
    advisoryId,
    vulnerabilityId,
    mappingPolicyId: VULNERABILITY_MAPPING_POLICY_ID,
    mappingMethod: EXACT_MAPPING_METHOD,
  };
}

function postgresState(error: unknown): string {
  if (typeof error !== 'object' || error === null || !('meta' in error)) {
    return '';
  }
  const meta = error.meta;
  if (typeof meta !== 'object' || meta === null || !('code' in meta)) {
    return '';
  }
  const code = meta.code;
  return typeof code === 'string' || typeof code === 'number' ? String(code) : '';
}

async function expectSqlState(action: () => Promise<unknown>, state: string): Promise<void> {
  try {
    await action();
    expect.unreachable();
  } catch (error) {
    const message = error instanceof Error ? error.message : '';
    expect(message.includes(state) || postgresState(error) === state).toBe(true);
  }
}

describe('advisory revision PostgreSQL persistence', () => {
  let databaseUrl = '';
  let databaseName = '';
  let admin: Awaited<ReturnType<typeof createEphemeralDatabase>>['admin'];
  let prisma: PrismaClient;
  let port: ReturnType<typeof createAdvisoryRevisionPersistence>;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseUrl = ephemeral.databaseUrl;
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(databaseUrl);
    prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    port = createAdvisoryRevisionPersistence(prisma);
  });

  afterAll(async () => {
    await prisma?.$disconnect();
    if (databaseName !== '') {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  it('starts with no advisory evidence, no active catalog, and no Findings', async () => {
    expect(await prisma.advisoryFamily.count()).toBe(0);
    expect(await prisma.advisoryRevision.count()).toBe(0);
    expect(await prisma.advisoryRevisionAlias.count()).toBe(0);
    expect(await prisma.advisoryVulnerabilityBinding.count()).toBe(0);
    expect(await prisma.finding.count()).toBe(0);
    const pointer = await prisma.$queryRaw<Array<{ count: bigint }>>`
      SELECT COUNT(*)::bigint AS count FROM "osv_active_catalog_pointer"
    `;
    expect(Number(pointer[0]?.count)).toBe(0);
  });

  it('persists a family and revision, replays exactly, and rejects a trust change', async () => {
    const command = providerCommand({
      advisoryId: 'GHSA-SYNTH-0001-0010',
      aliases: ['CVE-2099-1010'],
    });
    const recorded = await port.persistImmutableAdvisoryRevision(command);
    expect(recorded.kind).toBe('recorded');
    if (recorded.kind !== 'recorded') {
      return;
    }
    expect(recorded.counts.inserts).toBe(3);
    expect(recorded.counts).toMatchObject({
      updates: 0,
      deletes: 0,
      timestampChanges: 0,
      stateChanges: 0,
      parserCalls: 0,
      providerCalls: 0,
    });
    expect(recorded.projection.productEligibilityStored).toBe(false);
    expect(recorded.projection.catalogActivationStored).toBe(false);
    expect(recorded.projection.findingCreation).toBe('unavailable');
    expect(recorded.projection.mappingCountClassification).toBe('none');
    expect(JSON.stringify(recorded.projection)).not.toContain(RETRIEVAL_ID);

    const replay = await port.persistImmutableAdvisoryRevision(command);
    expect(replay.kind).toBe('already_applied');
    if (replay.kind === 'already_applied') {
      expect(replay.counts).toEqual(ADVISORY_REVISION_ZERO_COUNTS);
      expect(replay.projection.createdAt).toBe(recorded.projection.createdAt);
      expect(replay.projection.revisionId).toBe(recorded.projection.revisionId);
    }
    expect(
      await prisma.advisoryRevision.count({ where: { advisoryId: 'GHSA-SYNTH-0001-0010' } }),
    ).toBe(1);

    const conflict = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-0010',
        aliases: ['CVE-2099-1010'],
        trustClassification: 'unreviewed',
      }),
    );
    expect(conflict.kind).toBe('immutable_conflict');
    if (conflict.kind === 'immutable_conflict') {
      expect(conflict.counts).toEqual(ADVISORY_REVISION_ZERO_COUNTS);
    }
    const stored = await prisma.advisoryRevision.findUniqueOrThrow({
      where: { id: recorded.projection.revisionId },
      select: { trustClassification: true },
    });
    expect(stored.trustClassification).toBe('reviewed');
  });

  it('stores a second revision, an explicit withdrawal, and supersession without rewriting the prior row', async () => {
    const first = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-0020',
        aliases: [],
        trustClassification: 'unreviewed',
        providerGeneration: '4',
      }),
    );
    expect(first.kind).toBe('recorded');
    if (first.kind !== 'recorded') {
      return;
    }
    const second = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-0020',
        aliases: [],
        trustClassification: 'unreviewed',
        providerGeneration: '5',
      }),
    );
    expect(second.kind).toBe('recorded');
    const withdrawn = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-0021',
        aliases: [],
        trustClassification: 'unreviewed',
        withdrawalClassification: 'withdrawn',
        providerGeneration: '6',
      }),
    );
    expect(withdrawn.kind).toBe('recorded');
    if (withdrawn.kind === 'recorded') {
      expect(withdrawn.projection.revisionDisposition).toBe('withdrawn');
      expect(withdrawn.projection.withdrawalClassification).toBe('withdrawn');
    }
    const successor = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-0020',
        aliases: ['CVE-2099-1020'],
        trustClassification: 'unreviewed',
        providerGeneration: '7',
        supersedesRevisionDigest: first.projection.revisionDigest,
      }),
    );
    expect(successor.kind).toBe('recorded');
    if (successor.kind === 'recorded') {
      expect(successor.projection.revisionDisposition).toBe('superseding');
      expect(successor.projection.supersedesRevisionDigest).toBe(first.projection.revisionDigest);
    }
    const prior = await prisma.advisoryRevision.findUniqueOrThrow({
      where: { id: first.projection.revisionId },
      select: { revisionDisposition: true, withdrawalClassification: true },
    });
    expect(prior.revisionDisposition).toBe('recorded');
    expect(prior.withdrawalClassification).toBe('not_withdrawn');
    const missing = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-0022',
        aliases: [],
        trustClassification: 'unreviewed',
        supersedesRevisionDigest: 'ab'.repeat(32),
      }),
    );
    expect(missing.kind).toBe('rejected');
    if (missing.kind === 'rejected') {
      expect(missing.code).toBe('supersession_rejected');
    }
    expect(
      await prisma.advisoryFamily.count({ where: { advisoryId: 'GHSA-SYNTH-0001-0022' } }),
    ).toBe(0);
  });

  it('keeps the same advisory id under another source as another family', async () => {
    const github = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-0030',
        aliases: [],
        trustClassification: 'unreviewed',
      }),
    );
    const pypi = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        source: 'pypa_advisory_database',
        advisoryId: 'GHSA-SYNTH-0001-0030',
        aliases: [],
        trustClassification: 'unreviewed',
        providerGeneration: '8',
      }),
    );
    expect(github.kind).toBe('recorded');
    expect(pypi.kind).toBe('recorded');
    if (github.kind === 'recorded' && pypi.kind === 'recorded') {
      expect(github.projection.familyId).not.toBe(pypi.projection.familyId);
      expect(github.projection.familyDigest).not.toBe(pypi.projection.familyDigest);
    }
  });

  it('persists aliases and rejects a malformed alias before writing', async () => {
    const before = await prisma.advisoryRevisionAlias.count();
    const rejected = await port.persistImmutableAdvisoryRevision(
      revisionCommand({ aliases: ['not an alias'] }),
    );
    expect(rejected.kind).toBe('rejected');
    expect(await prisma.advisoryRevisionAlias.count()).toBe(before);
    const recorded = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-0040',
        aliases: ['GHSA-SYNTH-0001-0040', 'CVE-2099-1040'],
        trustClassification: 'reviewed',
      }),
    );
    expect(recorded.kind).toBe('recorded');
    if (recorded.kind === 'recorded') {
      expect(recorded.projection.aliasCount).toBe(2);
      expect(recorded.projection.cveAliasCount).toBe(1);
      const aliases = await prisma.advisoryRevisionAlias.findMany({
        where: { advisoryRevisionId: recorded.projection.revisionId },
        orderBy: { ordinal: 'asc' },
        select: { aliasType: true, aliasValue: true },
      });
      expect(aliases.map((alias) => alias.aliasValue)).toEqual([
        'CVE-2099-1040',
        'GHSA-SYNTH-0001-0040',
      ]);
      expect(aliases[0]?.aliasType).toBe('canonical_cve');
      expect(aliases[1]?.aliasType).toBe('provider_native');
    }
  });

  it('binds one reviewed Vulnerability and rejects a second, synthetic, withdrawn, and multi-CVE parent', async () => {
    const vulnerability = await prisma.vulnerability.create({
      data: { osvId: 'SYNTHETIC-VULN-1' },
      select: { id: true },
    });
    const other = await prisma.vulnerability.create({
      data: { osvId: 'SYNTHETIC-VULN-2' },
      select: { id: true },
    });
    const revision = await port.persistImmutableAdvisoryRevision(
      providerCommand({ advisoryId: 'GHSA-SYNTH-0001-0050', aliases: ['CVE-2099-1050'] }),
    );
    expect(revision.kind).toBe('recorded');
    if (revision.kind !== 'recorded') {
      return;
    }
    const bound = await port.persistReviewedAdvisoryVulnerabilityBinding(
      bindingCommand(revision.projection.revisionDigest, 'GHSA-SYNTH-0001-0050', vulnerability.id),
    );
    expect(bound.kind).toBe('recorded');
    if (bound.kind === 'recorded') {
      expect(bound.counts.inserts).toBe(1);
      expect(bound.projection.bindingClassification).toBe('one_cve_alias_evidence');
      expect(bound.projection.conflictClassification).toBe('none');
      expect(bound.projection.productEligibilityStored).toBe(false);
      expect(bound.projection.findingCreation).toBe('unavailable');
    }
    const replay = await port.persistReviewedAdvisoryVulnerabilityBinding(
      bindingCommand(revision.projection.revisionDigest, 'GHSA-SYNTH-0001-0050', vulnerability.id),
    );
    expect(replay.kind).toBe('already_applied');
    if (replay.kind === 'already_applied') {
      expect(replay.counts).toEqual(ADVISORY_REVISION_ZERO_COUNTS);
    }
    const conflict = await port.persistReviewedAdvisoryVulnerabilityBinding(
      bindingCommand(revision.projection.revisionDigest, 'GHSA-SYNTH-0001-0050', other.id),
    );
    expect(conflict.kind).toBe('immutable_conflict');
    const stored = await prisma.advisoryVulnerabilityBinding.findMany({
      where: { advisoryRevisionId: revision.projection.revisionId },
      select: { vulnerabilityId: true },
    });
    expect(stored).toEqual([{ vulnerabilityId: vulnerability.id }]);

    const nativeRevision = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-0051',
        aliases: [],
        trustClassification: 'reviewed',
      }),
    );
    expect(nativeRevision.kind).toBe('recorded');
    if (nativeRevision.kind === 'recorded') {
      const native = await port.persistReviewedAdvisoryVulnerabilityBinding(
        bindingCommand(nativeRevision.projection.revisionDigest, 'GHSA-SYNTH-0001-0051', other.id),
      );
      expect(native.kind).toBe('recorded');
      if (native.kind === 'recorded') {
        expect(native.projection.bindingClassification).toBe('provider_native_without_cve');
      }
    }

    const multi = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-0052',
        aliases: ['CVE-2099-1052', 'CVE-2099-1053'],
        trustClassification: 'reviewed',
      }),
    );
    expect(multi.kind).toBe('recorded');
    if (multi.kind === 'recorded') {
      const ambiguous = await port.persistReviewedAdvisoryVulnerabilityBinding(
        bindingCommand(multi.projection.revisionDigest, 'GHSA-SYNTH-0001-0052', vulnerability.id),
      );
      expect(ambiguous.kind).toBe('rejected');
      if (ambiguous.kind === 'rejected') {
        expect(ambiguous.code).toBe('vulnerability_binding_conflicted');
      }
      expect(
        await prisma.advisoryVulnerabilityBinding.count({
          where: { advisoryRevisionId: multi.projection.revisionId },
        }),
      ).toBe(0);
    }

    const synthetic = await port.persistImmutableAdvisoryRevision(
      revisionCommand({ advisoryId: 'SYNTHETICADV50' }),
    );
    expect(synthetic.kind).toBe('recorded');
    if (synthetic.kind === 'recorded') {
      const denied = await port.persistReviewedAdvisoryVulnerabilityBinding(
        bindingCommand(synthetic.projection.revisionDigest, 'SYNTHETICADV50', vulnerability.id),
      );
      expect(denied.kind).toBe('rejected');
      if (denied.kind === 'rejected') {
        expect(denied.code).toBe('synthetic_not_bindable');
      }
    }

    const withdrawn = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-0053',
        aliases: ['CVE-2099-1053'],
        trustClassification: 'unreviewed',
        withdrawalClassification: 'withdrawn',
      }),
    );
    expect(withdrawn.kind).toBe('recorded');
    if (withdrawn.kind === 'recorded') {
      const denied = await port.persistReviewedAdvisoryVulnerabilityBinding(
        bindingCommand(
          withdrawn.projection.revisionDigest,
          'GHSA-SYNTH-0001-0053',
          vulnerability.id,
        ),
      );
      expect(denied.kind).toBe('rejected');
      if (denied.kind === 'rejected') {
        expect(denied.code).toBe('withdrawn_revision');
      }
    }

    const unbound = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-0054',
        aliases: ['CVE-2099-1054'],
        providerGeneration: '18',
      }),
    );
    expect(unbound.kind).toBe('recorded');
    if (unbound.kind === 'recorded') {
      const missingVulnerability = await port.persistReviewedAdvisoryVulnerabilityBinding(
        bindingCommand(
          unbound.projection.revisionDigest,
          'GHSA-SYNTH-0001-0054',
          '99999999-9999-4999-8999-999999999999',
        ),
      );
      expect(missingVulnerability.kind).toBe('rejected');
      if (missingVulnerability.kind === 'rejected') {
        expect(missingVulnerability.code).toBe('vulnerability_missing');
      }
    }
  });

  it('rejects update, delete, and cascade removal of revision evidence', async () => {
    const recorded = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-0060',
        aliases: [],
        trustClassification: 'unreviewed',
      }),
    );
    expect(recorded.kind).toBe('recorded');
    if (recorded.kind !== 'recorded') {
      return;
    }
    await expectSqlState(
      () =>
        prisma.$executeRaw`
          UPDATE "advisory_revision"
          SET "trust_classification" = 'reviewed'
          WHERE "id" = ${recorded.projection.revisionId}::uuid
        `,
      '23001',
    );
    await expectSqlState(
      () =>
        prisma.$executeRaw`
          DELETE FROM "advisory_revision" WHERE "id" = ${recorded.projection.revisionId}::uuid
        `,
      '23001',
    );
    await expectSqlState(
      () =>
        prisma.$executeRaw`
          DELETE FROM "advisory_family" WHERE "id" = ${recorded.projection.familyId}::uuid
        `,
      '23001',
    );
    const vulnerability = await prisma.vulnerability.create({
      data: { osvId: 'SYNTHETIC-VULN-DELETE' },
      select: { id: true },
    });
    const parent = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-0061',
        aliases: [],
        trustClassification: 'reviewed',
        providerGeneration: '9',
      }),
    );
    expect(parent.kind).toBe('recorded');
    if (parent.kind !== 'recorded') {
      return;
    }
    const bound = await port.persistReviewedAdvisoryVulnerabilityBinding(
      bindingCommand(parent.projection.revisionDigest, 'GHSA-SYNTH-0001-0061', vulnerability.id),
    );
    expect(bound.kind).toBe('recorded');
    await expectSqlState(
      () => prisma.$executeRaw`DELETE FROM "vulnerability" WHERE "id" = ${vulnerability.id}::uuid`,
      '23503',
    );
    expect(
      await prisma.advisoryVulnerabilityBinding.count({
        where: { vulnerabilityId: vulnerability.id },
      }),
    ).toBe(1);
  });

  it('converges concurrent identical revisions and does not overwrite a conflicting twin', async () => {
    const command = providerCommand({
      advisoryId: 'GHSA-SYNTH-0001-0070',
      aliases: ['CVE-2099-1070'],
      providerGeneration: '11',
    });
    const results = await Promise.all([
      port.persistImmutableAdvisoryRevision(command),
      port.persistImmutableAdvisoryRevision(command),
    ]);
    const kinds = results.map((result) => result.kind).sort();
    expect(kinds).toEqual(['already_applied', 'recorded']);
    expect(
      await prisma.advisoryRevision.count({ where: { advisoryId: 'GHSA-SYNTH-0001-0070' } }),
    ).toBe(1);

    const reviewed = providerCommand({
      advisoryId: 'GHSA-SYNTH-0001-0071',
      aliases: ['CVE-2099-1071'],
      trustClassification: 'reviewed',
      providerGeneration: '12',
    });
    const unreviewed = providerCommand({
      advisoryId: 'GHSA-SYNTH-0001-0071',
      aliases: ['CVE-2099-1071'],
      trustClassification: 'unreviewed',
      providerGeneration: '12',
    });
    const raced = await Promise.all([
      port.persistImmutableAdvisoryRevision(reviewed),
      port.persistImmutableAdvisoryRevision(unreviewed),
    ]);
    expect(raced.filter((result) => result.kind === 'recorded')).toHaveLength(1);
    expect(raced.filter((result) => result.kind === 'immutable_conflict')).toHaveLength(1);
    expect(
      await prisma.advisoryRevision.count({ where: { advisoryId: 'GHSA-SYNTH-0001-0071' } }),
    ).toBe(1);
  });

  it('admits one concurrent binding and leaves a racing mapping without an orphan', async () => {
    const left = await prisma.vulnerability.create({
      data: { osvId: 'SYNTHETIC-VULN-RACE-1' },
      select: { id: true },
    });
    const right = await prisma.vulnerability.create({
      data: { osvId: 'SYNTHETIC-VULN-RACE-2' },
      select: { id: true },
    });
    const revision = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-0080',
        aliases: ['CVE-2099-1080'],
        providerGeneration: '13',
      }),
    );
    expect(revision.kind).toBe('recorded');
    if (revision.kind !== 'recorded') {
      return;
    }
    const raced = await Promise.all([
      port.persistReviewedAdvisoryVulnerabilityBinding(
        bindingCommand(revision.projection.revisionDigest, 'GHSA-SYNTH-0001-0080', left.id),
      ),
      port.persistReviewedAdvisoryVulnerabilityBinding(
        bindingCommand(revision.projection.revisionDigest, 'GHSA-SYNTH-0001-0080', right.id),
      ),
    ]);
    expect(raced.filter((result) => result.kind === 'recorded')).toHaveLength(1);
    expect(raced.filter((result) => result.kind === 'immutable_conflict')).toHaveLength(1);
    expect(
      await prisma.advisoryVulnerabilityBinding.count({
        where: { advisoryRevisionId: revision.projection.revisionId },
      }),
    ).toBe(1);

    const early = providerCommand({
      advisoryId: 'GHSA-SYNTH-0001-0081',
      aliases: [],
      trustClassification: 'reviewed',
      providerGeneration: '14',
    });
    const parsed = parseAdvisoryRevisionCommand(early);
    expect(parsed.accepted).toBe(true);
    if (!parsed.accepted) {
      return;
    }
    const paired = await Promise.all([
      port.persistImmutableAdvisoryRevision(early),
      port.persistReviewedAdvisoryVulnerabilityBinding(
        bindingCommand(parsed.command.revisionDigest, 'GHSA-SYNTH-0001-0081', left.id),
      ),
    ]);
    const revisionResult = paired[0] as PersistAdvisoryRevisionResult;
    expect(revisionResult.kind).toBe('recorded');
    const bindingResult = paired[1];
    if (bindingResult?.kind === 'rejected') {
      expect(bindingResult.code).toBe('revision_missing');
      const followUp = await port.persistReviewedAdvisoryVulnerabilityBinding(
        bindingCommand(parsed.command.revisionDigest, 'GHSA-SYNTH-0001-0081', left.id),
      );
      expect(followUp.kind).toBe('recorded');
    } else {
      expect(bindingResult?.kind).toBe('recorded');
    }
    expect(
      await prisma.advisoryVulnerabilityBinding.count({
        where: { revision: { advisoryId: 'GHSA-SYNTH-0001-0081' } },
      }),
    ).toBe(1);
  });

  it('does not show an uncommitted revision and reports an unreachable database without writing', async () => {
    const command = providerCommand({
      advisoryId: 'GHSA-SYNTH-0001-0090',
      aliases: [],
      trustClassification: 'unreviewed',
      providerGeneration: '15',
    });
    const parsed = parseAdvisoryRevisionCommand(command);
    expect(parsed.accepted).toBe(true);
    if (!parsed.accepted) {
      return;
    }
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered: (() => void) | undefined;
    const enteredGate = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const pending = prisma.$transaction(async (tx) => {
      const family = await tx.advisoryFamily.create({
        data: {
          familySchemaVersion: parsed.command.familySchemaVersion,
          source: parsed.command.source,
          advisoryId: parsed.command.advisoryId,
          familyDigest: parsed.command.familyDigest,
          sourceRegistryVersion: parsed.command.sourceLicenseRegistryVersion,
        },
        select: { id: true },
      });
      await tx.advisoryRevision.create({
        data: {
          revisionSchemaVersion: parsed.command.revisionSchemaVersion,
          advisoryFamilyId: family.id,
          source: parsed.command.source,
          advisoryId: parsed.command.advisoryId,
          familyDigest: parsed.command.familyDigest,
          revisionDigest: parsed.command.revisionDigest,
          providerGeneration: parsed.command.providerGeneration,
          contentFingerprint: parsed.command.contentFingerprint,
          session14RangeFingerprint: parsed.command.session14RangeFingerprint,
          productRangeFingerprint: parsed.command.productRangeFingerprint,
          parserId: parsed.command.parserId,
          parserResourcePolicy: parsed.command.parserResourcePolicy,
          advisorySchemaVersion: parsed.command.advisorySchemaVersion,
          advisorySchemaCommit: parsed.command.advisorySchemaCommit,
          sourceLicenseRegistryVersion: parsed.command.sourceLicenseRegistryVersion,
          sourceLicensePolicyVersion: parsed.command.sourceLicensePolicyVersion,
          spdxLicenseId: parsed.command.spdxLicenseId,
          origin: parsed.command.origin,
          trustClassification: parsed.command.trustClassification,
          revisionDisposition: parsed.command.revisionDisposition,
          withdrawalClassification: parsed.command.withdrawalClassification,
          quarantineClassification: parsed.command.quarantineClassification,
          supersedesRevisionDigest: parsed.command.supersedesRevisionDigest,
          retrievalClassification: parsed.command.retrievalClassification,
          retrievalEvidenceId: parsed.command.retrievalEvidenceId,
          retrievalPolicyId: parsed.command.retrievalPolicyId,
          ecosystem: parsed.command.ecosystem,
          packageNamespace: parsed.command.packageNamespace,
          packageName: parsed.command.packageName,
          packageIdentityKey: parsed.command.packageIdentityKey,
          evaluatorVersion: parsed.command.evaluatorVersion,
          matchingPolicyId: parsed.command.matchingPolicyId,
          aliasCount: 0,
          cveAliasCount: 0,
          aliasSetDigest: parsed.command.aliasSetDigest,
          replayFingerprint: parsed.command.replayFingerprint,
        },
      });
      entered?.();
      await gate;
    });
    await enteredGate;
    const hidden = await port.inspectImmutableAdvisoryRevision({
      inspectionSchemaVersion: ADVISORY_REVISION_INSPECTION_SCHEMA_VERSION,
      revisionDigest: parsed.command.revisionDigest,
    });
    expect(hidden.kind).toBe('not_found');
    release?.();
    await pending;
    const visible = await port.inspectImmutableAdvisoryRevision({
      inspectionSchemaVersion: ADVISORY_REVISION_INSPECTION_SCHEMA_VERSION,
      revisionDigest: parsed.command.revisionDigest,
    });
    expect(visible.kind).toBe('found');

    const before = await prisma.advisoryRevision.count();
    const brokenUrl = new URL(databaseUrl);
    brokenUrl.port = '1';
    const unreachable = new PrismaClient({ datasources: { db: { url: brokenUrl.toString() } } });
    try {
      const isolated = createAdvisoryRevisionPersistence(unreachable);
      const result = await isolated.persistImmutableAdvisoryRevision(
        providerCommand({
          advisoryId: 'GHSA-SYNTH-0001-0091',
          aliases: [],
          trustClassification: 'unreviewed',
        }),
      );
      expect(result.kind).toBe('rejected');
      if (result.kind === 'rejected') {
        expect(result.code).toBe('database_unavailable');
        expect(result.counts).toEqual(ADVISORY_REVISION_ZERO_COUNTS);
        expect(JSON.stringify(result)).not.toContain(RETRIEVAL_ID);
      }
    } finally {
      await unreachable.$disconnect();
    }
    expect(await prisma.advisoryRevision.count()).toBe(before);
    expect(await prisma.finding.count()).toBe(0);
    const bindingHidden = await port.inspectReviewedAdvisoryVulnerabilityBinding({
      inspectionSchemaVersion: ADVISORY_VULNERABILITY_BINDING_INSPECTION_SCHEMA_VERSION,
      revisionDigest: 'cd'.repeat(32),
    });
    expect(bindingHidden.kind).toBe('not_found');
  });

  it('rejects synthetic lifecycle contradictions, cross-family supersession, and hostile rows', async () => {
    const familiesBefore = await prisma.advisoryFamily.count();
    for (const command of [
      revisionCommand({
        advisoryId: 'SYNTHETICADV2R1',
        withdrawalClassification: 'withdrawn',
      }),
      revisionCommand({
        advisoryId: 'SYNTHETICADV2R2',
        quarantineClassification: 'quarantined',
      }),
      revisionCommand({
        advisoryId: 'SYNTHETICADV2R3',
        supersedesRevisionDigest: 'ab'.repeat(32),
      }),
    ]) {
      const rejected = await port.persistImmutableAdvisoryRevision(command);
      expect(rejected.kind).toBe('rejected');
      if (rejected.kind === 'rejected') {
        expect(rejected.code).toBe('invalid_classification');
        expect(JSON.stringify(rejected)).not.toContain('SELECT');
      }
    }
    expect(await prisma.advisoryFamily.count()).toBe(familiesBefore);

    const synthetic = await port.persistImmutableAdvisoryRevision(
      revisionCommand({ advisoryId: 'SYNTHETICADV2R4' }),
    );
    expect(synthetic.kind).toBe('recorded');
    if (synthetic.kind !== 'recorded') {
      return;
    }
    await expectSqlState(
      () =>
        prisma.$executeRaw`
          INSERT INTO "advisory_revision" (
            "revision_schema_version", "advisory_family_id", "source", "advisory_id",
            "family_digest", "revision_digest", "provider_generation", "content_fingerprint",
            "session14_range_fingerprint", "product_range_fingerprint", "parser_id",
            "parser_resource_policy", "advisory_schema_version", "advisory_schema_commit",
            "source_license_registry_version", "source_license_policy_version", "origin",
            "trust_classification", "revision_disposition", "withdrawal_classification",
            "quarantine_classification", "supersedes_revision_digest", "retrieval_classification",
            "retrieval_evidence_id", "retrieval_policy_id", "ecosystem", "package_name",
            "package_identity_key", "evaluator_version", "matching_policy_id", "alias_count",
            "cve_alias_count", "alias_set_digest", "replay_fingerprint"
          )
          SELECT
            "revision_schema_version", "advisory_family_id", "source", "advisory_id",
            "family_digest", ${'ab'.repeat(32)}, "provider_generation", "content_fingerprint",
            "session14_range_fingerprint", "product_range_fingerprint", "parser_id",
            "parser_resource_policy", "advisory_schema_version", "advisory_schema_commit",
            "source_license_registry_version", "source_license_policy_version", "origin",
            "trust_classification", "revision_disposition", 'withdrawn'::"advisory_withdrawal_classification",
            "quarantine_classification", "supersedes_revision_digest", "retrieval_classification",
            "retrieval_evidence_id", "retrieval_policy_id", "ecosystem", "package_name",
            "package_identity_key", "evaluator_version", "matching_policy_id", "alias_count",
            "cve_alias_count", "alias_set_digest", ${'cd'.repeat(32)}
          FROM "advisory_revision"
          WHERE "id" = ${synthetic.projection.revisionId}::uuid
        `,
      '23514',
    );
    expect(await prisma.advisoryRevision.count({ where: { advisoryId: 'SYNTHETICADV2R4' } })).toBe(
      1,
    );

    const left = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-2R10',
        aliases: [],
        trustClassification: 'unreviewed',
        providerGeneration: '21',
      }),
    );
    const right = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-2R11',
        aliases: [],
        trustClassification: 'unreviewed',
        providerGeneration: '22',
      }),
    );
    expect(left.kind).toBe('recorded');
    expect(right.kind).toBe('recorded');
    if (left.kind !== 'recorded' || right.kind !== 'recorded') {
      return;
    }
    const crossFamily = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-2R11',
        aliases: [],
        trustClassification: 'unreviewed',
        providerGeneration: '23',
        supersedesRevisionDigest: left.projection.revisionDigest,
      }),
    );
    expect(crossFamily.kind).toBe('rejected');
    if (crossFamily.kind === 'rejected') {
      expect(crossFamily.code).toBe('supersession_rejected');
    }
    expect(
      await prisma.advisoryRevision.count({ where: { advisoryId: 'GHSA-SYNTH-0001-2R11' } }),
    ).toBe(1);

    const quarantined = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-2R12',
        aliases: [],
        trustClassification: 'unreviewed',
        quarantineClassification: 'quarantined',
        providerGeneration: '24',
      }),
    );
    expect(quarantined.kind).toBe('recorded');
    if (quarantined.kind === 'recorded') {
      expect(quarantined.projection.revisionDisposition).toBe('quarantined');
      const vulnerability = await prisma.vulnerability.create({
        data: { osvId: 'SYNTHETIC-VULN-2R-QUARANTINE' },
        select: { id: true },
      });
      const denied = await port.persistReviewedAdvisoryVulnerabilityBinding(
        bindingCommand(
          quarantined.projection.revisionDigest,
          'GHSA-SYNTH-0001-2R12',
          vulnerability.id,
        ),
      );
      expect(denied.kind).toBe('rejected');
      if (denied.kind === 'rejected') {
        expect(denied.code).toBe('quarantined_revision');
      }
    }

    const aliased = await port.persistImmutableAdvisoryRevision(
      providerCommand({
        advisoryId: 'GHSA-SYNTH-0001-2R13',
        aliases: ['CVE-2099-2213'],
        trustClassification: 'reviewed',
        providerGeneration: '25',
      }),
    );
    expect(aliased.kind).toBe('recorded');
    if (aliased.kind !== 'recorded') {
      return;
    }
    const vulnerability = await prisma.vulnerability.create({
      data: { osvId: 'SYNTHETIC-VULN-2R-ALIAS' },
      select: { id: true },
    });
    const bound = await port.persistReviewedAdvisoryVulnerabilityBinding(
      bindingCommand(aliased.projection.revisionDigest, 'GHSA-SYNTH-0001-2R13', vulnerability.id),
    );
    expect(bound.kind).toBe('recorded');
    await expectSqlState(
      () =>
        prisma.advisoryRevision.update({
          where: { id: aliased.projection.revisionId },
          data: { trustClassification: 'unreviewed' },
        }),
      '23001',
    );
    await expectSqlState(
      () =>
        prisma.advisoryRevision.updateMany({
          where: { id: aliased.projection.revisionId },
          data: { origin: 'synthetic_fixture' },
        }),
      '23001',
    );
    await expectSqlState(
      () =>
        prisma.advisoryRevisionAlias.deleteMany({
          where: { advisoryRevisionId: aliased.projection.revisionId },
        }),
      '23001',
    );
    await expectSqlState(
      () =>
        prisma.advisoryVulnerabilityBinding.deleteMany({
          where: { advisoryRevisionId: aliased.projection.revisionId },
        }),
      '23001',
    );
    await expectSqlState(
      () =>
        prisma.advisoryRevision.deleteMany({
          where: { id: aliased.projection.revisionId },
        }),
      '23001',
    );
    const unchanged = await prisma.advisoryRevision.findUniqueOrThrow({
      where: { id: aliased.projection.revisionId },
      select: { trustClassification: true, origin: true },
    });
    expect(unchanged.trustClassification).toBe('reviewed');
    expect(unchanged.origin).toBe('provider_derived');
    expect(
      await prisma.advisoryRevisionAlias.count({
        where: { advisoryRevisionId: aliased.projection.revisionId },
      }),
    ).toBe(1);
    expect(
      await prisma.advisoryVulnerabilityBinding.count({
        where: { advisoryRevisionId: aliased.projection.revisionId },
      }),
    ).toBe(1);

    const gapFamily = await prisma.advisoryRevision.findUniqueOrThrow({
      where: { id: aliased.projection.revisionId },
      select: {
        advisoryFamilyId: true,
        source: true,
        advisoryId: true,
        familyDigest: true,
        contentFingerprint: true,
        session14RangeFingerprint: true,
        productRangeFingerprint: true,
        parserId: true,
        parserResourcePolicy: true,
        advisorySchemaVersion: true,
        advisorySchemaCommit: true,
        sourceLicenseRegistryVersion: true,
        sourceLicensePolicyVersion: true,
        spdxLicenseId: true,
        origin: true,
        trustClassification: true,
        retrievalClassification: true,
        retrievalEvidenceId: true,
        retrievalPolicyId: true,
        ecosystem: true,
        packageName: true,
        packageIdentityKey: true,
        evaluatorVersion: true,
        matchingPolicyId: true,
        aliasSetDigest: true,
      },
    });
    const revisionsBeforeGap = await prisma.advisoryRevision.count({
      where: { advisoryId: 'GHSA-SYNTH-0001-2R13' },
    });
    try {
      await prisma.$transaction(async (tx) => {
        const inserted = await tx.$queryRaw<Array<{ id: string }>>`
          INSERT INTO "advisory_revision" (
            "revision_schema_version", "advisory_family_id", "source", "advisory_id",
            "family_digest", "revision_digest", "provider_generation", "content_fingerprint",
            "session14_range_fingerprint", "product_range_fingerprint", "parser_id",
            "parser_resource_policy", "advisory_schema_version", "advisory_schema_commit",
            "source_license_registry_version", "source_license_policy_version", "spdx_license_id",
            "origin", "trust_classification", "revision_disposition", "withdrawal_classification",
            "quarantine_classification", "supersedes_revision_digest", "retrieval_classification",
            "retrieval_evidence_id", "retrieval_policy_id", "ecosystem", "package_name",
            "package_identity_key", "evaluator_version", "matching_policy_id", "alias_count",
            "cve_alias_count", "alias_set_digest", "replay_fingerprint"
          ) VALUES (
            'osv_advisory_revision_identity_v1',
            ${gapFamily.advisoryFamilyId}::uuid,
            ${gapFamily.source}::"advisory_evidence_source",
            ${gapFamily.advisoryId},
            ${gapFamily.familyDigest},
            ${'ee'.repeat(32)},
            '26',
            ${gapFamily.contentFingerprint},
            ${gapFamily.session14RangeFingerprint},
            ${gapFamily.productRangeFingerprint},
            ${gapFamily.parserId},
            ${gapFamily.parserResourcePolicy},
            ${gapFamily.advisorySchemaVersion},
            ${gapFamily.advisorySchemaCommit},
            ${gapFamily.sourceLicenseRegistryVersion},
            ${gapFamily.sourceLicensePolicyVersion},
            ${gapFamily.spdxLicenseId},
            ${gapFamily.origin}::"advisory_evidence_origin",
            'unreviewed'::"advisory_evidence_trust",
            'recorded'::"advisory_revision_disposition",
            'not_withdrawn'::"advisory_withdrawal_classification",
            'not_quarantined'::"advisory_quarantine_classification",
            'none',
            ${gapFamily.retrievalClassification}::"advisory_retrieval_classification",
            ${gapFamily.retrievalEvidenceId},
            ${gapFamily.retrievalPolicyId},
            ${gapFamily.ecosystem},
            ${gapFamily.packageName},
            ${gapFamily.packageIdentityKey},
            ${gapFamily.evaluatorVersion},
            ${gapFamily.matchingPolicyId},
            1,
            0,
            ${gapFamily.aliasSetDigest},
            ${'ff'.repeat(32)}
          )
          RETURNING "id"
        `;
        const revisionId = inserted[0]?.id;
        if (revisionId === undefined) {
          throw new Error('gap revision was not inserted');
        }
        await tx.$executeRaw`
          INSERT INTO "advisory_revision_alias" (
            "advisory_revision_id", "ordinal", "alias_type", "alias_value",
            "alias_policy_version", "source_classification", "review_classification",
            "replay_fingerprint"
          ) VALUES (
            ${revisionId}::uuid,
            5,
            'provider_native'::"advisory_alias_type",
            'GHSA-SYNTH-0001-2R13',
            'osv_advisory_alias_policy_v1',
            'provider_derived'::"advisory_evidence_origin",
            'unreviewed'::"advisory_alias_review",
            ${'12'.repeat(32)}
          )
        `;
      });
      expect.unreachable();
    } catch (error) {
      const message = error instanceof Error ? error.message : '';
      expect(message).toContain('advisory alias ordinal is inconsistent');
      expect(message).not.toContain('SELECT');
    }
    expect(
      await prisma.advisoryRevision.count({ where: { advisoryId: 'GHSA-SYNTH-0001-2R13' } }),
    ).toBe(revisionsBeforeGap);

    const hostile = await prisma.$queryRaw<Array<{ id: string }>>`
      INSERT INTO "advisory_revision" (
        "revision_schema_version", "advisory_family_id", "source", "advisory_id",
        "family_digest", "revision_digest", "provider_generation", "content_fingerprint",
        "session14_range_fingerprint", "product_range_fingerprint", "parser_id",
        "parser_resource_policy", "advisory_schema_version", "advisory_schema_commit",
        "source_license_registry_version", "source_license_policy_version", "spdx_license_id",
        "origin", "trust_classification", "revision_disposition", "withdrawal_classification",
        "quarantine_classification", "supersedes_revision_digest", "retrieval_classification",
        "retrieval_evidence_id", "retrieval_policy_id", "ecosystem", "package_name",
        "package_identity_key", "evaluator_version", "matching_policy_id", "alias_count",
        "cve_alias_count", "alias_set_digest", "replay_fingerprint"
      )
      SELECT
        "revision_schema_version", "advisory_family_id", "source", "advisory_id",
        "family_digest", ${'34'.repeat(32)}, '27', "content_fingerprint",
        "session14_range_fingerprint", "product_range_fingerprint", "parser_id",
        "parser_resource_policy", "advisory_schema_version", "advisory_schema_commit",
        "source_license_registry_version", "source_license_policy_version", "spdx_license_id",
        "origin", "trust_classification", "revision_disposition", "withdrawal_classification",
        "quarantine_classification", "supersedes_revision_digest", "retrieval_classification",
        "retrieval_evidence_id", "retrieval_policy_id", "ecosystem", "package_name",
        "package_identity_key", "evaluator_version", "matching_policy_id", 0, 0,
        "alias_set_digest", ${'56'.repeat(32)}
      FROM "advisory_revision"
      WHERE "id" = ${left.projection.revisionId}::uuid
      RETURNING "id"
    `;
    const hostileId = hostile[0]?.id;
    expect(hostileId).toBeDefined();
    const inspected = await port.inspectImmutableAdvisoryRevision({
      inspectionSchemaVersion: ADVISORY_REVISION_INSPECTION_SCHEMA_VERSION,
      revisionId: hostileId,
    });
    expect(inspected.kind).toBe('rejected');
    if (inspected.kind === 'rejected') {
      expect(inspected.code).toBe('malformed_persisted_state');
      expect(JSON.stringify(inspected)).not.toContain('advisory_revision');
    }
  });
});
