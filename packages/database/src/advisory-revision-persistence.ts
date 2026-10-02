/**
 * Uncomposed PostgreSQL adapter for immutable advisory revisions and
 * reviewed Vulnerability bindings. Construction performs no I/O.
 * The adapter does not contact a provider, parse a body, activate a catalog,
 * evaluate affectedness, or create a Finding.
 */

import { Prisma, type PrismaClient } from '@prisma/client';
import {
  ADVISORY_ALIAS_POLICY_VERSION,
  ADVISORY_MAPPING_CONFLICT_CLASSIFICATION,
  ADVISORY_MAPPING_REVIEW_STATE,
  ADVISORY_MAPPING_SOURCE_CLASSIFICATION,
  ADVISORY_REVISION_FINDING_CREATION,
  ADVISORY_REVISION_INSPECTION_SCHEMA_VERSION,
  ADVISORY_REVISION_ZERO_COUNTS,
  ADVISORY_VULNERABILITY_BINDING_INSPECTION_SCHEMA_VERSION,
  EXACT_MAPPING_METHOD,
  OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
  VULNERABILITY_MAPPING_POLICY_ID,
  advisoryFamilyDigest,
  advisoryRevisionDigest,
  advisoryRevisionReplayFingerprint,
  aliasReplayFingerprint,
  aliasSetCanonical,
  aliasSetDigest,
  classifyAdvisoryRevisionAgreement,
  classifyMappingAgreement,
  deriveRevisionDisposition,
  mappingEvidenceFingerprint,
  mappingReplayFingerprint,
  parseAdvisoryBindingCommand,
  parseAdvisoryBindingInspection,
  parseAdvisoryRevisionCommand,
  parseAdvisoryRevisionInspection,
  trustMatchesDisposition,
  type AdvisoryBindingClassification,
  type AdvisoryRevisionIdentityFields,
  type AdvisoryRevisionPersistencePort,
  type AdvisoryRevisionProjection,
  type AdvisoryRevisionRejectionCode,
  type AdvisoryVulnerabilityBindingProjection,
  type ParsedAdvisoryRevisionCommand,
  type PersistAdvisoryBindingResult,
  type PersistAdvisoryRevisionResult,
} from '@patchpilot/vulnerability-intelligence';

import {
  isAdvisoryRevisionUniqueViolation,
  translateAdvisoryRevisionPersistenceFailure,
} from './advisory-revision-persistence-errors.js';
import { isRootPrismaClient } from './guards.js';

const ROOT_CLIENT_REQUIRED = 'Advisory revision persistence requires the root database client.';
const FAMILY_SCHEMA_VERSION = 'osv_advisory_family_identity_v1';
const REVISION_SCHEMA_VERSION = 'osv_advisory_revision_identity_v1';
const BINDING_SCHEMA_VERSION = 'osv_advisory_vulnerability_binding_v1';

const REVISION_SELECT = {
  id: true,
  revisionSchemaVersion: true,
  advisoryFamilyId: true,
  source: true,
  advisoryId: true,
  familyDigest: true,
  revisionDigest: true,
  providerGeneration: true,
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
  revisionDisposition: true,
  withdrawalClassification: true,
  quarantineClassification: true,
  supersedesRevisionDigest: true,
  retrievalClassification: true,
  retrievalEvidenceId: true,
  retrievalPolicyId: true,
  ecosystem: true,
  packageNamespace: true,
  packageName: true,
  packageIdentityKey: true,
  evaluatorVersion: true,
  matchingPolicyId: true,
  aliasCount: true,
  cveAliasCount: true,
  aliasSetDigest: true,
  replayFingerprint: true,
  createdAt: true,
  aliases: {
    orderBy: { ordinal: 'asc' as const },
    select: {
      ordinal: true,
      aliasType: true,
      aliasValue: true,
      aliasPolicyVersion: true,
      sourceClassification: true,
      reviewClassification: true,
      replayFingerprint: true,
    },
  },
  binding: {
    select: { id: true },
  },
} satisfies Prisma.AdvisoryRevisionSelect;

const BINDING_SELECT = {
  id: true,
  bindingSchemaVersion: true,
  advisoryRevisionId: true,
  vulnerabilityId: true,
  mappingPolicyId: true,
  mappingMethod: true,
  mappingEvidenceFingerprint: true,
  mappingReviewState: true,
  mappingSourceClassification: true,
  conflictClassification: true,
  bindingClassification: true,
  replayFingerprint: true,
  createdAt: true,
  revision: {
    select: {
      revisionDigest: true,
      advisoryId: true,
      cveAliasCount: true,
      aliases: {
        orderBy: { ordinal: 'asc' as const },
        select: { aliasValue: true },
      },
    },
  },
} satisfies Prisma.AdvisoryVulnerabilityBindingSelect;

type RevisionRow = Prisma.AdvisoryRevisionGetPayload<{ select: typeof REVISION_SELECT }>;
type BindingRow = Prisma.AdvisoryVulnerabilityBindingGetPayload<{ select: typeof BINDING_SELECT }>;
type PersistenceClient = PrismaClient | Prisma.TransactionClient;

class AdvisoryRevisionRowError extends Error {
  public constructor() {
    super('Advisory revision row is malformed.');
    this.name = 'AdvisoryRevisionRowError';
  }
}

class AdvisoryRevisionPersistenceFailure extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'AdvisoryRevisionPersistenceFailure';
  }
}

class AdvisoryRevisionDecision extends Error {
  public constructor(readonly result: PersistAdvisoryRevisionResult) {
    super('advisory revision persistence decision');
    this.name = 'AdvisoryRevisionDecision';
  }
}

function rejectedRevision(code: AdvisoryRevisionRejectionCode): PersistAdvisoryRevisionResult {
  return { kind: 'rejected', code, counts: ADVISORY_REVISION_ZERO_COUNTS };
}

function rejectedBinding(code: AdvisoryRevisionRejectionCode): PersistAdvisoryBindingResult {
  return { kind: 'rejected', code, counts: ADVISORY_REVISION_ZERO_COUNTS };
}

function assertRevisionLifecycle(row: RevisionRow): void {
  const derived = deriveRevisionDisposition({
    origin: row.origin,
    withdrawalClassification: row.withdrawalClassification,
    quarantineClassification: row.quarantineClassification,
    supersedesRevisionDigest: row.supersedesRevisionDigest,
  });
  if (
    derived === null ||
    derived !== row.revisionDisposition ||
    !trustMatchesDisposition({
      origin: row.origin,
      trustClassification: row.trustClassification,
      revisionDisposition: row.revisionDisposition,
    })
  ) {
    throw new AdvisoryRevisionRowError();
  }
  if (row.origin === 'synthetic_fixture' && row.source !== 'synthetic_fixture') {
    throw new AdvisoryRevisionRowError();
  }
  if (row.origin === 'unrecognized' && row.source !== 'unrecognized') {
    throw new AdvisoryRevisionRowError();
  }
  if (
    row.origin === 'provider_derived' &&
    (row.source === 'synthetic_fixture' || row.source === 'unrecognized')
  ) {
    throw new AdvisoryRevisionRowError();
  }
}

function identityFromCommand(
  command: ParsedAdvisoryRevisionCommand,
): AdvisoryRevisionIdentityFields & {
  readonly familyDigest: string;
  readonly revisionDigest: string;
  readonly replayFingerprint: string;
} {
  return command;
}

function identityFromRow(row: RevisionRow): AdvisoryRevisionIdentityFields & {
  readonly familyDigest: string;
  readonly revisionDigest: string;
  readonly replayFingerprint: string;
} {
  if (row.ecosystem !== 'npm') {
    throw new AdvisoryRevisionRowError();
  }
  assertRevisionLifecycle(row);
  return {
    source: row.source,
    advisoryId: row.advisoryId,
    providerGeneration: row.providerGeneration,
    contentFingerprint: row.contentFingerprint,
    session14RangeFingerprint: row.session14RangeFingerprint,
    productRangeFingerprint: row.productRangeFingerprint,
    parserId: row.parserId,
    parserResourcePolicy: row.parserResourcePolicy,
    advisorySchemaVersion: row.advisorySchemaVersion,
    advisorySchemaCommit: row.advisorySchemaCommit,
    sourceLicenseRegistryVersion: row.sourceLicenseRegistryVersion,
    sourceLicensePolicyVersion: row.sourceLicensePolicyVersion,
    spdxLicenseId: row.spdxLicenseId,
    origin: row.origin,
    trustClassification: row.trustClassification,
    revisionDisposition: row.revisionDisposition,
    withdrawalClassification: row.withdrawalClassification,
    quarantineClassification: row.quarantineClassification,
    supersedesRevisionDigest: row.supersedesRevisionDigest,
    retrievalClassification: row.retrievalClassification,
    retrievalEvidenceId: row.retrievalEvidenceId,
    ecosystem: 'npm',
    packageIdentityKey: row.packageIdentityKey,
    evaluatorVersion: row.evaluatorVersion,
    matchingPolicyId: row.matchingPolicyId,
    aliases: row.aliases.map((alias) => ({
      ordinal: alias.ordinal,
      aliasType: alias.aliasType,
      aliasValue: alias.aliasValue,
      reviewClassification: alias.reviewClassification,
      sourceClassification: alias.sourceClassification,
      replayFingerprint: alias.replayFingerprint,
    })),
    familyDigest: row.familyDigest,
    revisionDigest: row.revisionDigest,
    replayFingerprint: row.replayFingerprint,
  };
}

function projectRevision(row: RevisionRow): AdvisoryRevisionProjection {
  if (row.ecosystem !== 'npm') {
    throw new AdvisoryRevisionRowError();
  }
  const identity = identityFromRow(row);
  if (advisoryFamilyDigest(row.source, row.advisoryId) !== row.familyDigest) {
    throw new AdvisoryRevisionRowError();
  }
  if (
    advisoryRevisionDigest({
      familyDigest: row.familyDigest,
      providerGeneration: row.providerGeneration,
      contentFingerprint: row.contentFingerprint,
      session14RangeFingerprint: row.session14RangeFingerprint,
      productRangeFingerprint: row.productRangeFingerprint,
      parserId: row.parserId,
      parserResourcePolicy: row.parserResourcePolicy,
      advisorySchemaVersion: row.advisorySchemaVersion,
      advisorySchemaCommit: row.advisorySchemaCommit,
      sourceLicenseRegistryVersion: row.sourceLicenseRegistryVersion,
      spdxLicenseId: row.spdxLicenseId,
      withdrawalClassification: row.withdrawalClassification,
      quarantineClassification: row.quarantineClassification,
      supersedesRevisionDigest: row.supersedesRevisionDigest,
      retrievalEvidenceId: row.retrievalEvidenceId,
    }) !== row.revisionDigest
  ) {
    throw new AdvisoryRevisionRowError();
  }
  if (advisoryRevisionReplayFingerprint(identity) !== row.replayFingerprint) {
    throw new AdvisoryRevisionRowError();
  }
  const aliasValues = row.aliases.map((alias) => alias.aliasValue);
  if (aliasSetDigest(aliasValues) !== row.aliasSetDigest || row.aliases.length !== row.aliasCount) {
    throw new AdvisoryRevisionRowError();
  }
  const cveCount = row.aliases.filter((alias) => alias.aliasType === 'canonical_cve').length;
  if (cveCount !== row.cveAliasCount) {
    throw new AdvisoryRevisionRowError();
  }
  for (let index = 0; index < row.aliases.length; index += 1) {
    const alias = row.aliases[index];
    if (alias === undefined || alias.ordinal !== index + 1) {
      throw new AdvisoryRevisionRowError();
    }
    if (alias.aliasPolicyVersion !== ADVISORY_ALIAS_POLICY_VERSION) {
      throw new AdvisoryRevisionRowError();
    }
    if (
      alias.replayFingerprint !==
      aliasReplayFingerprint({
        revisionDigest: row.revisionDigest,
        ordinal: alias.ordinal,
        aliasType: alias.aliasType,
        aliasValue: alias.aliasValue,
        reviewClassification: alias.reviewClassification,
        sourceClassification: alias.sourceClassification,
      })
    ) {
      throw new AdvisoryRevisionRowError();
    }
  }
  if (
    row.revisionSchemaVersion !== REVISION_SCHEMA_VERSION ||
    row.sourceLicenseRegistryVersion !== OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER ||
    row.sourceLicensePolicyVersion !== OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER
  ) {
    throw new AdvisoryRevisionRowError();
  }
  const mappingCount = row.binding === null ? 0 : 1;
  return {
    inspectionSchemaVersion: ADVISORY_REVISION_INSPECTION_SCHEMA_VERSION,
    revisionId: row.id,
    familyId: row.advisoryFamilyId,
    source: row.source,
    advisoryId: row.advisoryId,
    familyDigest: row.familyDigest,
    revisionDigest: row.revisionDigest,
    contentFingerprint: row.contentFingerprint,
    session14RangeFingerprint: row.session14RangeFingerprint,
    productRangeFingerprint: row.productRangeFingerprint,
    parserId: row.parserId,
    parserResourcePolicy: row.parserResourcePolicy,
    advisorySchemaVersion: row.advisorySchemaVersion,
    advisorySchemaCommit: row.advisorySchemaCommit,
    sourceLicenseRegistryVersion: row.sourceLicenseRegistryVersion,
    sourceLicensePolicyVersion: row.sourceLicensePolicyVersion,
    spdxLicenseId: row.spdxLicenseId,
    origin: row.origin,
    trustClassification: row.trustClassification,
    revisionDisposition: row.revisionDisposition,
    withdrawalClassification: row.withdrawalClassification,
    quarantineClassification: row.quarantineClassification,
    supersedesRevisionDigest: row.supersedesRevisionDigest,
    retrievalClassification: row.retrievalClassification,
    ecosystem: 'npm',
    packageNamespace: row.packageNamespace,
    packageName: row.packageName,
    packageIdentityKey: row.packageIdentityKey,
    replayFingerprint: row.replayFingerprint,
    aliasCount: row.aliasCount,
    cveAliasCount: row.cveAliasCount,
    mappingCountClassification: mappingCount === 0 ? 'none' : 'one_reviewed',
    createdAt: row.createdAt.toISOString(),
    findingCreation: ADVISORY_REVISION_FINDING_CREATION,
    productEligibilityStored: false,
    catalogActivationStored: false,
  };
}

function projectBinding(row: BindingRow): AdvisoryVulnerabilityBindingProjection {
  const aliasCanonical = aliasSetCanonical(row.revision.aliases.map((alias) => alias.aliasValue));
  const evidence = mappingEvidenceFingerprint({
    revisionDigest: row.revision.revisionDigest,
    vulnerabilityId: row.vulnerabilityId,
    bindingClassification: row.bindingClassification,
    aliasCanonical,
  });
  const replay = mappingReplayFingerprint({
    mappingEvidenceFingerprint: evidence,
    revisionDigest: row.revision.revisionDigest,
    vulnerabilityId: row.vulnerabilityId,
    bindingClassification: row.bindingClassification,
    aliasCanonical,
  });
  if (
    row.bindingSchemaVersion !== BINDING_SCHEMA_VERSION ||
    row.mappingPolicyId !== VULNERABILITY_MAPPING_POLICY_ID ||
    row.mappingMethod !== EXACT_MAPPING_METHOD ||
    row.mappingReviewState !== ADVISORY_MAPPING_REVIEW_STATE ||
    row.mappingSourceClassification !== ADVISORY_MAPPING_SOURCE_CLASSIFICATION ||
    row.conflictClassification !== ADVISORY_MAPPING_CONFLICT_CLASSIFICATION ||
    row.mappingEvidenceFingerprint !== evidence ||
    row.replayFingerprint !== replay
  ) {
    throw new AdvisoryRevisionRowError();
  }
  return {
    inspectionSchemaVersion: ADVISORY_VULNERABILITY_BINDING_INSPECTION_SCHEMA_VERSION,
    bindingId: row.id,
    revisionId: row.advisoryRevisionId,
    revisionDigest: row.revision.revisionDigest,
    advisoryId: row.revision.advisoryId,
    vulnerabilityId: row.vulnerabilityId,
    mappingPolicyId: row.mappingPolicyId,
    mappingMethod: row.mappingMethod,
    mappingEvidenceFingerprint: row.mappingEvidenceFingerprint,
    mappingReviewState: 'reviewed',
    mappingSourceClassification: 'explicit_reviewed_binding',
    conflictClassification: 'none',
    bindingClassification: row.bindingClassification,
    replayFingerprint: row.replayFingerprint,
    createdAt: row.createdAt.toISOString(),
    findingCreation: ADVISORY_REVISION_FINDING_CREATION,
    productEligibilityStored: false,
    catalogActivationStored: false,
  };
}

function bindingClassificationFor(cveAliasCount: number): AdvisoryBindingClassification | null {
  if (cveAliasCount === 0) {
    return 'provider_native_without_cve';
  }
  if (cveAliasCount === 1) {
    return 'one_cve_alias_evidence';
  }
  return null;
}

export function createAdvisoryRevisionPersistence(
  client: PrismaClient,
): AdvisoryRevisionPersistencePort {
  if (!isRootPrismaClient(client)) {
    throw new AdvisoryRevisionPersistenceFailure(ROOT_CLIENT_REQUIRED);
  }
  return new PrismaAdvisoryRevisionPersistence(client);
}

class PrismaAdvisoryRevisionPersistence implements AdvisoryRevisionPersistencePort {
  public constructor(private readonly client: PrismaClient) {}

  public async persistImmutableAdvisoryRevision(
    command: unknown,
  ): Promise<PersistAdvisoryRevisionResult> {
    const parsed = parseAdvisoryRevisionCommand(command);
    if (!parsed.accepted) {
      return rejectedRevision(parsed.code);
    }
    try {
      const existing = await this.findRevision(this.client, parsed.command.revisionDigest);
      if (existing !== null) {
        return this.classifyRevision(existing, parsed.command);
      }
      const family = await this.client.advisoryFamily.findUnique({
        where: {
          source_advisoryId: {
            source: parsed.command.source,
            advisoryId: parsed.command.advisoryId,
          },
        },
        select: { familyDigest: true, familySchemaVersion: true, sourceRegistryVersion: true },
      });
      if (
        family !== null &&
        (family.familyDigest !== parsed.command.familyDigest ||
          family.familySchemaVersion !== FAMILY_SCHEMA_VERSION ||
          family.sourceRegistryVersion !== OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER)
      ) {
        return { kind: 'immutable_conflict', counts: ADVISORY_REVISION_ZERO_COUNTS };
      }
      if (parsed.command.supersedesRevisionDigest !== 'none') {
        const prior = await this.client.advisoryRevision.findUnique({
          where: { revisionDigest: parsed.command.supersedesRevisionDigest },
          select: {
            advisoryFamilyId: true,
            family: { select: { source: true, advisoryId: true } },
          },
        });
        if (
          prior === null ||
          prior.family.source !== parsed.command.source ||
          prior.family.advisoryId !== parsed.command.advisoryId
        ) {
          return rejectedRevision('supersession_rejected');
        }
      }
      return await this.insertRevision(parsed.command);
    } catch (error) {
      if (error instanceof AdvisoryRevisionDecision) {
        return error.result;
      }
      if (error instanceof AdvisoryRevisionRowError) {
        return rejectedRevision('malformed_persisted_state');
      }
      if (isAdvisoryRevisionUniqueViolation(error)) {
        return this.reloadRevision(parsed.command);
      }
      return rejectedRevision(translateAdvisoryRevisionPersistenceFailure(error));
    }
  }

  public async persistReviewedAdvisoryVulnerabilityBinding(
    command: unknown,
  ): Promise<PersistAdvisoryBindingResult> {
    const parsed = parseAdvisoryBindingCommand(command);
    if (!parsed.accepted) {
      return rejectedBinding(parsed.code);
    }
    try {
      const revision = await this.findRevision(this.client, parsed.command.revisionDigest);
      if (revision === null) {
        return rejectedBinding('revision_missing');
      }
      if (revision.advisoryId !== parsed.command.advisoryId) {
        return rejectedBinding('invalid_identity');
      }
      const eligibility = this.bindingEligibility(revision);
      if (eligibility !== null) {
        return rejectedBinding(eligibility);
      }
      const classification = bindingClassificationFor(revision.cveAliasCount);
      if (classification === null) {
        return rejectedBinding('vulnerability_binding_conflicted');
      }
      const aliasCanonical = aliasSetCanonical(revision.aliases.map((alias) => alias.aliasValue));
      const evidence = mappingEvidenceFingerprint({
        revisionDigest: revision.revisionDigest,
        vulnerabilityId: parsed.command.vulnerabilityId,
        bindingClassification: classification,
        aliasCanonical,
      });
      const replay = mappingReplayFingerprint({
        mappingEvidenceFingerprint: evidence,
        revisionDigest: revision.revisionDigest,
        vulnerabilityId: parsed.command.vulnerabilityId,
        bindingClassification: classification,
        aliasCanonical,
      });
      const existing = await this.client.advisoryVulnerabilityBinding.findUnique({
        where: { advisoryRevisionId: revision.id },
        select: BINDING_SELECT,
      });
      if (existing !== null) {
        return this.classifyBinding(existing, {
          revisionDigest: revision.revisionDigest,
          vulnerabilityId: parsed.command.vulnerabilityId,
          bindingClassification: classification,
          mappingEvidenceFingerprint: evidence,
          replayFingerprint: replay,
          aliasCanonical,
        });
      }
      return await this.insertBinding({
        revisionId: revision.id,
        vulnerabilityId: parsed.command.vulnerabilityId,
        classification,
        evidence,
        replay,
        aliasCanonical,
        revisionDigest: revision.revisionDigest,
      });
    } catch (error) {
      if (error instanceof AdvisoryRevisionRowError) {
        return rejectedBinding('malformed_persisted_state');
      }
      if (isAdvisoryRevisionUniqueViolation(error)) {
        return this.reloadBinding(parsed.command.revisionDigest, parsed.command.vulnerabilityId);
      }
      return rejectedBinding(translateAdvisoryRevisionPersistenceFailure(error));
    }
  }

  public async inspectImmutableAdvisoryRevision(query: unknown) {
    const parsed = parseAdvisoryRevisionInspection(query);
    if (!parsed.accepted) {
      return { kind: 'rejected' as const, code: parsed.code };
    }
    try {
      const row =
        parsed.inspection.mode === 'revision_id'
          ? await this.client.advisoryRevision.findUnique({
              where: { id: parsed.inspection.revisionId },
              select: REVISION_SELECT,
            })
          : await this.client.advisoryRevision.findUnique({
              where: { revisionDigest: parsed.inspection.revisionDigest },
              select: REVISION_SELECT,
            });
      if (row === null) {
        return { kind: 'not_found' as const };
      }
      return { kind: 'found' as const, projection: projectRevision(row) };
    } catch (error) {
      if (error instanceof AdvisoryRevisionRowError) {
        return { kind: 'rejected' as const, code: 'malformed_persisted_state' as const };
      }
      return {
        kind: 'rejected' as const,
        code: translateAdvisoryRevisionPersistenceFailure(error),
      };
    }
  }

  public async inspectReviewedAdvisoryVulnerabilityBinding(query: unknown) {
    const parsed = parseAdvisoryBindingInspection(query);
    if (!parsed.accepted) {
      return { kind: 'rejected' as const, code: parsed.code };
    }
    try {
      const row =
        parsed.inspection.mode === 'binding_id'
          ? await this.client.advisoryVulnerabilityBinding.findUnique({
              where: { id: parsed.inspection.bindingId },
              select: BINDING_SELECT,
            })
          : await this.client.advisoryVulnerabilityBinding.findFirst({
              where: { revision: { revisionDigest: parsed.inspection.revisionDigest } },
              select: BINDING_SELECT,
            });
      if (row === null) {
        return { kind: 'not_found' as const };
      }
      return { kind: 'found' as const, projection: projectBinding(row) };
    } catch (error) {
      if (error instanceof AdvisoryRevisionRowError) {
        return { kind: 'rejected' as const, code: 'malformed_persisted_state' as const };
      }
      return {
        kind: 'rejected' as const,
        code: translateAdvisoryRevisionPersistenceFailure(error),
      };
    }
  }

  private async findRevision(
    client: PersistenceClient,
    revisionDigest: string,
  ): Promise<RevisionRow | null> {
    return client.advisoryRevision.findUnique({
      where: { revisionDigest },
      select: REVISION_SELECT,
    });
  }

  private classifyRevision(
    row: RevisionRow,
    command: ParsedAdvisoryRevisionCommand,
  ): PersistAdvisoryRevisionResult {
    const agreement = classifyAdvisoryRevisionAgreement(
      identityFromRow(row),
      identityFromCommand(command),
    );
    if (agreement === 'agree') {
      return {
        kind: 'already_applied',
        projection: projectRevision(row),
        counts: ADVISORY_REVISION_ZERO_COUNTS,
      };
    }
    return { kind: 'immutable_conflict', counts: ADVISORY_REVISION_ZERO_COUNTS };
  }

  private async reloadRevision(
    command: ParsedAdvisoryRevisionCommand,
  ): Promise<PersistAdvisoryRevisionResult> {
    const row = await this.findRevision(this.client, command.revisionDigest);
    if (row === null) {
      const family = await this.client.advisoryFamily.findUnique({
        where: {
          source_advisoryId: { source: command.source, advisoryId: command.advisoryId },
        },
        select: { familyDigest: true },
      });
      if (family !== null && family.familyDigest !== command.familyDigest) {
        return { kind: 'immutable_conflict', counts: ADVISORY_REVISION_ZERO_COUNTS };
      }
      return rejectedRevision('internal_failure');
    }
    return this.classifyRevision(row, command);
  }

  private async insertRevision(
    command: ParsedAdvisoryRevisionCommand,
  ): Promise<PersistAdvisoryRevisionResult> {
    return this.client.$transaction(async (tx) => {
      const raced = await this.findRevision(tx, command.revisionDigest);
      if (raced !== null) {
        return this.classifyRevision(raced, command);
      }
      let family = await tx.advisoryFamily.findUnique({
        where: {
          source_advisoryId: { source: command.source, advisoryId: command.advisoryId },
        },
        select: {
          id: true,
          familyDigest: true,
          familySchemaVersion: true,
          sourceRegistryVersion: true,
        },
      });
      let familyInserted = 0;
      if (family === null) {
        familyInserted = await tx.$executeRaw`
          INSERT INTO "advisory_family" (
            "family_schema_version",
            "source",
            "advisory_id",
            "family_digest",
            "source_registry_version"
          ) VALUES (
            ${command.familySchemaVersion},
            ${command.source}::"advisory_evidence_source",
            ${command.advisoryId},
            ${command.familyDigest},
            ${command.sourceLicenseRegistryVersion}
          )
          ON CONFLICT ("source", "advisory_id") DO NOTHING
        `;
        family = await tx.advisoryFamily.findUnique({
          where: {
            source_advisoryId: { source: command.source, advisoryId: command.advisoryId },
          },
          select: {
            id: true,
            familyDigest: true,
            familySchemaVersion: true,
            sourceRegistryVersion: true,
          },
        });
      }
      if (
        family === null ||
        family.familyDigest !== command.familyDigest ||
        family.familySchemaVersion !== FAMILY_SCHEMA_VERSION ||
        family.sourceRegistryVersion !== OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER
      ) {
        throw new AdvisoryRevisionDecision({
          kind: 'immutable_conflict',
          counts: ADVISORY_REVISION_ZERO_COUNTS,
        });
      }
      let supersedesId: string | null = null;
      if (command.supersedesRevisionDigest !== 'none') {
        const prior = await tx.advisoryRevision.findUnique({
          where: { revisionDigest: command.supersedesRevisionDigest },
          select: { id: true, advisoryFamilyId: true },
        });
        if (prior === null || prior.advisoryFamilyId !== family.id) {
          throw new AdvisoryRevisionDecision(rejectedRevision('supersession_rejected'));
        }
        supersedesId = prior.id;
      }
      const created = await tx.advisoryRevision.create({
        data: {
          revisionSchemaVersion: command.revisionSchemaVersion,
          advisoryFamilyId: family.id,
          source: command.source,
          advisoryId: command.advisoryId,
          familyDigest: command.familyDigest,
          revisionDigest: command.revisionDigest,
          providerGeneration: command.providerGeneration,
          contentFingerprint: command.contentFingerprint,
          session14RangeFingerprint: command.session14RangeFingerprint,
          productRangeFingerprint: command.productRangeFingerprint,
          parserId: command.parserId,
          parserResourcePolicy: command.parserResourcePolicy,
          advisorySchemaVersion: command.advisorySchemaVersion,
          advisorySchemaCommit: command.advisorySchemaCommit,
          sourceLicenseRegistryVersion: command.sourceLicenseRegistryVersion,
          sourceLicensePolicyVersion: command.sourceLicensePolicyVersion,
          spdxLicenseId: command.spdxLicenseId,
          origin: command.origin,
          trustClassification: command.trustClassification,
          revisionDisposition: command.revisionDisposition,
          withdrawalClassification: command.withdrawalClassification,
          quarantineClassification: command.quarantineClassification,
          supersedesRevisionDigest: command.supersedesRevisionDigest,
          supersedesAdvisoryRevisionId: supersedesId,
          retrievalClassification: command.retrievalClassification,
          retrievalEvidenceId: command.retrievalEvidenceId,
          retrievalPolicyId: command.retrievalPolicyId,
          ecosystem: command.ecosystem,
          packageNamespace: command.packageNamespace,
          packageName: command.packageName,
          packageIdentityKey: command.packageIdentityKey,
          evaluatorVersion: command.evaluatorVersion,
          matchingPolicyId: command.matchingPolicyId,
          aliasCount: command.aliasCount,
          cveAliasCount: command.cveAliasCount,
          aliasSetDigest: command.aliasSetDigest,
          replayFingerprint: command.replayFingerprint,
          aliases: {
            create: command.aliases.map((alias) => ({
              ordinal: alias.ordinal,
              aliasType: alias.aliasType,
              aliasValue: alias.aliasValue,
              aliasPolicyVersion: command.aliasPolicyVersion,
              sourceClassification: alias.sourceClassification,
              reviewClassification: alias.reviewClassification,
              replayFingerprint: alias.replayFingerprint,
            })),
          },
        },
        select: REVISION_SELECT,
      });
      return {
        kind: 'recorded' as const,
        projection: projectRevision(created),
        counts: {
          inserts: familyInserted + 1 + command.aliasCount,
          updates: 0 as const,
          deletes: 0 as const,
          timestampChanges: 0 as const,
          stateChanges: 0 as const,
          parserCalls: 0 as const,
          providerCalls: 0 as const,
        },
      };
    });
  }

  private bindingEligibility(row: RevisionRow): AdvisoryRevisionRejectionCode | null {
    if (row.origin === 'synthetic_fixture') {
      return 'synthetic_not_bindable';
    }
    if (row.origin !== 'provider_derived') {
      return 'invalid_classification';
    }
    if (row.withdrawalClassification === 'withdrawn') {
      return 'withdrawn_revision';
    }
    if (row.quarantineClassification === 'quarantined') {
      return 'quarantined_revision';
    }
    if (row.trustClassification !== 'reviewed') {
      return 'unreviewed_revision';
    }
    if (row.cveAliasCount > 1) {
      return 'vulnerability_binding_conflicted';
    }
    return null;
  }

  private classifyBinding(
    row: BindingRow,
    command: {
      readonly revisionDigest: string;
      readonly vulnerabilityId: string;
      readonly bindingClassification: AdvisoryBindingClassification;
      readonly mappingEvidenceFingerprint: string;
      readonly replayFingerprint: string;
      readonly aliasCanonical: string;
    },
  ): PersistAdvisoryBindingResult {
    const agreement = classifyMappingAgreement(
      {
        revisionDigest: row.revision.revisionDigest,
        vulnerabilityId: row.vulnerabilityId,
        bindingClassification: row.bindingClassification,
        mappingEvidenceFingerprint: row.mappingEvidenceFingerprint,
        replayFingerprint: row.replayFingerprint,
        aliasCanonical: aliasSetCanonical(row.revision.aliases.map((alias) => alias.aliasValue)),
      },
      command,
    );
    if (agreement === 'agree') {
      return {
        kind: 'already_applied',
        projection: projectBinding(row),
        counts: ADVISORY_REVISION_ZERO_COUNTS,
      };
    }
    return { kind: 'immutable_conflict', counts: ADVISORY_REVISION_ZERO_COUNTS };
  }

  private async reloadBinding(
    revisionDigest: string,
    vulnerabilityId: string,
  ): Promise<PersistAdvisoryBindingResult> {
    const revision = await this.findRevision(this.client, revisionDigest);
    if (revision === null) {
      return rejectedBinding('revision_missing');
    }
    const row = await this.client.advisoryVulnerabilityBinding.findUnique({
      where: { advisoryRevisionId: revision.id },
      select: BINDING_SELECT,
    });
    if (row === null) {
      return rejectedBinding('internal_failure');
    }
    const classification = bindingClassificationFor(revision.cveAliasCount);
    if (classification === null) {
      return { kind: 'immutable_conflict', counts: ADVISORY_REVISION_ZERO_COUNTS };
    }
    const aliasCanonical = aliasSetCanonical(revision.aliases.map((alias) => alias.aliasValue));
    const evidence = mappingEvidenceFingerprint({
      revisionDigest,
      vulnerabilityId,
      bindingClassification: classification,
      aliasCanonical,
    });
    const replay = mappingReplayFingerprint({
      mappingEvidenceFingerprint: evidence,
      revisionDigest,
      vulnerabilityId,
      bindingClassification: classification,
      aliasCanonical,
    });
    return this.classifyBinding(row, {
      revisionDigest,
      vulnerabilityId,
      bindingClassification: classification,
      mappingEvidenceFingerprint: evidence,
      replayFingerprint: replay,
      aliasCanonical,
    });
  }

  private async insertBinding(input: {
    readonly revisionId: string;
    readonly vulnerabilityId: string;
    readonly classification: AdvisoryBindingClassification;
    readonly evidence: string;
    readonly replay: string;
    readonly aliasCanonical: string;
    readonly revisionDigest: string;
  }): Promise<PersistAdvisoryBindingResult> {
    return this.client.$transaction(async (tx) => {
      const revision = await tx.advisoryRevision.findUnique({
        where: { id: input.revisionId },
        select: REVISION_SELECT,
      });
      if (revision === null || revision.revisionDigest !== input.revisionDigest) {
        return rejectedBinding('revision_missing');
      }
      const eligibility = this.bindingEligibility(revision);
      if (eligibility !== null) {
        return rejectedBinding(eligibility);
      }
      const vulnerability = await tx.vulnerability.findUnique({
        where: { id: input.vulnerabilityId },
        select: { id: true },
      });
      if (vulnerability === null) {
        return rejectedBinding('vulnerability_missing');
      }
      const raced = await tx.advisoryVulnerabilityBinding.findUnique({
        where: { advisoryRevisionId: revision.id },
        select: BINDING_SELECT,
      });
      if (raced !== null) {
        return this.classifyBinding(raced, {
          revisionDigest: input.revisionDigest,
          vulnerabilityId: input.vulnerabilityId,
          bindingClassification: input.classification,
          mappingEvidenceFingerprint: input.evidence,
          replayFingerprint: input.replay,
          aliasCanonical: input.aliasCanonical,
        });
      }
      const created = await tx.advisoryVulnerabilityBinding.create({
        data: {
          bindingSchemaVersion: BINDING_SCHEMA_VERSION,
          advisoryRevisionId: revision.id,
          vulnerabilityId: input.vulnerabilityId,
          mappingPolicyId: VULNERABILITY_MAPPING_POLICY_ID,
          mappingMethod: EXACT_MAPPING_METHOD,
          mappingEvidenceFingerprint: input.evidence,
          mappingReviewState: ADVISORY_MAPPING_REVIEW_STATE,
          mappingSourceClassification: ADVISORY_MAPPING_SOURCE_CLASSIFICATION,
          conflictClassification: ADVISORY_MAPPING_CONFLICT_CLASSIFICATION,
          bindingClassification: input.classification,
          replayFingerprint: input.replay,
        },
        select: BINDING_SELECT,
      });
      return {
        kind: 'recorded' as const,
        projection: projectBinding(created),
        counts: {
          inserts: 1,
          updates: 0 as const,
          deletes: 0 as const,
          timestampChanges: 0 as const,
          stateChanges: 0 as const,
          parserCalls: 0 as const,
          providerCalls: 0 as const,
        },
      };
    });
  }
}
