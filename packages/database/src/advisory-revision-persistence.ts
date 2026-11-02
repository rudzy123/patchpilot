/**
 * Uncomposed PostgreSQL adapter for immutable advisory revisions and
 * reviewed Vulnerability bindings. Construction performs no I/O.
 * The adapter does not contact a provider, parse a body, activate a catalog,
 * evaluate affectedness, or create a Finding.
 * Offline npm GHSA files are one transaction: range events, explicit versions,
 * provenance, same-package supersession, and one file audit. The GCS command
 * still stores zero range rows.
 */

import { JSON_SCHEMA_VERSION_V1 } from '@patchpilot/domain';
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
  OFFLINE_IMPORT_PROVIDER_GENERATION,
  OFFLINE_IMPORT_RETRIEVAL_EVIDENCE_ID,
  OFFLINE_NPM_ADVISORY_REVISION_IDENTITY_SCHEMA_VERSION,
  OFFLINE_NPM_LICENSE_ADMISSION_REASON,
  OFFLINE_NPM_OSV_NORMALIZATION_IDENTITY,
  OFFLINE_OSV_IMPORT_RETRIEVAL_POLICY_ID,
  OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
  SUPERSESSION_NONE,
  VULNERABILITY_MAPPING_POLICY_ID,
  advisoryFamilyDigest,
  advisoryRevisionDigest,
  advisoryRevisionReplayFingerprint,
  aliasReplayFingerprint,
  aliasSetCanonical,
  aliasSetDigest,
  classifyAdvisoryRevisionAgreement,
  classifyMappingAgreement,
  classifyOfflineNpmAdvisoryRevisionAgreement,
  deriveRevisionDisposition,
  mappingEvidenceFingerprint,
  mappingReplayFingerprint,
  offlineNpmAdvisoryRevisionDigest,
  offlineNpmAdvisoryRevisionReplayFingerprint,
  parseAdvisoryBindingCommand,
  parseAdvisoryBindingInspection,
  parseAdvisoryRevisionCommand,
  parseAdvisoryRevisionInspection,
  parseOfflineNpmAdvisoryFileCommand,
  session14RangeFingerprint,
  trustMatchesDisposition,
  type AdvisoryBindingClassification,
  type AdvisoryRevisionIdentityFields,
  type AdvisoryRevisionPersistencePort,
  type AdvisoryRevisionProjection,
  type AdvisoryRevisionRejectionCode,
  type AdvisoryVulnerabilityBindingProjection,
  type ParsedAdvisoryRevisionCommand,
  type ParsedOfflineNpmAdvisoryFileCommand,
  type PersistAdvisoryBindingResult,
  type PersistAdvisoryRevisionResult,
  type PersistOfflineNpmAdvisoryFileResult,
} from '@patchpilot/vulnerability-intelligence';

import {
  isAdvisoryRevisionUniqueViolation,
  translateAdvisoryRevisionPersistenceFailure,
} from './advisory-revision-persistence-errors.js';
import { asJsonObject, isRootPrismaClient } from './guards.js';

const ROOT_CLIENT_REQUIRED = 'Advisory revision persistence requires the root database client.';
const FAMILY_SCHEMA_VERSION = 'osv_advisory_family_identity_v1';
const REVISION_SCHEMA_VERSION = 'osv_advisory_revision_identity_v1';
const BINDING_SCHEMA_VERSION = 'osv_advisory_vulnerability_binding_v1';
const OFFLINE_NPM_FILE_AUDIT_ACTION = 'intelligence.offline_npm_osv_file_imported';
const OFFLINE_NPM_FILE_AUDIT_SUBJECT = 'advisory_family';
const OFFLINE_IMPORT_LOCK_PREFIX = 'offline-npm-osv:';
/** Lets one file insert every affected package before the client aborts the transaction. */
const OFFLINE_NPM_FILE_TRANSACTION_TIMEOUT_MS = 120_000;

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
  sourceProvenance: {
    select: {
      source: true,
      sourceLicenseRegistryVersion: true,
      advisoryId: true,
      packageIdentityKey: true,
      rawContentSha256: true,
      parserId: true,
      parserResourcePolicy: true,
      advisorySchemaVersion: true,
      advisorySchemaCommit: true,
      normalizationIdentity: true,
      retrievedAt: true,
      modifiedAt: true,
      publishedAt: true,
      withdrawnAt: true,
      purl: true,
      licenseAdmissionReason: true,
      offlineAdvisoryImportBatchId: true,
    },
  },
  rangeEvents: {
    orderBy: [{ rangeOrdinal: 'asc' as const }, { eventOrdinal: 'asc' as const }],
    select: {
      rangeOrdinal: true,
      eventOrdinal: true,
      eventName: true,
      eventValue: true,
    },
  },
  explicitVersions: {
    orderBy: { ordinal: 'asc' as const },
    select: {
      ordinal: true,
      versionText: true,
    },
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

function session15Origin(
  origin: RevisionRow['origin'],
): Exclude<RevisionRow['origin'], 'maintainer_reviewed_advisory'> {
  if (origin === 'maintainer_reviewed_advisory') {
    throw new AdvisoryRevisionRowError();
  }
  return origin;
}

function session15Source(
  source: RevisionRow['source'],
): Exclude<RevisionRow['source'], 'maintainer_reviewed_advisory'> {
  if (source === 'maintainer_reviewed_advisory') {
    throw new AdvisoryRevisionRowError();
  }
  return source;
}

function session15Retrieval(
  retrieval: RevisionRow['retrievalClassification'],
): Exclude<RevisionRow['retrievalClassification'], 'local_not_retrieved'> {
  if (retrieval === 'local_not_retrieved') {
    throw new AdvisoryRevisionRowError();
  }
  return retrieval;
}

function assertRevisionLifecycle(row: RevisionRow): void {
  const origin = session15Origin(row.origin);
  const derived = deriveRevisionDisposition({
    origin,
    withdrawalClassification: row.withdrawalClassification,
    quarantineClassification: row.quarantineClassification,
    supersedesRevisionDigest: row.supersedesRevisionDigest,
  });
  if (
    derived === null ||
    derived !== row.revisionDisposition ||
    !trustMatchesDisposition({
      origin,
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
  const source = session15Source(row.source);
  const origin = session15Origin(row.origin);
  const retrievalClassification = session15Retrieval(row.retrievalClassification);
  return {
    source,
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
    origin,
    trustClassification: row.trustClassification,
    revisionDisposition: row.revisionDisposition,
    withdrawalClassification: row.withdrawalClassification,
    quarantineClassification: row.quarantineClassification,
    supersedesRevisionDigest: row.supersedesRevisionDigest,
    retrievalClassification,
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
      sourceClassification: session15Origin(alias.sourceClassification),
      replayFingerprint: alias.replayFingerprint,
    })),
    familyDigest: row.familyDigest,
    revisionDigest: row.revisionDigest,
    replayFingerprint: row.replayFingerprint,
  };
}

function isStoredOfflineRevision(row: RevisionRow): boolean {
  return (
    row.origin === 'provider_derived' &&
    row.source === 'github_advisory_database' &&
    row.retrievalClassification === 'local_not_retrieved' &&
    row.retrievalEvidenceId === OFFLINE_IMPORT_RETRIEVAL_EVIDENCE_ID &&
    row.providerGeneration === OFFLINE_IMPORT_PROVIDER_GENERATION &&
    row.retrievalPolicyId === OFFLINE_OSV_IMPORT_RETRIEVAL_POLICY_ID &&
    row.revisionSchemaVersion === OFFLINE_NPM_ADVISORY_REVISION_IDENTITY_SCHEMA_VERSION
  );
}

function projectRevision(row: RevisionRow): AdvisoryRevisionProjection {
  if (isStoredOfflineRevision(row)) {
    return projectOfflineRevision(row);
  }
  if (row.sourceProvenance !== null || row.explicitVersions.length > 0) {
    throw new AdvisoryRevisionRowError();
  }
  if (row.ecosystem !== 'npm') {
    throw new AdvisoryRevisionRowError();
  }
  const identity = identityFromRow(row);
  if (advisoryFamilyDigest(identity.source, row.advisoryId) !== row.familyDigest) {
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
        sourceClassification: session15Origin(alias.sourceClassification),
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
  const source = session15Source(row.source);
  const origin = session15Origin(row.origin);
  const retrievalClassification = session15Retrieval(row.retrievalClassification);
  return {
    inspectionSchemaVersion: ADVISORY_REVISION_INSPECTION_SCHEMA_VERSION,
    revisionId: row.id,
    familyId: row.advisoryFamilyId,
    source,
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
    origin,
    trustClassification: row.trustClassification,
    revisionDisposition: row.revisionDisposition,
    withdrawalClassification: row.withdrawalClassification,
    quarantineClassification: row.quarantineClassification,
    supersedesRevisionDigest: row.supersedesRevisionDigest,
    retrievalClassification,
    providerGeneration: row.providerGeneration,
    retrievalPolicyId: row.retrievalPolicyId,
    revisionSchemaVersion: row.revisionSchemaVersion,
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

type StoredRangeRow = {
  readonly rangeOrdinal: number;
  readonly events: readonly {
    readonly eventOrdinal: number;
    readonly name: 'introduced' | 'fixed' | 'last_affected' | 'limit';
    readonly value: string;
  }[];
};

function eventName(value: string): 'introduced' | 'fixed' | 'last_affected' | 'limit' | null {
  if (
    value === 'introduced' ||
    value === 'fixed' ||
    value === 'last_affected' ||
    value === 'limit'
  ) {
    return value;
  }
  return null;
}

function storedRangeRows(row: RevisionRow): readonly StoredRangeRow[] | null {
  const ranges: Array<{
    rangeOrdinal: number;
    events: Array<{
      eventOrdinal: number;
      name: 'introduced' | 'fixed' | 'last_affected' | 'limit';
      value: string;
    }>;
  }> = [];
  for (const event of row.rangeEvents) {
    const name = eventName(event.eventName);
    const current = ranges[ranges.length - 1];
    if (name === null) {
      return null;
    }
    if (current === undefined || current.rangeOrdinal !== event.rangeOrdinal) {
      if (event.eventOrdinal !== 0 || event.rangeOrdinal !== ranges.length) {
        return null;
      }
      ranges.push({
        rangeOrdinal: event.rangeOrdinal,
        events: [{ eventOrdinal: event.eventOrdinal, name, value: event.eventValue }],
      });
      continue;
    }
    if (current.events.length !== event.eventOrdinal) {
      return null;
    }
    current.events.push({ eventOrdinal: event.eventOrdinal, name, value: event.eventValue });
  }
  return ranges;
}

function storedVersionRows(
  row: RevisionRow,
): readonly { ordinal: number; versionText: string }[] | null {
  const versions: Array<{ ordinal: number; versionText: string }> = [];
  for (const version of row.explicitVersions) {
    if (version.ordinal !== versions.length || version.versionText.length === 0) {
      return null;
    }
    versions.push({ ordinal: version.ordinal, versionText: version.versionText });
  }
  return versions;
}

function sameRangeRows(
  left: readonly StoredRangeRow[],
  right: ParsedAdvisoryRevisionCommand['rangeRows'],
): boolean {
  if (left.length !== right.length) {
    return false;
  }
  for (let index = 0; index < left.length; index += 1) {
    const stored = left[index];
    const command = right[index];
    if (
      stored === undefined ||
      command === undefined ||
      stored.rangeOrdinal !== command.rangeOrdinal ||
      stored.events.length !== command.events.length
    ) {
      return false;
    }
    for (let eventIndex = 0; eventIndex < stored.events.length; eventIndex += 1) {
      const storedEvent = stored.events[eventIndex];
      const commandEvent = command.events[eventIndex];
      if (
        storedEvent === undefined ||
        commandEvent === undefined ||
        storedEvent.eventOrdinal !== commandEvent.eventOrdinal ||
        storedEvent.name !== commandEvent.name ||
        storedEvent.value !== commandEvent.value
      ) {
        return false;
      }
    }
  }
  return true;
}

function sameVersionRows(
  left: readonly { readonly ordinal: number; readonly versionText: string }[],
  right: ParsedAdvisoryRevisionCommand['explicitVersionRows'],
): boolean {
  if (left.length !== right.length) {
    return false;
  }
  for (let index = 0; index < left.length; index += 1) {
    const stored = left[index];
    const command = right[index];
    if (
      stored === undefined ||
      command === undefined ||
      stored.ordinal !== command.ordinal ||
      stored.versionText !== command.versionText
    ) {
      return false;
    }
  }
  return true;
}

function offlineInstants(row: RevisionRow): {
  readonly modifiedAt: string;
  readonly publishedAt: string | null;
  readonly withdrawnAt: string | null;
  readonly rawContentSha256: string;
} {
  const provenance = row.sourceProvenance;
  if (provenance === null) {
    throw new AdvisoryRevisionRowError();
  }
  return {
    modifiedAt: provenance.modifiedAt.toISOString(),
    publishedAt: provenance.publishedAt === null ? null : provenance.publishedAt.toISOString(),
    withdrawnAt: provenance.withdrawnAt === null ? null : provenance.withdrawnAt.toISOString(),
    rawContentSha256: provenance.rawContentSha256,
  };
}

function projectOfflineRevision(row: RevisionRow): AdvisoryRevisionProjection {
  if (row.ecosystem !== 'npm' || row.sourceProvenance === null) {
    throw new AdvisoryRevisionRowError();
  }
  assertRevisionLifecycle(row);
  const provenance = row.sourceProvenance;
  const instants = offlineInstants(row);
  const ranges = storedRangeRows(row);
  const versions = storedVersionRows(row);
  if (ranges === null || versions === null || (ranges.length === 0 && versions.length === 0)) {
    throw new AdvisoryRevisionRowError();
  }
  if (
    provenance.source !== row.source ||
    provenance.advisoryId !== row.advisoryId ||
    provenance.packageIdentityKey !== row.packageIdentityKey ||
    provenance.parserId !== row.parserId ||
    provenance.parserResourcePolicy !== row.parserResourcePolicy ||
    provenance.advisorySchemaVersion !== row.advisorySchemaVersion ||
    provenance.advisorySchemaCommit !== row.advisorySchemaCommit ||
    provenance.sourceLicenseRegistryVersion !== row.sourceLicenseRegistryVersion ||
    provenance.normalizationIdentity !== OFFLINE_NPM_OSV_NORMALIZATION_IDENTITY ||
    provenance.licenseAdmissionReason !== OFFLINE_NPM_LICENSE_ADMISSION_REASON ||
    (row.withdrawalClassification === 'withdrawn' && instants.withdrawnAt === null) ||
    (row.withdrawalClassification !== 'withdrawn' && instants.withdrawnAt !== null)
  ) {
    throw new AdvisoryRevisionRowError();
  }
  const source = session15Source(row.source);
  const origin = session15Origin(row.origin);
  if (advisoryFamilyDigest(source, row.advisoryId) !== row.familyDigest) {
    throw new AdvisoryRevisionRowError();
  }
  if (
    session14RangeFingerprint(
      ranges.map((range) => ({
        type: 'SEMVER' as const,
        events: range.events.map((event) => ({ name: event.name, value: event.value })),
      })),
      versions.map((version) => version.versionText),
    ) !== row.session14RangeFingerprint
  ) {
    throw new AdvisoryRevisionRowError();
  }
  if (
    offlineNpmAdvisoryRevisionDigest({
      familyDigest: row.familyDigest,
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
      modifiedAt: instants.modifiedAt,
      publishedAt: instants.publishedAt,
      withdrawnAt: instants.withdrawnAt,
      rawContentSha256: instants.rawContentSha256,
    }) !== row.revisionDigest
  ) {
    throw new AdvisoryRevisionRowError();
  }
  const aliases = row.aliases.map((alias) => ({
    ordinal: alias.ordinal,
    aliasType: alias.aliasType,
    aliasValue: alias.aliasValue,
    reviewClassification: alias.reviewClassification,
    sourceClassification: session15Origin(alias.sourceClassification),
    replayFingerprint: alias.replayFingerprint,
  }));
  if (
    offlineNpmAdvisoryRevisionReplayFingerprint({
      source,
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
      origin,
      trustClassification: row.trustClassification,
      revisionDisposition: row.revisionDisposition,
      withdrawalClassification: row.withdrawalClassification,
      quarantineClassification: row.quarantineClassification,
      supersedesRevisionDigest: row.supersedesRevisionDigest,
      retrievalClassification: 'local_not_retrieved',
      retrievalEvidenceId: row.retrievalEvidenceId,
      ecosystem: 'npm',
      packageIdentityKey: row.packageIdentityKey,
      evaluatorVersion: row.evaluatorVersion,
      matchingPolicyId: row.matchingPolicyId,
      aliases,
      familyDigest: row.familyDigest,
      revisionDigest: row.revisionDigest,
      modifiedAt: instants.modifiedAt,
      publishedAt: instants.publishedAt,
      withdrawnAt: instants.withdrawnAt,
      rawContentSha256: instants.rawContentSha256,
    }) !== row.replayFingerprint
  ) {
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
        sourceClassification: session15Origin(alias.sourceClassification),
      })
    ) {
      throw new AdvisoryRevisionRowError();
    }
  }
  if (
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
    source,
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
    origin,
    trustClassification: row.trustClassification,
    revisionDisposition: row.revisionDisposition,
    withdrawalClassification: row.withdrawalClassification,
    quarantineClassification: row.quarantineClassification,
    supersedesRevisionDigest: row.supersedesRevisionDigest,
    retrievalClassification: 'local_not_retrieved',
    providerGeneration: row.providerGeneration,
    retrievalPolicyId: row.retrievalPolicyId,
    revisionSchemaVersion: row.revisionSchemaVersion,
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

function offlineRevisionAgrees(
  row: RevisionRow,
  command: ParsedAdvisoryRevisionCommand,
  purl: string | null,
): boolean {
  if (
    !isStoredOfflineRevision(row) ||
    command.modifiedAt === null ||
    command.rawContentSha256 === null
  ) {
    return false;
  }
  projectOfflineRevision(row);
  const instants = offlineInstants(row);
  const ranges = storedRangeRows(row);
  const versions = storedVersionRows(row);
  if (ranges === null || versions === null) {
    throw new AdvisoryRevisionRowError();
  }
  const source = session15Source(row.source);
  const origin = session15Origin(row.origin);
  const agreement = classifyOfflineNpmAdvisoryRevisionAgreement(
    {
      source,
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
      origin,
      trustClassification: row.trustClassification,
      revisionDisposition: row.revisionDisposition,
      withdrawalClassification: row.withdrawalClassification,
      quarantineClassification: row.quarantineClassification,
      supersedesRevisionDigest: row.supersedesRevisionDigest,
      retrievalClassification: 'local_not_retrieved',
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
        sourceClassification: session15Origin(alias.sourceClassification),
        replayFingerprint: alias.replayFingerprint,
      })),
      familyDigest: row.familyDigest,
      revisionDigest: row.revisionDigest,
      replayFingerprint: row.replayFingerprint,
      modifiedAt: instants.modifiedAt,
      publishedAt: instants.publishedAt,
      withdrawnAt: instants.withdrawnAt,
      rawContentSha256: instants.rawContentSha256,
    },
    {
      ...command,
      modifiedAt: command.modifiedAt,
      publishedAt: command.publishedAt,
      withdrawnAt: command.withdrawnAt,
      rawContentSha256: command.rawContentSha256,
    },
  );
  return (
    agreement === 'agree' &&
    (row.sourceProvenance?.purl ?? null) === purl &&
    sameRangeRows(ranges, command.rangeRows) &&
    sameVersionRows(versions, command.explicitVersionRows)
  );
}

function recordedCounts(inserts: number): {
  readonly inserts: number;
  readonly updates: 0;
  readonly deletes: 0;
  readonly timestampChanges: 0;
  readonly stateChanges: 0;
  readonly parserCalls: 0;
  readonly providerCalls: 0;
} {
  return {
    inserts,
    updates: 0,
    deletes: 0,
    timestampChanges: 0,
    stateChanges: 0,
    parserCalls: 0,
    providerCalls: 0,
  };
}

function rejectedFile(code: AdvisoryRevisionRejectionCode): PersistOfflineNpmAdvisoryFileResult {
  return { kind: 'rejected', code, counts: ADVISORY_REVISION_ZERO_COUNTS };
}

function fileResultFromRevisionDecision(
  result: PersistAdvisoryRevisionResult,
): PersistOfflineNpmAdvisoryFileResult {
  if (result.kind === 'immutable_conflict') {
    return { kind: 'immutable_conflict', counts: ADVISORY_REVISION_ZERO_COUNTS };
  }
  if (result.kind === 'rejected') {
    return rejectedFile(result.code);
  }
  return rejectedFile('internal_failure');
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
    if (parsed.command.normalizationIdentity !== null) {
      return rejectedRevision('invalid_command');
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
            packageIdentityKey: true,
            family: { select: { source: true, advisoryId: true } },
          },
        });
        if (
          prior === null ||
          prior.family.source !== parsed.command.source ||
          prior.family.advisoryId !== parsed.command.advisoryId ||
          prior.packageIdentityKey !== parsed.command.packageIdentityKey
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

  public async persistOfflineNpmAdvisoryFile(
    command: unknown,
  ): Promise<PersistOfflineNpmAdvisoryFileResult> {
    const parsed = parseOfflineNpmAdvisoryFileCommand(command);
    if (!parsed.accepted) {
      return rejectedFile(parsed.code);
    }
    try {
      return await this.client.$transaction((tx) => this.writeOfflineFile(tx, parsed.command), {
        maxWait: 5_000,
        timeout: OFFLINE_NPM_FILE_TRANSACTION_TIMEOUT_MS,
      });
    } catch (error) {
      if (error instanceof AdvisoryRevisionDecision) {
        return fileResultFromRevisionDecision(error.result);
      }
      if (error instanceof AdvisoryRevisionRowError) {
        return rejectedFile('malformed_persisted_state');
      }
      if (isAdvisoryRevisionUniqueViolation(error)) {
        return this.reloadOfflineFile(parsed.command);
      }
      return rejectedFile(translateAdvisoryRevisionPersistenceFailure(error));
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
      const family = await this.ensureFamily(tx, command);
      let supersedesId: string | null = null;
      if (command.supersedesRevisionDigest !== SUPERSESSION_NONE) {
        const prior = await tx.advisoryRevision.findUnique({
          where: { revisionDigest: command.supersedesRevisionDigest },
          select: { id: true, advisoryFamilyId: true, packageIdentityKey: true },
        });
        if (
          prior === null ||
          prior.advisoryFamilyId !== family.id ||
          prior.packageIdentityKey !== command.packageIdentityKey
        ) {
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
              sourceClassification: session15Origin(alias.sourceClassification),
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
          inserts: family.inserted + 1 + command.aliasCount,
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

  private async ensureFamily(
    tx: Prisma.TransactionClient,
    command: ParsedAdvisoryRevisionCommand,
  ): Promise<{ readonly id: string; readonly inserted: number }> {
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
    let inserted = 0;
    if (family === null) {
      inserted = await tx.$executeRaw`
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
    return { id: family.id, inserted };
  }

  private async writeOfflineFile(
    tx: Prisma.TransactionClient,
    command: ParsedOfflineNpmAdvisoryFileCommand,
  ): Promise<PersistOfflineNpmAdvisoryFileResult> {
    const first = command.revisions[0];
    if (first === undefined) {
      return rejectedFile('invalid_command');
    }
    const batch = await tx.offlineAdvisoryImportBatch.findUnique({
      where: { id: command.batchId },
      select: { id: true, retrievedAt: true, sourceLicenseRegistryVersion: true },
    });
    if (
      batch === null ||
      batch.sourceLicenseRegistryVersion !== OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER
    ) {
      throw new AdvisoryRevisionDecision(rejectedRevision('foreign_key_violation'));
    }
    await tx.$queryRaw`
      SELECT 1::int AS locked
      FROM (
        SELECT pg_advisory_xact_lock(
          hashtextextended(
            ${`${OFFLINE_IMPORT_LOCK_PREFIX}${first.command.source}:${first.command.advisoryId}`},
            0
          )
        )
      ) AS taken
    `;
    const family = await this.ensureFamily(tx, first.command);
    await tx.$queryRaw`
      SELECT "id"
      FROM "advisory_family"
      WHERE "id" = ${family.id}::uuid
      FOR UPDATE
    `;
    const projections: AdvisoryRevisionProjection[] = [];
    let inserts = family.inserted;
    let accepted = 0;
    let skipped = 0;
    for (const revision of command.revisions) {
      const existing = await this.findRevision(tx, revision.command.revisionDigest);
      if (existing !== null) {
        if (!offlineRevisionAgrees(existing, revision.command, revision.purl)) {
          throw new AdvisoryRevisionDecision({
            kind: 'immutable_conflict',
            counts: ADVISORY_REVISION_ZERO_COUNTS,
          });
        }
        projections.push(projectOfflineRevision(existing));
        skipped += 1;
        continue;
      }
      const created = await this.insertOfflineRevision(
        tx,
        revision,
        family.id,
        batch.retrievedAt,
        command.batchId,
      );
      projections.push(created.projection);
      inserts += created.inserts;
      accepted += 1;
    }
    const familyId = projections[0]?.familyId;
    if (familyId === undefined) {
      throw new AdvisoryRevisionRowError();
    }
    if (accepted === 0) {
      return {
        kind: 'already_applied',
        familyId,
        projections,
        counts: ADVISORY_REVISION_ZERO_COUNTS,
        auditEventAdded: false,
      };
    }
    const rawContentSha256 = first.command.rawContentSha256;
    if (rawContentSha256 === null) {
      throw new AdvisoryRevisionDecision(rejectedRevision('invalid_command'));
    }
    const reasonCodes = ['recorded'];
    if (skipped > 0) {
      reasonCodes.push('already_applied');
      reasonCodes.sort();
    }
    const existingAudit = await tx.auditEvent.findFirst({
      where: {
        organizationId: null,
        action: OFFLINE_NPM_FILE_AUDIT_ACTION,
        subjectType: OFFLINE_NPM_FILE_AUDIT_SUBJECT,
        subjectId: familyId,
        correlationId: command.correlationId,
      },
      select: { id: true },
    });
    if (existingAudit !== null) {
      throw new AdvisoryRevisionDecision({
        kind: 'immutable_conflict',
        counts: ADVISORY_REVISION_ZERO_COUNTS,
      });
    }
    await tx.auditEvent.create({
      data: {
        actorType: 'system',
        action: OFFLINE_NPM_FILE_AUDIT_ACTION,
        subjectType: OFFLINE_NPM_FILE_AUDIT_SUBJECT,
        subjectId: familyId,
        correlationId: command.correlationId,
        schemaVersion: JSON_SCHEMA_VERSION_V1,
        retentionCategory: 'security',
        payload: asJsonObject(
          {
            schemaVersion: JSON_SCHEMA_VERSION_V1,
            registryId: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
            rawContentSha256,
            byteLength: command.byteLength,
            advisoryIds: [first.command.advisoryId],
            reasonCodes,
            counts: {
              accepted,
              skipped,
              rejected: 0,
              failed: 0,
            },
          },
          'offline npm import audit',
        ),
      },
    });
    return {
      kind: 'recorded',
      familyId,
      projections,
      counts: recordedCounts(inserts + 1),
      auditEventAdded: true,
    };
  }

  private async insertOfflineRevision(
    tx: Prisma.TransactionClient,
    revision: ParsedOfflineNpmAdvisoryFileCommand['revisions'][number],
    familyId: string,
    retrievedAt: Date,
    batchId: string,
  ): Promise<{ readonly projection: AdvisoryRevisionProjection; readonly inserts: number }> {
    const command = revision.command;
    if (
      command.modifiedAt === null ||
      command.rawContentSha256 === null ||
      command.normalizationIdentity === null
    ) {
      throw new AdvisoryRevisionDecision(rejectedRevision('invalid_command'));
    }
    const tips = await tx.$queryRaw<Array<{ id: string; revision_digest: string }>>`
      SELECT revision."id" AS "id", revision."revision_digest" AS "revision_digest"
      FROM "advisory_revision" revision
      WHERE revision."advisory_family_id" = ${familyId}::uuid
        AND revision."package_identity_key" = ${command.packageIdentityKey}
        AND NOT EXISTS (
          SELECT 1
          FROM "advisory_revision" successor
          WHERE successor."advisory_family_id" = revision."advisory_family_id"
            AND successor."package_identity_key" = revision."package_identity_key"
            AND successor."supersedes_advisory_revision_id" = revision."id"
        )
    `;
    if (tips.length > 1) {
      throw new AdvisoryRevisionDecision(rejectedRevision('malformed_persisted_state'));
    }
    const tip = tips[0];
    if (tip === undefined && command.supersedesRevisionDigest !== SUPERSESSION_NONE) {
      throw new AdvisoryRevisionDecision(rejectedRevision('supersession_rejected'));
    }
    if (tip !== undefined && command.supersedesRevisionDigest !== tip.revision_digest) {
      throw new AdvisoryRevisionDecision(rejectedRevision('supersession_rejected'));
    }
    const supersedesId = tip === undefined ? null : tip.id;
    const rangeEvents = command.rangeRows.flatMap((range) =>
      range.events.map((event) => ({
        rangeOrdinal: range.rangeOrdinal,
        eventOrdinal: event.eventOrdinal,
        eventName: event.name,
        eventValue: event.value,
      })),
    );
    const created = await tx.advisoryRevision.create({
      data: {
        revisionSchemaVersion: command.revisionSchemaVersion,
        advisoryFamilyId: familyId,
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
            sourceClassification: session15Origin(alias.sourceClassification),
            reviewClassification: alias.reviewClassification,
            replayFingerprint: alias.replayFingerprint,
          })),
        },
        ...(rangeEvents.length > 0 ? { rangeEvents: { create: rangeEvents } } : {}),
        ...(command.explicitVersionRows.length > 0
          ? {
              explicitVersions: {
                create: command.explicitVersionRows.map((version) => ({
                  ordinal: version.ordinal,
                  versionText: version.versionText,
                })),
              },
            }
          : {}),
        sourceProvenance: {
          create: {
            source: command.source,
            sourceLicenseRegistryVersion: command.sourceLicenseRegistryVersion,
            advisoryId: command.advisoryId,
            packageIdentityKey: command.packageIdentityKey,
            rawContentSha256: command.rawContentSha256,
            parserId: command.parserId,
            parserResourcePolicy: command.parserResourcePolicy,
            advisorySchemaVersion: command.advisorySchemaVersion,
            advisorySchemaCommit: command.advisorySchemaCommit,
            normalizationIdentity: command.normalizationIdentity,
            retrievedAt,
            modifiedAt: new Date(command.modifiedAt),
            publishedAt: command.publishedAt === null ? null : new Date(command.publishedAt),
            withdrawnAt: command.withdrawnAt === null ? null : new Date(command.withdrawnAt),
            purl: revision.purl,
            licenseAdmissionReason: OFFLINE_NPM_LICENSE_ADMISSION_REASON,
            offlineAdvisoryImportBatchId: batchId,
          },
        },
      },
      select: REVISION_SELECT,
    });
    return {
      projection: projectOfflineRevision(created),
      inserts: 1 + command.aliasCount + rangeEvents.length + command.explicitVersionRows.length + 1,
    };
  }

  private async reloadOfflineFile(
    command: ParsedOfflineNpmAdvisoryFileCommand,
  ): Promise<PersistOfflineNpmAdvisoryFileResult> {
    const projections: AdvisoryRevisionProjection[] = [];
    for (const revision of command.revisions) {
      const row = await this.findRevision(this.client, revision.command.revisionDigest);
      if (row === null || !offlineRevisionAgrees(row, revision.command, revision.purl)) {
        return { kind: 'immutable_conflict', counts: ADVISORY_REVISION_ZERO_COUNTS };
      }
      projections.push(projectOfflineRevision(row));
    }
    const familyId = projections[0]?.familyId;
    if (familyId === undefined) {
      return rejectedFile('internal_failure');
    }
    return {
      kind: 'already_applied',
      familyId,
      projections,
      counts: ADVISORY_REVISION_ZERO_COUNTS,
      auditEventAdded: false,
    };
  }
}
