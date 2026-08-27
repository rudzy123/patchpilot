/**
 * JSON documents stored in PostgreSQL. Each document includes `schemaVersion`.
 * Application code must validate against the matching version before trusting fields.
 * These shapes are persistence-neutral; they are not Prisma types.
 */

export const JSON_SCHEMA_VERSION_V1 = 1;

export type VersionedJsonDocument = {
  schemaVersion: number;
};

export type RiskPolicyDefinitionJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  policyKey: string;
  factorCatalog: ReadonlyArray<{
    factorId: string;
    description: string;
  }>;
  weights: Readonly<Record<string, number>>;
};

export type RiskCalculationFactorsJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  factors: ReadonlyArray<{
    factorId: string;
    inputKind: 'observed' | 'unavailable';
    rawValue: string | number | boolean | null;
    contribution: number;
    notes: string;
  }>;
};

export type RiskCalculationResultJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  priority: number;
  priorityBand: string;
  dueDateRecommendationDays: number;
  escalationRecommendation: boolean | string;
};

export type AuditPayloadJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  metadata: Readonly<Record<string, string | number | boolean | null>>;
};

export type OutboxPayloadJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  ids: Readonly<Record<string, string>>;
  metadata: Readonly<Record<string, string | number | boolean | null>>;
};

export type EvidenceMetadataJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  metadata: Readonly<Record<string, string | number | boolean | null>>;
};

export type VulnerabilityNormalizedJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  summary: string | null;
  severity: string | null;
  affectedPackages: ReadonlyArray<{
    ecosystem: string;
    namespace: string | null;
    name: string;
    versionRange: string | null;
  }>;
};

export type FindingObservationEvidenceJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  metadata: Readonly<Record<string, string | number | boolean | null>>;
};

export type IdempotencyResponseJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  metadata: Readonly<Record<string, string | number | boolean | null>>;
};

export type IntegrationConfigJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  refreshIntervalSeconds: number | null;
  endpointAllowlist: ReadonlyArray<string>;
};
