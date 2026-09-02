import {
  INTELLIGENCE_CATALOG_VERSION_MAX_LENGTH,
  INTELLIGENCE_PROVIDER_LIST_ORDER,
  INTELLIGENCE_PROVIDER_STATUS_CACHE_CONTROL,
  INTELLIGENCE_PROVIDER_STATUS_PATH,
  INTELLIGENCE_PROVIDERS_PATH,
  UTC_INSTANT_PATTERN,
  intelligenceProviderDisplayNames,
  intelligenceProviderHealthStatuses,
  intelligenceProviderImplementationStatuses,
  intelligenceProviders,
  intelligencePublicFailureCodes,
  type IntelligenceProvider,
} from '@patchpilot/domain';
import { z } from 'zod';

export {
  INTELLIGENCE_PROVIDER_STATUS_CACHE_CONTROL,
  INTELLIGENCE_PROVIDER_STATUS_PATH,
  INTELLIGENCE_PROVIDERS_PATH,
};

const utcTimestampSchema = z
  .string()
  .regex(UTC_INSTANT_PATTERN, { message: 'timestamp must be UTC ISO 8601' });

export const intelligenceProviderSchema = z.enum(intelligenceProviders);
export const intelligenceProviderImplementationStatusSchema = z.enum(
  intelligenceProviderImplementationStatuses,
);
export const intelligenceProviderHealthStatusSchema = z.enum(intelligenceProviderHealthStatuses);
export const intelligencePublicFailureCodeSchema = z.enum(intelligencePublicFailureCodes);

export const intelligenceProviderParamSchema = z.strictObject({
  provider: intelligenceProviderSchema,
});

const publicProviderStatusBaseSchema = z.strictObject({
  provider: intelligenceProviderSchema,
  displayName: z.string().min(1).max(128),
  runtimeEnabled: z.boolean(),
  implementationStatus: intelligenceProviderImplementationStatusSchema,
  healthStatus: intelligenceProviderHealthStatusSchema,
  stale: z.boolean(),
  staleThresholdSeconds: z.number().int().positive(),
  lastSuccessfulSyncAt: utcTimestampSchema.nullable(),
  lastAttemptAt: utcTimestampSchema.nullable(),
  latestAcceptedCatalogVersion: z
    .string()
    .min(1)
    .max(INTELLIGENCE_CATALOG_VERSION_MAX_LENGTH)
    .nullable(),
  latestAcceptedCatalogReleasedAt: utcTimestampSchema.nullable(),
  currentEntryCount: z.number().int().nonnegative().nullable(),
  lastSafeFailureCode: intelligencePublicFailureCodeSchema.nullable(),
  lastFailureAt: utcTimestampSchema.nullable(),
});

function failWithMessage(ctx: z.RefinementCtx, message: string): typeof z.NEVER {
  ctx.addIssue({ code: 'custom', message });
  return z.NEVER;
}

function assertPublicProviderStatus(
  value: z.infer<typeof publicProviderStatusBaseSchema>,
  ctx: z.RefinementCtx,
): void {
  if (value.provider === 'osv') {
    if (value.implementationStatus !== 'deferred' || value.healthStatus !== 'deferred') {
      failWithMessage(ctx, 'OSV must be deferred and must not appear healthy or synchronized.');
    }
    if (value.runtimeEnabled || value.stale) {
      failWithMessage(ctx, 'OSV must not be runtime-enabled or stale.');
    }
    if (
      value.lastSuccessfulSyncAt !== null ||
      value.lastAttemptAt !== null ||
      value.latestAcceptedCatalogVersion !== null ||
      value.latestAcceptedCatalogReleasedAt !== null ||
      value.currentEntryCount !== null ||
      value.lastSafeFailureCode !== null ||
      value.lastFailureAt !== null
    ) {
      failWithMessage(ctx, 'OSV must not expose accepted catalog freshness or failure fields.');
    }
    return;
  }

  if (value.implementationStatus === 'disabled') {
    if (value.healthStatus !== 'disabled' || value.stale || value.runtimeEnabled) {
      failWithMessage(ctx, 'Disabled providers are not stale, current, or runtime-enabled.');
    }
    assertAcceptedCatalogFields(value, ctx, value.lastSuccessfulSyncAt !== null);
    return;
  }

  if (value.implementationStatus === 'deferred') {
    failWithMessage(ctx, 'cisa_kev is not a deferred Session 9 provider.');
    return;
  }

  if (value.lastSuccessfulSyncAt === null) {
    if (
      value.healthStatus === 'current' ||
      value.healthStatus === 'stale' ||
      value.healthStatus === 'degraded' ||
      value.stale
    ) {
      failWithMessage(
        ctx,
        'No accepted KEV generation means status is never current, stale, or degraded.',
      );
    }
    assertAcceptedCatalogFields(value, ctx, false);
    if (value.healthStatus !== 'never_synchronized') {
      failWithMessage(ctx, 'Available KEV without an accepted generation is never_synchronized.');
    }
    return;
  }

  if (
    value.healthStatus !== 'current' &&
    value.healthStatus !== 'stale' &&
    value.healthStatus !== 'degraded'
  ) {
    failWithMessage(ctx, 'Accepted KEV generation status is current, stale, or degraded.');
  }
  if (value.stale !== (value.healthStatus === 'stale')) {
    failWithMessage(ctx, 'stale must be true only when healthStatus is stale.');
  }
  if (value.healthStatus === 'degraded') {
    if (value.lastFailureAt === null || value.lastSafeFailureCode === null) {
      failWithMessage(
        ctx,
        'Degraded KEV status requires a mapped public failure code and timestamp.',
      );
    }
  }
  assertAcceptedCatalogFields(value, ctx, true);
}

function assertAcceptedCatalogFields(
  value: z.infer<typeof publicProviderStatusBaseSchema>,
  ctx: z.RefinementCtx,
  required: boolean,
): void {
  const hasCatalog =
    value.latestAcceptedCatalogVersion !== null ||
    value.latestAcceptedCatalogReleasedAt !== null ||
    value.currentEntryCount !== null;
  if (required) {
    if (
      value.latestAcceptedCatalogVersion === null ||
      value.latestAcceptedCatalogReleasedAt === null ||
      value.currentEntryCount === null
    ) {
      failWithMessage(
        ctx,
        'Accepted generation requires catalog version, release timestamp, and entry count.',
      );
    }
    return;
  }
  if (hasCatalog) {
    failWithMessage(ctx, 'Absent accepted generation requires nullable catalog fields.');
  }
}

export const intelligenceProviderStatusSchema = publicProviderStatusBaseSchema.superRefine(
  assertPublicProviderStatus,
);

export const intelligenceProviderListResponseSchema = z
  .strictObject({
    providers: z.array(intelligenceProviderStatusSchema).length(2),
  })
  .superRefine((value, ctx) => {
    const names = value.providers.map((provider) => provider.provider);
    if (
      names.length !== 2 ||
      names[0] !== INTELLIGENCE_PROVIDER_LIST_ORDER[0] ||
      names[1] !== INTELLIGENCE_PROVIDER_LIST_ORDER[1] ||
      new Set(names).size !== names.length
    ) {
      ctx.addIssue({
        code: 'custom',
        message: 'Provider list must contain cisa_kev then osv exactly once.',
      });
    }
  });

export const intelligenceProviderDetailResponseSchema = intelligenceProviderStatusSchema;

export type IntelligenceProviderContract = z.infer<typeof intelligenceProviderSchema>;
export type IntelligenceProviderImplementationStatusContract = z.infer<
  typeof intelligenceProviderImplementationStatusSchema
>;
export type IntelligenceProviderHealthStatusContract = z.infer<
  typeof intelligenceProviderHealthStatusSchema
>;
export type IntelligencePublicFailureCodeContract = z.infer<
  typeof intelligencePublicFailureCodeSchema
>;
export type IntelligenceProviderParam = z.infer<typeof intelligenceProviderParamSchema>;
export type IntelligenceProviderStatus = z.infer<typeof intelligenceProviderStatusSchema>;
export type IntelligenceProviderListResponse = z.infer<
  typeof intelligenceProviderListResponseSchema
>;
export type IntelligenceProviderDetailResponse = z.infer<
  typeof intelligenceProviderDetailResponseSchema
>;

export function intelligenceDisplayName(provider: IntelligenceProvider): string {
  return intelligenceProviderDisplayNames[provider];
}

export function expectedOsvPublicStatus(staleThresholdSeconds: number): IntelligenceProviderStatus {
  return intelligenceProviderStatusSchema.parse({
    provider: 'osv',
    displayName: intelligenceProviderDisplayNames.osv,
    runtimeEnabled: false,
    implementationStatus: 'deferred',
    healthStatus: 'deferred',
    stale: false,
    staleThresholdSeconds,
    lastSuccessfulSyncAt: null,
    lastAttemptAt: null,
    latestAcceptedCatalogVersion: null,
    latestAcceptedCatalogReleasedAt: null,
    currentEntryCount: null,
    lastSafeFailureCode: null,
    lastFailureAt: null,
  });
}

export function expectedDisabledKevPublicStatus(
  staleThresholdSeconds: number,
): IntelligenceProviderStatus {
  return intelligenceProviderStatusSchema.parse({
    provider: 'cisa_kev',
    displayName: intelligenceProviderDisplayNames.cisa_kev,
    runtimeEnabled: false,
    implementationStatus: 'disabled',
    healthStatus: 'disabled',
    stale: false,
    staleThresholdSeconds,
    lastSuccessfulSyncAt: null,
    lastAttemptAt: null,
    latestAcceptedCatalogVersion: null,
    latestAcceptedCatalogReleasedAt: null,
    currentEntryCount: null,
    lastSafeFailureCode: null,
    lastFailureAt: null,
  });
}
