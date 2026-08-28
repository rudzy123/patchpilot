import {
  ASSET_IDENTIFIER_MAX_COUNT,
  ASSET_LIST_DEFAULT_LIMIT,
  ASSET_LIST_MAX_LIMIT,
  ASSET_LIST_MIN_LIMIT,
  ASSET_OWNER_MAX_COUNT,
  ASSET_RAW_TEXT_MAX_LENGTH,
  ASSET_TAG_MAX_COUNT,
  DEFAULT_ASSET_LIFECYCLE_LIST_FILTER,
  MAX_PAGE_SIZE,
  MIN_PAGE_SIZE,
  assetDataClassifications,
  assetOwnerRoles,
  assetTypes,
  businessCriticalities,
  decodeAssetListCursor,
  encodeAssetListCursor,
  environmentSensitivityClasses,
  internetExposures,
  membershipRoles,
  normalizeAssetNamePrefix,
  normalizeAssetTag,
  normalizeCreateAssetCommand,
  normalizeUpdateAssetCommand,
  type AssetListQuery,
  type NormalizedCreateAssetCommand,
  type NormalizedUpdateAssetCommand,
  type PageRequest,
} from '@patchpilot/domain';
import { z } from 'zod';

const utcTimestampSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/, {
  message: 'timestamp must be UTC ISO 8601',
});

export const assetTypeSchema = z.enum(assetTypes);
export const businessCriticalitySchema = z.enum(businessCriticalities);
export const internetExposureSchema = z.enum(internetExposures);
export const assetDataClassificationSchema = z.enum(assetDataClassifications);
export const assetOwnerRoleSchema = z.enum(assetOwnerRoles);
export const assetLifecycleListFilterSchema = z.enum(['active', 'archived', 'all']);
export const environmentSensitivityClassSchema = z.enum(environmentSensitivityClasses);

export const membershipAssetOwnerAssignmentSchema = z.strictObject({
  kind: z.literal('membership'),
  membershipId: z.uuid(),
  role: assetOwnerRoleSchema,
});

export const teamAssetOwnerAssignmentSchema = z.strictObject({
  kind: z.literal('team'),
  teamId: z.uuid(),
  role: assetOwnerRoleSchema,
});

export const assetOwnerAssignmentSchema = z.discriminatedUnion('kind', [
  membershipAssetOwnerAssignmentSchema,
  teamAssetOwnerAssignmentSchema,
]);

export const assetTagSchema = z.string().max(ASSET_RAW_TEXT_MAX_LENGTH);

export const assetExternalIdentifierSchema = z.strictObject({
  namespace: z.string().max(ASSET_RAW_TEXT_MAX_LENGTH),
  identifier: z.string().max(ASSET_RAW_TEXT_MAX_LENGTH),
});

const expectedVersionSchema = z.number().int().min(1);

function failWithMessage(ctx: z.RefinementCtx, message: string): typeof z.NEVER {
  ctx.addIssue({ code: 'custom', message });
  return z.NEVER;
}

export const createAssetRequestSchema = z
  .strictObject({
    name: z.string().max(ASSET_RAW_TEXT_MAX_LENGTH),
    assetType: assetTypeSchema,
    environmentId: z.uuid().optional(),
    owningTeamId: z.uuid().optional(),
    description: z.string().max(ASSET_RAW_TEXT_MAX_LENGTH).optional(),
    businessCriticality: businessCriticalitySchema.optional(),
    internetExposure: internetExposureSchema.optional(),
    dataClassification: assetDataClassificationSchema.optional(),
    repositoryUrl: z.string().max(ASSET_RAW_TEXT_MAX_LENGTH).optional(),
    deploymentContext: z.string().max(ASSET_RAW_TEXT_MAX_LENGTH).optional(),
    owners: z.array(assetOwnerAssignmentSchema).max(ASSET_OWNER_MAX_COUNT).optional(),
    tags: z.array(assetTagSchema).max(ASSET_TAG_MAX_COUNT).optional(),
    externalIdentifiers: z
      .array(assetExternalIdentifierSchema)
      .max(ASSET_IDENTIFIER_MAX_COUNT)
      .optional(),
  })
  .transform((value, ctx): NormalizedCreateAssetCommand => {
    const result = normalizeCreateAssetCommand(value);
    if (!result.ok) {
      return failWithMessage(ctx, result.error.message);
    }

    return result.value;
  });

export const updateAssetRequestSchema = z
  .strictObject({
    expectedVersion: expectedVersionSchema,
    name: z.string().max(ASSET_RAW_TEXT_MAX_LENGTH).optional(),
    assetType: assetTypeSchema.optional(),
    environmentId: z.uuid().nullable().optional(),
    owningTeamId: z.uuid().nullable().optional(),
    description: z.string().max(ASSET_RAW_TEXT_MAX_LENGTH).nullable().optional(),
    businessCriticality: businessCriticalitySchema.optional(),
    internetExposure: internetExposureSchema.optional(),
    dataClassification: assetDataClassificationSchema.optional(),
    repositoryUrl: z.string().max(ASSET_RAW_TEXT_MAX_LENGTH).nullable().optional(),
    deploymentContext: z.string().max(ASSET_RAW_TEXT_MAX_LENGTH).nullable().optional(),
    owners: z.array(assetOwnerAssignmentSchema).max(ASSET_OWNER_MAX_COUNT).optional(),
    tags: z.array(assetTagSchema).max(ASSET_TAG_MAX_COUNT).optional(),
    externalIdentifiers: z
      .array(assetExternalIdentifierSchema)
      .max(ASSET_IDENTIFIER_MAX_COUNT)
      .optional(),
  })
  .transform((value, ctx): NormalizedUpdateAssetCommand => {
    const result = normalizeUpdateAssetCommand(value);
    if (!result.ok) {
      return failWithMessage(ctx, result.error.message);
    }

    return result.value;
  });

export const archiveAssetRequestSchema = z.strictObject({
  expectedVersion: expectedVersionSchema,
});

export const assetIdParamSchema = z.strictObject({
  assetId: z.uuid(),
});

export const assetOptionsQuerySchema = z
  .strictObject({
    limit: z.coerce.number().int().min(MIN_PAGE_SIZE).max(MAX_PAGE_SIZE).optional(),
    cursor: z.uuid().optional(),
  })
  .transform((value): PageRequest => {
    const page: PageRequest = {};
    if (value.limit !== undefined) {
      page.limit = value.limit;
    }
    if (value.cursor !== undefined) {
      page.afterId = value.cursor;
    }
    return page;
  });

export const assetListQuerySchema = z
  .strictObject({
    limit: z.coerce.number().int().min(ASSET_LIST_MIN_LIMIT).max(ASSET_LIST_MAX_LIMIT).optional(),
    cursor: z.string().min(1).max(ASSET_RAW_TEXT_MAX_LENGTH).optional(),
    lifecycleStatus: assetLifecycleListFilterSchema.optional(),
    environmentId: z.uuid().optional(),
    assetType: assetTypeSchema.optional(),
    businessCriticality: businessCriticalitySchema.optional(),
    internetExposure: internetExposureSchema.optional(),
    owningTeamId: z.uuid().optional(),
    tag: z.string().max(ASSET_RAW_TEXT_MAX_LENGTH).optional(),
    namePrefix: z.string().max(ASSET_RAW_TEXT_MAX_LENGTH).optional(),
  })
  .transform((value, ctx): AssetListQuery => {
    const cursorResult =
      value.cursor === undefined ? undefined : decodeAssetListCursor(value.cursor);
    if (cursorResult !== undefined && !cursorResult.ok) {
      return failWithMessage(ctx, cursorResult.error.message);
    }

    const query: AssetListQuery = {
      limit: value.limit ?? ASSET_LIST_DEFAULT_LIMIT,
      lifecycleStatus: value.lifecycleStatus ?? DEFAULT_ASSET_LIFECYCLE_LIST_FILTER,
    };

    if (cursorResult !== undefined && cursorResult.ok) {
      query.cursor = cursorResult.value;
    }

    return attachOptionalQueryFilters(query, value, ctx);
  });

export const assetEnvironmentSummarySchema = z.strictObject({
  id: z.uuid(),
  name: z.string().min(1),
  sensitivityClass: environmentSensitivityClassSchema,
});

export const assetTeamSummarySchema = z.strictObject({
  id: z.uuid(),
  name: z.string().min(1),
});

export const membershipAssetOwnerViewSchema = z.strictObject({
  kind: z.literal('membership'),
  id: z.uuid(),
  membershipId: z.uuid(),
  displayName: z.string().min(1),
  role: assetOwnerRoleSchema,
});

export const teamAssetOwnerViewSchema = z.strictObject({
  kind: z.literal('team'),
  id: z.uuid(),
  teamId: z.uuid(),
  name: z.string().min(1),
  role: assetOwnerRoleSchema,
});

export const assetOwnerViewSchema = z.discriminatedUnion('kind', [
  membershipAssetOwnerViewSchema,
  teamAssetOwnerViewSchema,
]);

export const assetExternalIdentifierViewSchema = z.strictObject({
  namespace: z.string().min(1),
  identifier: z.string().min(1),
});

export const assetSummarySchema = z.strictObject({
  id: z.uuid(),
  name: z.string().min(1),
  assetType: assetTypeSchema,
  lifecycleStatus: z.enum(['active', 'archived']),
  environment: assetEnvironmentSummarySchema.nullable(),
  owningTeam: assetTeamSummarySchema.nullable(),
  businessCriticality: businessCriticalitySchema,
  internetExposure: internetExposureSchema,
  dataClassification: assetDataClassificationSchema,
  tags: z.array(z.string()),
  lastObservedAt: utcTimestampSchema.nullable(),
  version: expectedVersionSchema,
  updatedAt: utcTimestampSchema,
});

export const assetDetailSchema = assetSummarySchema.safeExtend({
  description: z.string().nullable(),
  repositoryUrl: z.string().nullable(),
  deploymentContext: z.string().nullable(),
  lastSuccessfulSbomIngestionId: z.uuid().nullable(),
  lastSuccessfulSbomIngestionAt: utcTimestampSchema.nullable(),
  archivedAt: utcTimestampSchema.nullable(),
  owners: z.array(assetOwnerViewSchema),
  externalIdentifiers: z.array(assetExternalIdentifierViewSchema),
  createdAt: utcTimestampSchema,
});

export const assetListResponseSchema = z.strictObject({
  items: z.array(assetSummarySchema),
  nextCursor: z.string().min(1).nullable(),
});

export const environmentOptionSchema = z.strictObject({
  id: z.uuid(),
  name: z.string().min(1),
  slug: z.string().min(1),
  sensitivityClass: environmentSensitivityClassSchema,
});

export const teamOptionSchema = z.strictObject({
  id: z.uuid(),
  name: z.string().min(1),
  slug: z.string().min(1),
});

export const membershipOptionSchema = z.strictObject({
  membershipId: z.uuid(),
  displayName: z.string().min(1),
  role: z.enum(membershipRoles),
});

export const environmentOptionsResponseSchema = z.strictObject({
  items: z.array(environmentOptionSchema),
  nextCursor: z.string().min(1).nullable(),
});

export const teamOptionsResponseSchema = z.strictObject({
  items: z.array(teamOptionSchema),
  nextCursor: z.string().min(1).nullable(),
});

export const membershipOptionsResponseSchema = z.strictObject({
  items: z.array(membershipOptionSchema),
  nextCursor: z.string().min(1).nullable(),
});

export { encodeAssetListCursor };

export type CreateAssetRequest = z.infer<typeof createAssetRequestSchema>;
export type UpdateAssetRequest = z.infer<typeof updateAssetRequestSchema>;
export type ArchiveAssetRequest = z.infer<typeof archiveAssetRequestSchema>;
export type AssetIdParam = z.infer<typeof assetIdParamSchema>;
export type AssetListQueryRequest = z.infer<typeof assetListQuerySchema>;
export type AssetOptionsQuery = z.infer<typeof assetOptionsQuerySchema>;
export type AssetSummary = z.infer<typeof assetSummarySchema>;
export type AssetDetail = z.infer<typeof assetDetailSchema>;
export type AssetListResponse = z.infer<typeof assetListResponseSchema>;
export type EnvironmentOption = z.infer<typeof environmentOptionSchema>;
export type TeamOption = z.infer<typeof teamOptionSchema>;
export type MembershipOption = z.infer<typeof membershipOptionSchema>;
export type AssetOwnerAssignmentRequest = z.infer<typeof assetOwnerAssignmentSchema>;

function attachOptionalQueryFilters(
  query: AssetListQuery,
  value: {
    environmentId?: string | undefined;
    assetType?: z.infer<typeof assetTypeSchema> | undefined;
    businessCriticality?: z.infer<typeof businessCriticalitySchema> | undefined;
    internetExposure?: z.infer<typeof internetExposureSchema> | undefined;
    owningTeamId?: string | undefined;
    tag?: string | undefined;
    namePrefix?: string | undefined;
  },
  ctx: z.RefinementCtx,
): AssetListQuery {
  const next: AssetListQuery = { ...query };

  if (value.environmentId !== undefined) {
    next.environmentId = value.environmentId;
  }
  if (value.assetType !== undefined) {
    next.assetType = value.assetType;
  }
  if (value.businessCriticality !== undefined) {
    next.businessCriticality = value.businessCriticality;
  }
  if (value.internetExposure !== undefined) {
    next.internetExposure = value.internetExposure;
  }
  if (value.owningTeamId !== undefined) {
    next.owningTeamId = value.owningTeamId;
  }

  if (value.tag !== undefined) {
    const tag = normalizeAssetTag(value.tag);
    if (!tag.ok) {
      return failWithMessage(ctx, tag.error.message);
    }
    next.tag = tag.value;
  }

  if (value.namePrefix !== undefined) {
    const prefix = normalizeAssetNamePrefix(value.namePrefix);
    if (!prefix.ok) {
      return failWithMessage(ctx, prefix.error.message);
    }
    next.namePrefix = prefix.value;
  }

  return next;
}
