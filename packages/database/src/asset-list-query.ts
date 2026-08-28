import { Prisma } from '@prisma/client';
import {
  ASSET_LIST_CURSOR_VERSION,
  ASSET_LIST_DEFAULT_LIMIT,
  ASSET_LIST_MAX_LIMIT,
  ASSET_LIST_MIN_LIMIT,
  ASSET_NAME_MAX_LENGTH,
  DEFAULT_ASSET_LIFECYCLE_LIST_FILTER,
  assetTypes,
  businessCriticalities,
  internetExposures,
  type AssetListQuery,
} from '@patchpilot/domain';

import { isUuid } from './guards.js';

const LIFECYCLE_FILTERS = new Set(['active', 'archived', 'all']);

export type ResolvedAssetListQuery = {
  organizationId: string;
  take: number;
  empty: boolean;
  sql: Prisma.Sql;
};

export function boundAssetListLimit(limit: number | undefined): number {
  if (limit === undefined) {
    return ASSET_LIST_DEFAULT_LIMIT;
  }

  if (!Number.isInteger(limit) || limit < ASSET_LIST_MIN_LIMIT) {
    return ASSET_LIST_MIN_LIMIT;
  }

  if (limit > ASSET_LIST_MAX_LIMIT) {
    return ASSET_LIST_MAX_LIMIT;
  }

  return limit;
}

export function buildAssetListQuery(
  organizationId: string,
  query?: AssetListQuery,
): ResolvedAssetListQuery {
  const take = boundAssetListLimit(query?.limit) + 1;
  if (!isUuid(organizationId)) {
    return emptyQuery(organizationId, take);
  }

  const lifecycleStatus = query?.lifecycleStatus ?? DEFAULT_ASSET_LIFECYCLE_LIST_FILTER;
  if (!LIFECYCLE_FILTERS.has(lifecycleStatus)) {
    return emptyQuery(organizationId, take);
  }

  const cursor = query?.cursor;
  if (cursor !== undefined && !isValidListCursor(cursor)) {
    return emptyQuery(organizationId, take);
  }

  const filters: Prisma.Sql[] = [Prisma.sql`a.organization_id = CAST(${organizationId} AS UUID)`];

  if (lifecycleStatus !== 'all') {
    filters.push(
      Prisma.sql`a.lifecycle_status = CAST(${lifecycleStatus} AS asset_lifecycle_status)`,
    );
  }

  if (query?.environmentId !== undefined) {
    if (!isUuid(query.environmentId)) {
      return emptyQuery(organizationId, take);
    }
    filters.push(Prisma.sql`a.environment_id = CAST(${query.environmentId} AS UUID)`);
  }

  if (query?.owningTeamId !== undefined) {
    if (!isUuid(query.owningTeamId)) {
      return emptyQuery(organizationId, take);
    }
    filters.push(Prisma.sql`a.owning_team_id = CAST(${query.owningTeamId} AS UUID)`);
  }

  if (query?.assetType !== undefined) {
    if (!isAllowlisted(query.assetType, assetTypes)) {
      return emptyQuery(organizationId, take);
    }
    filters.push(Prisma.sql`a.asset_type = CAST(${query.assetType} AS asset_type)`);
  }

  if (query?.businessCriticality !== undefined) {
    if (!isAllowlisted(query.businessCriticality, businessCriticalities)) {
      return emptyQuery(organizationId, take);
    }
    filters.push(
      Prisma.sql`a.business_criticality = CAST(${query.businessCriticality} AS business_criticality)`,
    );
  }

  if (query?.internetExposure !== undefined) {
    if (!isAllowlisted(query.internetExposure, internetExposures)) {
      return emptyQuery(organizationId, take);
    }
    filters.push(
      Prisma.sql`a.internet_exposure = CAST(${query.internetExposure} AS internet_exposure)`,
    );
  }

  if (query?.tag !== undefined) {
    filters.push(Prisma.sql`EXISTS (
      SELECT 1
      FROM asset_tag tg
      WHERE tg.organization_id = a.organization_id
        AND tg.asset_id = a.id
        AND tg.tag = ${query.tag}
    )`);
  }

  if (query?.namePrefix !== undefined) {
    filters.push(Prisma.sql`starts_with(lower(a.name), lower(${query.namePrefix}))`);
  }

  if (cursor !== undefined) {
    filters.push(
      Prisma.sql`(lower(a.name), a.id) > (lower(${cursor.n}), CAST(${cursor.i} AS UUID))`,
    );
  }

  const sql = Prisma.sql`
    SELECT
      a.id::text AS id,
      a.organization_id::text AS "organizationId",
      a.name,
      a.asset_type AS "assetType",
      a.lifecycle_status AS "lifecycleStatus",
      a.business_criticality AS "businessCriticality",
      a.internet_exposure AS "internetExposure",
      a.data_classification AS "dataClassification",
      a.last_observed_at AS "lastObservedAt",
      a.version,
      a.updated_at AS "updatedAt",
      a.environment_id::text AS "environmentId",
      e.name AS "environmentName",
      e.sensitivity_class AS "environmentSensitivityClass",
      a.owning_team_id::text AS "owningTeamId",
      t.name AS "owningTeamName",
      COALESCE(
        (
          SELECT json_agg(tg.tag ORDER BY tg.tag)
          FROM asset_tag tg
          WHERE tg.organization_id = a.organization_id
            AND tg.asset_id = a.id
        ),
        '[]'::json
      ) AS tags
    FROM asset a
    LEFT JOIN environment e
      ON e.organization_id = a.organization_id AND e.id = a.environment_id
    LEFT JOIN team t
      ON t.organization_id = a.organization_id AND t.id = a.owning_team_id
    WHERE ${Prisma.join(filters, ' AND ')}
    ORDER BY lower(a.name), a.id
    LIMIT ${take}
  `;

  return { organizationId, take, empty: false, sql };
}

export function sqlContainsRawValue(sql: Prisma.Sql, value: string): boolean {
  return sql.strings.some((fragment) => fragment.includes(value));
}

function emptyQuery(organizationId: string, take: number): ResolvedAssetListQuery {
  return {
    organizationId,
    take,
    empty: true,
    sql: Prisma.sql`SELECT 1 WHERE false`,
  };
}

function isValidListCursor(cursor: NonNullable<AssetListQuery['cursor']>): boolean {
  return (
    cursor.v === ASSET_LIST_CURSOR_VERSION &&
    isUuid(cursor.i) &&
    cursor.n.length > 0 &&
    cursor.n.length <= ASSET_NAME_MAX_LENGTH
  );
}

function isAllowlisted<T extends string>(value: string, catalog: readonly T[]): value is T {
  return (catalog as readonly string[]).includes(value);
}
