import { Prisma } from '@prisma/client';
import {
  JSON_SCHEMA_VERSION_V1,
  SBOM_INVALID_GRAPH,
  SBOM_INVALID_TRANSITION,
  SBOM_PROCESSING_REQUIRES_STARTED_AT,
  SBOM_TERMINAL_STATE,
  applySession8IngestionTransition,
  err,
  isSession8TerminalState,
  ok,
  toOccurrenceVersionColumns,
  validateNormalizedComponentGraph,
  type ComponentGraphPersistencePort,
  type ComponentOccurrenceRecord,
  type DependencyRelationshipRecord,
  type Page,
  type PageRequest,
  type PersistComponentGraphInput,
  type Result,
} from '@patchpilot/domain';

import {
  asJsonObject,
  isRootPrismaClient,
  isUuid,
  requireVersionLabel,
  type PrismaClientLike,
} from './guards.js';
import { afterIdWhere, paginateById } from './paging.js';
import {
  mapComponentOccurrence,
  mapDependencyRelationship,
  mapSbomIngestion,
  toIngestionSnapshot,
} from './sbom-mappers.js';

export class PrismaComponentGraphPersistence implements ComponentGraphPersistencePort {
  public constructor(private readonly client: PrismaClientLike) {}

  public async persistOnceForIngestion(input: PersistComponentGraphInput): Promise<Result<void>> {
    const graph = validateNormalizedComponentGraph(input.graph);
    if (!graph.ok) {
      return graph;
    }
    if (!isUuid(input.organizationId) || !isUuid(input.sbomIngestionId)) {
      return err(SBOM_INVALID_TRANSITION);
    }

    return this.runInTransaction(async (tx) => {
      await tx.$queryRaw`
        SELECT "id"
        FROM "sbom_ingestion"
        WHERE "organization_id" = ${input.organizationId}::uuid
          AND "id" = ${input.sbomIngestionId}::uuid
        FOR UPDATE
      `;
      const ingestionRow = await tx.sbomIngestion.findFirst({
        where: { organizationId: input.organizationId, id: input.sbomIngestionId },
      });
      if (ingestionRow === null) {
        return err(SBOM_INVALID_TRANSITION);
      }
      const ingestion = mapSbomIngestion(ingestionRow);
      if (
        ingestion.assetId !== input.assetId ||
        ingestion.sbomId !== input.sbomId ||
        ingestion.organizationId !== input.organizationId
      ) {
        return err(SBOM_INVALID_TRANSITION);
      }

      if (ingestion.state === 'completed') {
        return ok(undefined);
      }
      if (isSession8TerminalState(ingestion.state)) {
        return err(SBOM_TERMINAL_STATE);
      }
      if (ingestion.state !== 'processing') {
        return err(SBOM_INVALID_TRANSITION);
      }
      if (ingestion.startedAt === null) {
        return err(SBOM_PROCESSING_REQUIRES_STARTED_AT);
      }

      const sbom = await tx.sbom.findFirst({
        where: {
          organizationId: input.organizationId,
          id: input.sbomId,
          assetId: input.assetId,
        },
      });
      if (sbom === null) {
        return err(SBOM_INVALID_TRANSITION);
      }

      const occurrenceByBomRef = new Map<string, string>();
      for (const component of graph.value.components) {
        const versionColumns = toOccurrenceVersionColumns(component.version);
        if (!versionColumns.ok) {
          return versionColumns;
        }

        const componentId = await upsertComponent(tx, {
          organizationId: input.organizationId,
          identityKey: component.identityKey,
          purl: component.versionlessPurl,
          ecosystem: component.ecosystem,
          namespace: component.namespace,
          name: component.name,
          identityState: component.identityState,
        });

        const occurrence = await tx.componentOccurrence.create({
          data: {
            organizationId: input.organizationId,
            assetId: input.assetId,
            sbomId: input.sbomId,
            sbomIngestionId: input.sbomIngestionId,
            componentId,
            bomRef: component.bomRef,
            version: versionColumns.value.version,
            versionKnown: versionColumns.value.versionKnown,
            versionedPurl: component.versionedPurl,
            isDirect: component.isDirect,
          },
        });
        if (component.bomRef !== null) {
          occurrenceByBomRef.set(component.bomRef, occurrence.id);
        }
      }

      const edgeData: Array<{
        organizationId: string;
        sbomId: string;
        sbomIngestionId: string;
        fromOccurrenceId: string;
        toOccurrenceId: string;
        relationshipType: 'depends_on';
      }> = [];
      for (const edge of graph.value.edges) {
        // Parser Batch 9 omits self-edges before persist. DTO validation already
        // rejects them; this is not warning accounting.
        if (edge.fromBomRef === edge.toBomRef) {
          continue;
        }
        const fromOccurrenceId = occurrenceByBomRef.get(edge.fromBomRef);
        const toOccurrenceId = occurrenceByBomRef.get(edge.toBomRef);
        if (fromOccurrenceId === undefined || toOccurrenceId === undefined) {
          return err(SBOM_INVALID_GRAPH);
        }
        edgeData.push({
          organizationId: input.organizationId,
          sbomId: input.sbomId,
          sbomIngestionId: input.sbomIngestionId,
          fromOccurrenceId,
          toOccurrenceId,
          relationshipType: 'depends_on',
        });
      }
      if (edgeData.length > 0) {
        await tx.dependencyRelationship.createMany({ data: edgeData });
      }

      const completedAt = new Date();
      const complete = applySession8IngestionTransition(toIngestionSnapshot(ingestion), {
        type: 'complete',
        completedAt,
        graphCompleteness: graph.value.graphCompleteness,
        componentCount: graph.value.componentCount,
        dependencyEdgeCount: graph.value.dependencyEdgeCount,
        warningCount: graph.value.warningCount,
      });
      if (!complete.ok) {
        return complete;
      }

      const transitioned = await tx.sbomIngestion.updateMany({
        where: {
          organizationId: input.organizationId,
          id: input.sbomIngestionId,
          version: ingestion.version,
          state: 'processing',
        },
        data: {
          state: complete.value.state,
          stage: complete.value.stage,
          completedAt: complete.value.completedAt,
          graphCompleteness: complete.value.graphCompleteness,
          componentCount: complete.value.componentCount,
          dependencyEdgeCount: complete.value.dependencyEdgeCount,
          warningCount: complete.value.warningCount,
          failureCategory: null,
          failureCode: null,
          version: { increment: 1 },
        },
      });
      if (transitioned.count === 0) {
        return err(SBOM_INVALID_TRANSITION);
      }

      await tx.sbom.updateMany({
        where: { organizationId: input.organizationId, id: input.sbomId },
        data: {
          parserVersionLastSucceeded: requireVersionLabel(
            graph.value.parserVersion,
            'parserVersion',
          ),
          specificationVersion: graph.value.specificationVersion,
        },
      });

      await replaceAssetPointerIfCandidateIsCurrent(tx, {
        organizationId: input.organizationId,
        assetId: input.assetId,
        candidateIngestionId: input.sbomIngestionId,
        completedAt,
      });

      await tx.auditEvent.create({
        data: {
          organizationId: input.organizationId,
          actorType: 'system',
          action: 'sbom.ingestion.completed',
          subjectType: 'sbom_ingestion',
          subjectId: input.sbomIngestionId,
          correlationId: input.correlationId,
          payload: asJsonObject(
            {
              schemaVersion: JSON_SCHEMA_VERSION_V1,
              metadata: {
                sbomId: input.sbomId,
                ingestionId: input.sbomIngestionId,
                graphCompleteness: graph.value.graphCompleteness,
                componentCount: graph.value.componentCount,
                dependencyEdgeCount: graph.value.dependencyEdgeCount,
                warningCount: graph.value.warningCount,
                parserVersion: graph.value.parserVersion,
                normalizationVersion: graph.value.normalizationVersion,
              },
            },
            'payload',
          ),
          schemaVersion: JSON_SCHEMA_VERSION_V1,
          retentionCategory: 'security',
        },
      });

      const ownedJob = input.ownedJob;
      if (ownedJob !== undefined) {
        await tx.backgroundJob.updateMany({
          where: {
            id: ownedJob.jobId,
            organizationId: input.organizationId,
            workerIdentifier: ownedJob.workerIdentifier,
            status: 'running',
            leaseExpiresAt: { gt: completedAt },
          },
          data: {
            status: 'succeeded',
            completedAt: ownedJob.completedAt,
            leaseExpiresAt: null,
            failureCategory: null,
            failureCode: null,
          },
        });
      }

      return ok(undefined);
    });
  }

  public async listOccurrencesForIngestion(
    organizationId: string,
    sbomIngestionId: string,
    page?: PageRequest,
  ): Promise<Page<ComponentOccurrenceRecord>> {
    if (!isUuid(organizationId) || !isUuid(sbomIngestionId)) {
      return { items: [], nextCursor: undefined };
    }
    return paginateById(async ({ take, cursorId }) => {
      const rows = await this.client.componentOccurrence.findMany({
        where: { organizationId, sbomIngestionId, ...afterIdWhere(cursorId) },
        orderBy: { id: 'asc' },
        take,
      });
      return rows.map(mapComponentOccurrence);
    }, page);
  }

  public async listEdgesForIngestion(
    organizationId: string,
    sbomIngestionId: string,
    page?: PageRequest,
  ): Promise<Page<DependencyRelationshipRecord>> {
    if (!isUuid(organizationId) || !isUuid(sbomIngestionId)) {
      return { items: [], nextCursor: undefined };
    }
    return paginateById(async ({ take, cursorId }) => {
      const rows = await this.client.dependencyRelationship.findMany({
        where: { organizationId, sbomIngestionId, ...afterIdWhere(cursorId) },
        orderBy: { id: 'asc' },
        take,
      });
      return rows.map(mapDependencyRelationship);
    }, page);
  }

  private async runInTransaction<T>(work: (client: PrismaClientLike) => Promise<T>): Promise<T> {
    if (isRootPrismaClient(this.client)) {
      return this.client.$transaction(async (tx) => work(tx), {
        isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted,
      });
    }
    return work(this.client);
  }
}

/**
 * Serialize pointer updates for one asset until commit. `$queryRaw` must
 * return a row: Prisma cannot deserialize `void` from `pg_advisory_xact_lock`.
 * Ranking uses the locked pointer id and both ingestions' stored columns so
 * a concurrent older writer cannot compare against a stale asset snapshot.
 */
async function lockAssetForPointerUpdate(
  tx: PrismaClientLike,
  organizationId: string,
  assetId: string,
): Promise<string | null> {
  await tx.$queryRaw`
    SELECT 1::int AS locked
    FROM (
      SELECT pg_advisory_xact_lock(
        hashtextextended(${`${organizationId}:${assetId}`}, 0)
      )
    ) AS taken
  `;
  const locked = await tx.$queryRaw<Array<{ current_id: string | null }>>`
    SELECT "last_successful_sbom_ingestion_id" AS "current_id"
    FROM "asset"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "id" = ${assetId}::uuid
    FOR UPDATE
  `;
  return locked[0]?.current_id ?? null;
}

async function replaceAssetPointerIfCandidateIsCurrent(
  tx: PrismaClientLike,
  input: {
    organizationId: string;
    assetId: string;
    candidateIngestionId: string;
    completedAt: Date;
  },
): Promise<void> {
  const currentIngestionId = await lockAssetForPointerUpdate(
    tx,
    input.organizationId,
    input.assetId,
  );

  if (currentIngestionId !== null) {
    const ranking = await tx.$queryRaw<Array<{ current_wins: number }>>`
      SELECT CASE
        WHEN (
          cur_sbom."received_at",
          cur."created_at",
          cur."id"
        ) >= (
          cand_sbom."received_at",
          cand."created_at",
          cand."id"
        )
        THEN 1
        ELSE 0
      END::int AS "current_wins"
      FROM "sbom_ingestion" AS cand
      INNER JOIN "sbom" AS cand_sbom
        ON cand_sbom."organization_id" = cand."organization_id"
       AND cand_sbom."id" = cand."sbom_id"
      INNER JOIN "sbom_ingestion" AS cur
        ON cur."organization_id" = cand."organization_id"
       AND cur."id" = ${currentIngestionId}::uuid
       AND cur."state" = 'completed'
      INNER JOIN "sbom" AS cur_sbom
        ON cur_sbom."organization_id" = cur."organization_id"
       AND cur_sbom."id" = cur."sbom_id"
      WHERE cand."organization_id" = ${input.organizationId}::uuid
        AND cand."id" = ${input.candidateIngestionId}::uuid
        AND cand."asset_id" = ${input.assetId}::uuid
        AND cand."state" = 'completed'
    `;
    if (Number(ranking[0]?.current_wins) === 1) {
      return;
    }
  }

  await tx.$executeRaw`
    UPDATE "asset"
    SET
      "last_successful_sbom_ingestion_id" = ${input.candidateIngestionId}::uuid,
      "last_successful_sbom_ingestion_at" = ${input.completedAt},
      "updated_at" = CURRENT_TIMESTAMP
    WHERE "organization_id" = ${input.organizationId}::uuid
      AND "id" = ${input.assetId}::uuid
  `;
}

async function upsertComponent(
  tx: PrismaClientLike,
  input: {
    organizationId: string;
    identityKey: string;
    purl: string | null;
    ecosystem: string | null;
    namespace: string | null;
    name: string;
    identityState: 'resolved' | 'ambiguous' | 'unsupported';
  },
): Promise<string> {
  const existing = await tx.component.findUnique({
    where: {
      organizationId_identityKey: {
        organizationId: input.organizationId,
        identityKey: input.identityKey,
      },
    },
  });
  if (existing !== null) {
    return existing.id;
  }

  try {
    const created = await tx.component.create({
      data: {
        organizationId: input.organizationId,
        identityKey: input.identityKey,
        purl: input.purl,
        ecosystem: input.ecosystem,
        namespace: input.namespace,
        name: input.name,
        identityState: input.identityState,
      },
    });
    return created.id;
  } catch (error) {
    if (!(error instanceof Prisma.PrismaClientKnownRequestError) || error.code !== 'P2002') {
      throw error;
    }
  }

  const raced = await tx.component.findUnique({
    where: {
      organizationId_identityKey: {
        organizationId: input.organizationId,
        identityKey: input.identityKey,
      },
    },
  });
  if (raced === null) {
    throw new Error('Component identity conflict could not be loaded.');
  }
  return raced.id;
}
