import {
  SBOM_INVALID_TRANSITION,
  SBOM_TERMINAL_STATE,
  applySession8IngestionTransition,
  err,
  isSession8TerminalState,
  ok,
  type CreateAcceptedIngestionInput,
  type Result,
  type SbomIngestionPersistencePort,
  type SbomIngestionRecord,
  type Session8IngestionCommand,
  type Session8IngestionSnapshot,
} from '@patchpilot/domain';

import type { PrismaClientLike } from './guards.js';
import { isUuid, requireVersionLabel } from './guards.js';
import { mapSbomIngestion, toIngestionSnapshot } from './sbom-mappers.js';

export class PrismaSbomIngestionPersistence implements SbomIngestionPersistencePort {
  public constructor(private readonly client: PrismaClientLike) {}

  public async createAccepted(
    input: CreateAcceptedIngestionInput,
  ): Promise<Result<SbomIngestionRecord>> {
    const created = applySession8IngestionTransition(undefined, { type: 'create_accepted' });
    if (!created.ok) {
      return created;
    }

    const row = await this.client.sbomIngestion.create({
      data: {
        organizationId: input.organizationId,
        sbomId: input.sbomId,
        assetId: input.assetId,
        parserVersion: requireVersionLabel(input.parserVersion, 'parserVersion'),
        normalizationVersion: requireVersionLabel(
          input.normalizationVersion,
          'normalizationVersion',
        ),
        state: created.value.state,
        stage: created.value.stage,
      },
    });
    return ok(mapSbomIngestion(row));
  }

  public async findById(
    organizationId: string,
    ingestionId: string,
  ): Promise<SbomIngestionRecord | undefined> {
    if (!isUuid(organizationId) || !isUuid(ingestionId)) {
      return undefined;
    }
    const row = await this.client.sbomIngestion.findFirst({
      where: { organizationId, id: ingestionId },
    });
    return row === null ? undefined : mapSbomIngestion(row);
  }

  public async findByAssetAndId(
    organizationId: string,
    assetId: string,
    ingestionId: string,
  ): Promise<SbomIngestionRecord | undefined> {
    if (!isUuid(organizationId) || !isUuid(assetId) || !isUuid(ingestionId)) {
      return undefined;
    }
    const row = await this.client.sbomIngestion.findFirst({
      where: { organizationId, assetId, id: ingestionId },
    });
    return row === null ? undefined : mapSbomIngestion(row);
  }

  public async findCurrentForSbom(
    organizationId: string,
    sbomId: string,
  ): Promise<SbomIngestionRecord | undefined> {
    if (!isUuid(organizationId) || !isUuid(sbomId)) {
      return undefined;
    }
    const row = await this.client.sbomIngestion.findFirst({
      where: { organizationId, sbomId },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    });
    return row === null ? undefined : mapSbomIngestion(row);
  }

  public async applyTransition(
    organizationId: string,
    ingestionId: string,
    expectedVersion: number,
    command: Session8IngestionCommand,
  ): Promise<Result<{ record: SbomIngestionRecord; snapshot: Session8IngestionSnapshot }>> {
    if (!isUuid(organizationId) || !isUuid(ingestionId)) {
      return err(SBOM_INVALID_TRANSITION);
    }

    const current = await this.findById(organizationId, ingestionId);
    if (current === undefined) {
      return err(SBOM_INVALID_TRANSITION);
    }

    if (isSession8TerminalState(current.state)) {
      if (current.state === 'completed' && command.type === 'complete') {
        return ok({ record: current, snapshot: toIngestionSnapshot(current) });
      }
      return err(SBOM_TERMINAL_STATE);
    }

    const next = applySession8IngestionTransition(toIngestionSnapshot(current), command);
    if (!next.ok) {
      return next;
    }

    const updated = await this.client.sbomIngestion.updateMany({
      where: { organizationId, id: ingestionId, version: expectedVersion },
      data: {
        state: next.value.state,
        stage: next.value.stage,
        startedAt: next.value.startedAt,
        completedAt: next.value.completedAt,
        graphCompleteness: next.value.graphCompleteness,
        componentCount: next.value.componentCount,
        dependencyEdgeCount: next.value.dependencyEdgeCount,
        warningCount: next.value.warningCount,
        failureCategory: next.value.failureCategory,
        failureCode: next.value.failureCode,
        version: { increment: 1 },
      },
    });
    if (updated.count === 0) {
      return err(SBOM_INVALID_TRANSITION);
    }

    const record = await this.findById(organizationId, ingestionId);
    if (record === undefined) {
      return err(SBOM_INVALID_TRANSITION);
    }
    return ok({ record, snapshot: toIngestionSnapshot(record) });
  }
}
