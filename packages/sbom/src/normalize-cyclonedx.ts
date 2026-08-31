import {
  buildComponentIdentityKey,
  deriveGraphCompleteness,
  knownComponentVersion,
  parserThreadDisposition,
  unknownComponentVersion,
  validateNormalizedComponentGraph,
  type ComponentVersion,
  type CountOnlyWarningSummary,
  type NormalizedComponent,
  type NormalizedDependencyEdge,
  type ParseWarningCode,
  type SafeFailureCode,
  type SbomParserLimits,
} from '@patchpilot/domain';

import type { ParserWorkerFailure, ParserWorkerSuccess } from './parser-thread.js';
import { normalizePackageUrl, versionedPackageUrl } from './purl.js';

const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function parserFailure(code: SafeFailureCode): ParserWorkerFailure {
  const disposition = parserThreadDisposition(code);
  if (disposition === undefined) {
    return { ok: false, disposition: 'quarantined', code: 'parser_crash' };
  }
  return { ok: false, disposition, code };
}

function byteLength(value: string): number {
  return Buffer.byteLength(value, 'utf8');
}

function observedVersion(raw: string | undefined): ComponentVersion {
  if (raw === undefined) {
    return unknownComponentVersion();
  }
  const known = knownComponentVersion(raw);
  if (known.ok) {
    return known.value;
  }
  return unknownComponentVersion();
}

function collectComponents(document: Record<string, unknown>): Record<string, unknown>[] {
  const collected: Record<string, unknown>[] = [];
  const visit = (value: unknown): void => {
    if (!isObjectRecord(value)) {
      return;
    }
    collected.push(value);
    const nested = value['components'];
    if (Array.isArray(nested)) {
      for (const child of nested) {
        visit(child);
      }
    }
  };

  const metadata = document['metadata'];
  if (isObjectRecord(metadata)) {
    visit(metadata['component']);
  }
  const components = document['components'];
  if (Array.isArray(components)) {
    for (const component of components) {
      visit(component);
    }
  }
  return collected;
}

function countMetadataTools(document: Record<string, unknown>): number {
  const metadata = document['metadata'];
  if (!isObjectRecord(metadata)) {
    return 0;
  }
  const tools = metadata['tools'];
  if (Array.isArray(tools)) {
    return tools.length;
  }
  if (!isObjectRecord(tools)) {
    return 0;
  }
  const components = tools['components'];
  const services = tools['services'];
  const componentCount = Array.isArray(components) ? components.length : 0;
  const serviceCount = Array.isArray(services) ? services.length : 0;
  return componentCount + serviceCount;
}

function arrayLength(value: unknown): number {
  return Array.isArray(value) ? value.length : 0;
}

function capturedAtFromMetadata(document: Record<string, unknown>): string | null {
  const metadata = document['metadata'];
  if (!isObjectRecord(metadata)) {
    return null;
  }
  const timestamp = asString(metadata['timestamp']);
  if (timestamp === undefined || !UTC_TIMESTAMP.test(timestamp)) {
    return null;
  }
  return timestamp;
}

function metadataComponentBomRef(document: Record<string, unknown>): string | undefined {
  const metadata = document['metadata'];
  if (!isObjectRecord(metadata) || !isObjectRecord(metadata['component'])) {
    return undefined;
  }
  return asString(metadata['component']['bom-ref']);
}

function incrementWarning(
  warnings: Map<ParseWarningCode, number>,
  code: ParseWarningCode,
  count = 1,
): void {
  warnings.set(code, (warnings.get(code) ?? 0) + count);
}

function warningSummaries(warnings: Map<ParseWarningCode, number>): CountOnlyWarningSummary[] {
  const summaries: CountOnlyWarningSummary[] = [];
  for (const code of ['self_dependency_skipped', 'duplicate_identity_collapsed'] as const) {
    const count = warnings.get(code);
    if (count !== undefined && count > 0) {
      summaries.push({ code, count });
    }
  }
  return summaries;
}

function normalizeOneComponent(
  raw: Record<string, unknown>,
  limits: SbomParserLimits,
): ParserWorkerFailure | NormalizedComponent {
  const name = asString(raw['name']);
  if (name === undefined || name.length === 0) {
    return parserFailure('schema_invalid');
  }
  if (name.length > limits.maxComponentNameChars) {
    return parserFailure('identifier_length');
  }
  if (arrayLength(raw['externalReferences']) > limits.maxExternalRefsPerComponent) {
    return parserFailure('reference_limit');
  }
  if (arrayLength(raw['properties']) > limits.maxPropertiesPerComponent) {
    return parserFailure('property_limit');
  }

  const bomRefRaw = asString(raw['bom-ref']);
  const bomRef = bomRefRaw === undefined || bomRefRaw.length === 0 ? null : bomRefRaw;
  if (bomRef !== null && byteLength(bomRef) > limits.maxBomRefBytes) {
    return parserFailure('identifier_length');
  }

  const listedVersion = asString(raw['version']);
  const group = asString(raw['group']);
  const purlRaw = asString(raw['purl']);

  if (purlRaw !== undefined && purlRaw.length > 0) {
    if (byteLength(purlRaw) > limits.maxPurlBytes) {
      return parserFailure('identifier_length');
    }
    const normalized = normalizePackageUrl(purlRaw);
    if (!normalized.ok) {
      return parserFailure('invalid_purl');
    }
    if (byteLength(normalized.value.versionless) > limits.maxPurlBytes) {
      return parserFailure('identifier_length');
    }

    const version = observedVersion(listedVersion ?? normalized.value.version ?? undefined);
    if (version.kind === 'known' && version.value.length > limits.maxVersionChars) {
      return parserFailure('identifier_length');
    }

    let versionedPurl = normalized.value.versioned;
    if (versionedPurl === null && version.kind === 'known') {
      const encoded = versionedPackageUrl(normalized.value, version.value);
      if (!encoded.ok) {
        return parserFailure('invalid_purl');
      }
      versionedPurl = encoded.value;
    }
    if (versionedPurl !== null && byteLength(versionedPurl) > limits.maxPurlBytes) {
      return parserFailure('identifier_length');
    }

    const identityState = 'resolved' as const;
    const identityKey = buildComponentIdentityKey({
      identityState,
      versionlessPurl: normalized.value.versionless,
      ecosystem: normalized.value.type,
      namespace: normalized.value.namespace,
      name,
      bomRef,
    });
    if (!identityKey.ok) {
      return parserFailure('identifier_length');
    }

    return {
      bomRef,
      name,
      namespace: normalized.value.namespace,
      ecosystem: normalized.value.type,
      identityState,
      versionlessPurl: normalized.value.versionless,
      versionedPurl,
      version,
      isDirect: null,
      identityKey: identityKey.value,
    };
  }

  const version = observedVersion(listedVersion);
  if (version.kind === 'known' && version.value.length > limits.maxVersionChars) {
    return parserFailure('identifier_length');
  }

  const identityState = 'unsupported' as const;
  const identityKey = buildComponentIdentityKey({
    identityState,
    versionlessPurl: null,
    ecosystem: null,
    namespace: group === undefined || group.length === 0 ? null : group,
    name,
    bomRef,
  });
  if (!identityKey.ok) {
    return parserFailure('identifier_length');
  }

  return {
    bomRef,
    name,
    namespace: group === undefined || group.length === 0 ? null : group,
    ecosystem: null,
    identityState,
    versionlessPurl: null,
    versionedPurl: null,
    version,
    isDirect: null,
    identityKey: identityKey.value,
  };
}

function collapseDuplicateIdentities(components: NormalizedComponent[]): {
  components: NormalizedComponent[];
  bomRefAlias: Map<string, string>;
  duplicateCount: number;
} {
  const kept: NormalizedComponent[] = [];
  const byIdentity = new Map<string, NormalizedComponent>();
  const bomRefAlias = new Map<string, string>();
  let duplicateCount = 0;

  for (const component of components) {
    const existing = byIdentity.get(component.identityKey);
    if (existing === undefined) {
      byIdentity.set(component.identityKey, component);
      kept.push(component);
      if (component.bomRef !== null) {
        bomRefAlias.set(component.bomRef, component.bomRef);
      }
      continue;
    }

    duplicateCount += 1;
    if (component.bomRef === null) {
      continue;
    }
    if (existing.bomRef === null) {
      existing.bomRef = component.bomRef;
      bomRefAlias.set(component.bomRef, component.bomRef);
      continue;
    }
    bomRefAlias.set(component.bomRef, existing.bomRef);
  }

  return { components: kept, bomRefAlias, duplicateCount };
}

function resolveAlias(alias: Map<string, string>, bomRef: string): string {
  return alias.get(bomRef) ?? bomRef;
}

function applyDirectness(
  components: NormalizedComponent[],
  directBomRefs: Set<string>,
  hasDependencyGraph: boolean,
): void {
  if (!hasDependencyGraph) {
    return;
  }
  for (const component of components) {
    if (component.bomRef !== null && directBomRefs.has(component.bomRef)) {
      component.isDirect = true;
    } else if (component.bomRef !== null) {
      component.isDirect = false;
    }
  }
}

export function normalizeCycloneDxDocument(
  document: unknown,
  limits: SbomParserLimits,
  parserVersion: string,
  normalizationVersion: string,
  specificationVersion: ParserWorkerSuccess['specificationVersion'],
): ParserWorkerSuccess | ParserWorkerFailure {
  if (!isObjectRecord(document)) {
    return parserFailure('not_cyclonedx');
  }

  if (countMetadataTools(document) > limits.maxMetadataTools) {
    return parserFailure('tool_limit');
  }

  const rawComponents = collectComponents(document);
  if (rawComponents.length > limits.maxComponents) {
    return parserFailure('component_limit');
  }

  const normalized: NormalizedComponent[] = [];
  const seenBomRefs = new Set<string>();
  for (const raw of rawComponents) {
    const component = normalizeOneComponent(raw, limits);
    if ('ok' in component && component.ok === false) {
      return component;
    }
    const next = component as NormalizedComponent;
    if (next.bomRef !== null) {
      if (seenBomRefs.has(next.bomRef)) {
        return parserFailure('duplicate_bom_ref');
      }
      seenBomRefs.add(next.bomRef);
    }
    normalized.push(next);
  }

  const collapsed = collapseDuplicateIdentities(normalized);
  const knownBomRefs = new Set<string>();
  for (const component of collapsed.components) {
    if (component.bomRef !== null) {
      knownBomRefs.add(component.bomRef);
    }
  }

  const warnings = new Map<ParseWarningCode, number>();
  if (collapsed.duplicateCount > 0) {
    incrementWarning(warnings, 'duplicate_identity_collapsed', collapsed.duplicateCount);
  }

  const dependencies = document['dependencies'];
  const listedEdges: Array<{ fromBomRef: string; toBomRef: string }> = [];
  if (dependencies !== undefined && !Array.isArray(dependencies)) {
    return parserFailure('schema_invalid');
  }
  if (Array.isArray(dependencies)) {
    for (const entry of dependencies) {
      if (!isObjectRecord(entry)) {
        return parserFailure('schema_invalid');
      }
      const from = asString(entry['ref']);
      if (from === undefined || from.length === 0) {
        return parserFailure('unresolved_dependency_ref');
      }
      if (!knownBomRefs.has(resolveAlias(collapsed.bomRefAlias, from))) {
        return parserFailure('unresolved_dependency_ref');
      }
      const dependsOn = entry['dependsOn'];
      if (dependsOn === undefined) {
        continue;
      }
      if (!Array.isArray(dependsOn)) {
        return parserFailure('schema_invalid');
      }
      for (const target of dependsOn) {
        const to = asString(target);
        if (to === undefined || to.length === 0) {
          return parserFailure('unresolved_dependency_ref');
        }
        listedEdges.push({ fromBomRef: from, toBomRef: to });
      }
    }
  }

  if (listedEdges.length > limits.maxDependencyEdges) {
    return parserFailure('edge_limit');
  }

  const edges: NormalizedDependencyEdge[] = [];
  const seenEdges = new Set<string>();
  let skippedListedEdgeCount = 0;

  for (const listed of listedEdges) {
    const fromBomRef = resolveAlias(collapsed.bomRefAlias, listed.fromBomRef);
    const toBomRef = resolveAlias(collapsed.bomRefAlias, listed.toBomRef);
    if (!knownBomRefs.has(fromBomRef) || !knownBomRefs.has(toBomRef)) {
      return parserFailure('unresolved_dependency_ref');
    }
    if (fromBomRef === toBomRef) {
      skippedListedEdgeCount += 1;
      incrementWarning(warnings, 'self_dependency_skipped');
      continue;
    }
    const key = `${fromBomRef}\u0000${toBomRef}`;
    if (seenEdges.has(key)) {
      continue;
    }
    seenEdges.add(key);
    edges.push({ fromBomRef, toBomRef, relationshipType: 'depends_on' });
  }

  if (edges.length > limits.maxDependencyEdges) {
    return parserFailure('edge_limit');
  }

  const rootBomRef = metadataComponentBomRef(document);
  const aliasedRoot =
    rootBomRef === undefined ? undefined : resolveAlias(collapsed.bomRefAlias, rootBomRef);
  const directBomRefs = new Set<string>();
  if (aliasedRoot !== undefined) {
    directBomRefs.add(aliasedRoot);
    for (const edge of edges) {
      if (edge.fromBomRef === aliasedRoot) {
        directBomRefs.add(edge.toBomRef);
      }
    }
  }
  applyDirectness(collapsed.components, directBomRefs, listedEdges.length > 0);

  const completeness = deriveGraphCompleteness({
    componentCount: collapsed.components.length,
    dependencyEdgeCount: edges.length,
    skippedListedEdgeCount,
  });
  if (!completeness.ok) {
    return parserFailure('schema_invalid');
  }

  const summaries = warningSummaries(warnings);
  const warningCount = summaries.reduce((sum, warning) => sum + warning.count, 0);
  const capturedAt = capturedAtFromMetadata(document);

  const success: ParserWorkerSuccess = {
    ok: true,
    specificationVersion,
    graphCompleteness: completeness.value,
    components: collapsed.components,
    edges,
    warnings: summaries,
    stats: {
      componentCount: collapsed.components.length,
      dependencyEdgeCount: edges.length,
      warningCount,
    },
    capturedAt,
    parserVersion,
    normalizationVersion,
  };

  const graph = validateNormalizedComponentGraph({
    specificationVersion: success.specificationVersion,
    graphCompleteness: success.graphCompleteness,
    components: success.components,
    edges: success.edges,
    warnings: success.warnings,
    componentCount: success.stats.componentCount,
    dependencyEdgeCount: success.stats.dependencyEdgeCount,
    warningCount: success.stats.warningCount,
    capturedAt: capturedAt === null ? null : new Date(capturedAt),
    parserVersion,
    normalizationVersion,
  });
  if (!graph.ok) {
    return parserFailure('schema_invalid');
  }

  return success;
}

export { parserFailure };
