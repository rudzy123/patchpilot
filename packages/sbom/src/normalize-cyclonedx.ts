import {
  buildComponentIdentityKey,
  componentOccurrenceNormalizationKey,
  CURRENT_SBOM_NORMALIZATION_VERSION,
  deriveGraphCompleteness,
  knownComponentVersion,
  occurrenceAliasConflict,
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
const SHA256_CONTENT = /^[a-fA-F0-9]{64}$/;

type PreparedComponent = {
  component: NormalizedComponent;
  sha256Hex: ReadonlySet<string> | null;
};

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

function presentVersion(value: string | null | undefined): string | null {
  if (value === undefined || value === null || value.length === 0) {
    return null;
  }
  return value;
}

function resolveObservedVersion(
  listedRaw: string | undefined,
  purlVersion: string | null,
): ParserWorkerFailure | ComponentVersion {
  const listed = presentVersion(listedRaw);
  const purl = presentVersion(purlVersion);
  if (listed !== null && purl !== null && listed !== purl) {
    return parserFailure('component_version_conflict');
  }
  return observedVersion(listed ?? purl ?? undefined);
}

function collectSha256(
  raw: Record<string, unknown>,
): ParserWorkerFailure | { sha256Hex: ReadonlySet<string> | null } {
  const hashes = raw['hashes'];
  if (hashes === undefined) {
    return { sha256Hex: null };
  }
  if (!Array.isArray(hashes)) {
    return parserFailure('schema_invalid');
  }
  const digests = new Set<string>();
  for (const hash of hashes) {
    if (!isObjectRecord(hash)) {
      return parserFailure('schema_invalid');
    }
    if (asString(hash['alg']) !== 'SHA-256') {
      continue;
    }
    const content = asString(hash['content']);
    if (content === undefined || !SHA256_CONTENT.test(content)) {
      return parserFailure('component_hash_conflict');
    }
    digests.add(content.toLowerCase());
  }
  if (digests.size === 0) {
    return { sha256Hex: null };
  }
  if (digests.size > 1) {
    return parserFailure('component_hash_conflict');
  }
  return { sha256Hex: digests };
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

function finishPrepared(
  component: NormalizedComponent,
  sha256Hex: ReadonlySet<string> | null,
): PreparedComponent {
  return { component, sha256Hex };
}

function normalizeOneComponent(
  raw: Record<string, unknown>,
  limits: SbomParserLimits,
): ParserWorkerFailure | PreparedComponent {
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

  const hashes = collectSha256(raw);
  if ('ok' in hashes) {
    return hashes;
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

    const version = resolveObservedVersion(listedVersion, normalized.value.version);
    if ('ok' in version) {
      return version;
    }
    if (version.kind === 'known' && version.value.length > limits.maxVersionChars) {
      return parserFailure('identifier_length');
    }

    let versionedPurl = version.kind === 'known' ? normalized.value.versioned : null;
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

    return finishPrepared(
      {
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
      },
      hashes.sha256Hex,
    );
  }

  const version = resolveObservedVersion(listedVersion, null);
  if ('ok' in version) {
    return version;
  }
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

  return finishPrepared(
    {
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
    },
    hashes.sha256Hex,
  );
}

type CollapsedOccurrence = {
  component: NormalizedComponent;
  sha256Hex: ReadonlySet<string> | null;
  names: string[];
  bomRefs: string[];
};

/**
 * UTF-16 code-unit order. Alias labels must not follow document order.
 */
function earliestText(values: readonly string[]): string | undefined {
  let selected: string | undefined;
  for (const value of values) {
    if (selected === undefined || value < selected) {
      selected = value;
    }
  }
  return selected;
}

function collapseOccurrences(prepared: readonly PreparedComponent[]):
  | ParserWorkerFailure
  | {
      components: NormalizedComponent[];
      bomRefAlias: Map<string, string>;
      duplicateCount: number;
    } {
  const kept: CollapsedOccurrence[] = [];
  const byOccurrence = new Map<string, CollapsedOccurrence>();
  let duplicateCount = 0;

  for (const candidate of prepared) {
    const key = componentOccurrenceNormalizationKey(candidate.component);
    const existing = byOccurrence.get(key);
    if (existing === undefined) {
      const created: CollapsedOccurrence = {
        component: candidate.component,
        sha256Hex: candidate.sha256Hex,
        names: [candidate.component.name],
        bomRefs: candidate.component.bomRef === null ? [] : [candidate.component.bomRef],
      };
      byOccurrence.set(key, created);
      kept.push(created);
      continue;
    }

    const conflict = occurrenceAliasConflict(
      {
        version: existing.component.version,
        versionedPurl: existing.component.versionedPurl,
        sha256Hex: existing.sha256Hex,
      },
      {
        version: candidate.component.version,
        versionedPurl: candidate.component.versionedPurl,
        sha256Hex: candidate.sha256Hex,
      },
    );
    if (conflict === 'sha256') {
      return parserFailure('component_hash_conflict');
    }
    if (conflict !== null) {
      return parserFailure('component_version_conflict');
    }
    if (existing.sha256Hex === null && candidate.sha256Hex !== null) {
      existing.sha256Hex = candidate.sha256Hex;
    }
    if (existing.component.versionedPurl === null && candidate.component.versionedPurl !== null) {
      existing.component.versionedPurl = candidate.component.versionedPurl;
    }

    duplicateCount += 1;
    existing.names.push(candidate.component.name);
    if (candidate.component.bomRef !== null) {
      existing.bomRefs.push(candidate.component.bomRef);
    }
  }

  const bomRefAlias = new Map<string, string>();
  for (const entry of kept) {
    const name = earliestText(entry.names);
    if (name !== undefined) {
      entry.component.name = name;
    }
    const canonicalBomRef = earliestText(entry.bomRefs);
    entry.component.bomRef = canonicalBomRef ?? null;
    if (canonicalBomRef !== undefined) {
      for (const bomRef of entry.bomRefs) {
        bomRefAlias.set(bomRef, canonicalBomRef);
      }
    }
  }

  return {
    components: kept.map((entry) => entry.component),
    bomRefAlias,
    duplicateCount,
  };
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
  if (normalizationVersion !== CURRENT_SBOM_NORMALIZATION_VERSION) {
    return parserFailure('unsupported_normalization_version');
  }
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

  const prepared: PreparedComponent[] = [];
  const seenBomRefs = new Set<string>();
  for (const raw of rawComponents) {
    const component = normalizeOneComponent(raw, limits);
    if ('ok' in component) {
      return component;
    }
    if (component.component.bomRef !== null) {
      if (seenBomRefs.has(component.component.bomRef)) {
        return parserFailure('duplicate_bom_ref');
      }
      seenBomRefs.add(component.component.bomRef);
    }
    prepared.push(component);
  }

  const collapsed = collapseOccurrences(prepared);
  if ('ok' in collapsed) {
    return collapsed;
  }
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
