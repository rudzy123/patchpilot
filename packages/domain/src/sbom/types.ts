import type { Page } from '../pagination.js';
import type { SbomSpecificationVersion } from '../lifecycle.js';
import { SBOM_LIST_CURSOR_VERSION } from './constants.js';
import type { NormalizedComponentGraph } from './graph.js';

export type SbomListCursor = {
  v: typeof SBOM_LIST_CURSOR_VERSION;
  r: string;
  i: string;
};

export type SbomListQuery = {
  limit: number;
  cursor?: SbomListCursor;
};

export type SbomListPage = {
  items: SbomSummaryRecord[];
  nextCursor: SbomListCursor | undefined;
};

export type SbomSummaryRecord = {
  id: string;
  organizationId: string;
  assetId: string;
  sha256: string;
  byteLength: number;
  specificationType: 'cyclonedx';
  specificationVersion: SbomSpecificationVersion | null;
  source: 'upload' | 'reprocess';
  receivedAt: Date;
  capturedAt: Date | null;
  parserVersionLastSucceeded: string | null;
};

export type SbomParserLimits = {
  maxBytes: number;
  jsonMaxDepth: number;
  jsonMaxNodes: number;
  jsonMaxStringBytes: number;
  maxComponents: number;
  maxDependencyEdges: number;
  maxBomRefBytes: number;
  maxPurlBytes: number;
  maxComponentNameChars: number;
  maxVersionChars: number;
  maxMetadataTools: number;
  maxExternalRefsPerComponent: number;
  maxPropertiesPerComponent: number;
};

export type PersistNormalizedGraphInput = {
  organizationId: string;
  assetId: string;
  sbomId: string;
  sbomIngestionId: string;
  graph: NormalizedComponentGraph;
};

export type ComponentGraphPage = Page<{
  identityKey: string;
  name: string;
  identityState: 'resolved' | 'ambiguous' | 'unsupported';
}>;
