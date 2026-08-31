import type { SbomConfig } from '@patchpilot/config';
import type { SbomParserLimits } from '@patchpilot/domain';

type SbomParserLimitSource = Pick<
  SbomConfig,
  | 'uploadMaxBytes'
  | 'jsonMaxDepth'
  | 'jsonMaxNodes'
  | 'jsonMaxStringBytes'
  | 'maxComponents'
  | 'maxDependencyEdges'
  | 'maxBomRefBytes'
  | 'maxPurlBytes'
  | 'maxComponentNameChars'
  | 'maxVersionChars'
  | 'maxMetadataTools'
  | 'maxExternalRefsPerComponent'
  | 'maxPropertiesPerComponent'
>;

export function sbomParserLimitsFromConfig(sbom: SbomParserLimitSource): SbomParserLimits {
  return {
    maxBytes: sbom.uploadMaxBytes,
    jsonMaxDepth: sbom.jsonMaxDepth,
    jsonMaxNodes: sbom.jsonMaxNodes,
    jsonMaxStringBytes: sbom.jsonMaxStringBytes,
    maxComponents: sbom.maxComponents,
    maxDependencyEdges: sbom.maxDependencyEdges,
    maxBomRefBytes: sbom.maxBomRefBytes,
    maxPurlBytes: sbom.maxPurlBytes,
    maxComponentNameChars: sbom.maxComponentNameChars,
    maxVersionChars: sbom.maxVersionChars,
    maxMetadataTools: sbom.maxMetadataTools,
    maxExternalRefsPerComponent: sbom.maxExternalRefsPerComponent,
    maxPropertiesPerComponent: sbom.maxPropertiesPerComponent,
  };
}
