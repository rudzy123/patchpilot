import { describe, expect, it } from 'vitest';

import {
  SBOM_JSON_MAX_DEPTH_DEFAULT,
  SBOM_JSON_MAX_NODES_DEFAULT,
  SBOM_JSON_MAX_STRING_BYTES_DEFAULT,
  SBOM_MAX_BOM_REF_BYTES_DEFAULT,
  SBOM_MAX_COMPONENTS_DEFAULT,
  SBOM_MAX_COMPONENT_NAME_CHARS_DEFAULT,
  SBOM_MAX_DEPENDENCY_EDGES_DEFAULT,
  SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_DEFAULT,
  SBOM_MAX_METADATA_TOOLS_DEFAULT,
  SBOM_MAX_PROPERTIES_PER_COMPONENT_DEFAULT,
  SBOM_MAX_PURL_BYTES_DEFAULT,
  SBOM_MAX_VERSION_CHARS_DEFAULT,
  SBOM_UPLOAD_MAX_BYTES_DEFAULT,
} from '@patchpilot/config';

import { sbomParserLimitsFromConfig } from './parser-limits.js';

describe('sbomParserLimitsFromConfig', () => {
  it('maps typed SBOM config onto parser limits', () => {
    const sbom = {
      uploadMaxBytes: SBOM_UPLOAD_MAX_BYTES_DEFAULT,
      jsonMaxDepth: SBOM_JSON_MAX_DEPTH_DEFAULT,
      jsonMaxNodes: SBOM_JSON_MAX_NODES_DEFAULT,
      jsonMaxStringBytes: SBOM_JSON_MAX_STRING_BYTES_DEFAULT,
      maxComponents: SBOM_MAX_COMPONENTS_DEFAULT,
      maxDependencyEdges: SBOM_MAX_DEPENDENCY_EDGES_DEFAULT,
      maxBomRefBytes: SBOM_MAX_BOM_REF_BYTES_DEFAULT,
      maxPurlBytes: SBOM_MAX_PURL_BYTES_DEFAULT,
      maxComponentNameChars: SBOM_MAX_COMPONENT_NAME_CHARS_DEFAULT,
      maxVersionChars: SBOM_MAX_VERSION_CHARS_DEFAULT,
      maxMetadataTools: SBOM_MAX_METADATA_TOOLS_DEFAULT,
      maxExternalRefsPerComponent: SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_DEFAULT,
      maxPropertiesPerComponent: SBOM_MAX_PROPERTIES_PER_COMPONENT_DEFAULT,
    };
    expect(sbomParserLimitsFromConfig(sbom).maxBytes).toBe(SBOM_UPLOAD_MAX_BYTES_DEFAULT);
    expect(sbomParserLimitsFromConfig(sbom).maxComponents).toBe(SBOM_MAX_COMPONENTS_DEFAULT);
  });
});
