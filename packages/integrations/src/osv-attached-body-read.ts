/**
 * Session 11 Batch 6B attached-body read adapter. Resume-safe SHA-256
 * read-back of immutable advisory bodies. Does not list GCS, retrieve from
 * the provider, or change write-once storage identity.
 */

import {
  createOsvStorageBoundedInput,
  OSV_OBJECT_STORAGE_LAYOUT_VERSION,
  OSV_PROVIDER_BODY_STORAGE_MAX_BYTES,
  type OsvAttachedBodyReadPort,
} from '@patchpilot/vulnerability-intelligence';

import type { S3OsvAdvisoryObjectStorage } from './s3-osv-advisory-object-storage.js';

const CONTENT_TYPE = 'application/json';
const CONTENT_ENCODING = 'identity';

export function createOsvAttachedBodyReadPort(
  storage: S3OsvAdvisoryObjectStorage,
): OsvAttachedBodyReadPort {
  return {
    async readAttachedAdvisoryBody(input) {
      const read = await storage.readVerifiedBody({
        locator: input.locator,
        expectedSha256: input.expectedSha256,
        expectedByteCount: input.expectedByteCount,
        expectedContentType: CONTENT_TYPE,
        expectedContentEncoding: CONTENT_ENCODING,
        maxBytes: OSV_PROVIDER_BODY_STORAGE_MAX_BYTES,
      });
      if (!read.ok) {
        return null;
      }
      const bounded = createOsvStorageBoundedInput({
        bytes: read.value.bytes,
        artifactCategory: 'advisory_body',
        contentType: CONTENT_TYPE,
        contentEncoding: CONTENT_ENCODING,
        layoutVersion: OSV_OBJECT_STORAGE_LAYOUT_VERSION,
        byteCount: read.value.byteCount,
        sha256: read.value.sha256,
      });
      return bounded.ok ? bounded.value : null;
    },
  };
}
