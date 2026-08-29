import { fileURLToPath } from 'node:url';

export const VENDOR_CYCLONEDX_JSON_SCHEMA_DIRECTORY = fileURLToPath(
  new URL('../vendor/cyclonedx-json-schema/', import.meta.url),
);
