import { register } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const hooksPath = join(
  dirname(fileURLToPath(import.meta.url)),
  'integration-typescript-resolver-hooks.mjs',
);
register(pathToFileURL(hooksPath).href);
