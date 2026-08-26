#!/usr/bin/env node

import { rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const pathsToRemove = ['.turbo', 'node_modules/.cache', 'coverage'];

for (const relativePath of pathsToRemove) {
  rmSync(path.join(rootDirectory, relativePath), { recursive: true, force: true });
}
