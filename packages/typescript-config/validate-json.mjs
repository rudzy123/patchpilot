#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const packageDirectory = path.dirname(fileURLToPath(import.meta.url));
const files = ['base.json', 'library.json', 'node.json', 'nextjs.json'];

for (const fileName of files) {
  const contents = readFileSync(path.join(packageDirectory, fileName), 'utf8');
  const parsed = JSON.parse(contents);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${fileName} must contain a JSON object.`);
  }
}
