import assert from 'node:assert/strict';
import test from 'node:test';

import { libraryConfig } from './library.js';

test('library ESLint config forbids database and application imports', () => {
  const names = [];
  for (const entry of libraryConfig) {
    const rule = entry.rules?.['no-restricted-imports'];
    if (!Array.isArray(rule) || rule.length < 2) {
      continue;
    }

    const options = rule[1];
    if (options && typeof options === 'object' && Array.isArray(options.paths)) {
      for (const path of options.paths) {
        if (path && typeof path === 'object' && typeof path.name === 'string') {
          names.push(path.name);
        }
      }
    }
  }

  assert.ok(names.includes('@patchpilot/database'));
  assert.ok(names.includes('@patchpilot/api'));
  assert.ok(names.includes('@patchpilot/web'));
  assert.ok(names.includes('@patchpilot/worker'));
});
