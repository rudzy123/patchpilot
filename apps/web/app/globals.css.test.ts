import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

describe('web focus styles', () => {
  it('defines a visible :focus-visible outline for links', () => {
    const css = readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), 'globals.css'),
      'utf8',
    );
    expect(css).toContain('a:focus-visible');
    expect(css).toContain('outline');
  });
});
