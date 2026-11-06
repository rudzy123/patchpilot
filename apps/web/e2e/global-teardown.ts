import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export default function globalTeardown(): void {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
  execFileSync(
    'pnpm',
    [
      '--filter',
      '@patchpilot/api',
      'exec',
      'tsx',
      '../../packages/database/src/release-smoke-fixture.ts',
      'drop',
    ],
    {
      cwd: root,
      stdio: 'inherit',
      env: process.env,
    },
  );
}
