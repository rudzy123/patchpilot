import { nodeConfig } from '@patchpilot/eslint-config/node';

export default [
  {
    ignores: [
      'dist/**',
      'coverage/**',
      'src/generated/**',
      'src/osv-bounded-listing-canary-operator-main.ts',
    ],
  },
  ...nodeConfig,
];
