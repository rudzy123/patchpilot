import { baseConfig } from '@patchpilot/eslint-config/base';
import globals from 'globals';

export default [
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/.next/**',
      '**/.turbo/**',
      '**/coverage/**',
      '**/playwright-report/**',
      '**/test-results/**',
      'docs/**',
      'deploy/compose/data/**',
      'packages/sbom/vendor/**',
    ],
  },
  ...baseConfig,
  {
    files: ['scripts/**/*.mjs'],
    languageOptions: {
      globals: {
        ...globals.node,
      },
    },
    rules: {
      'no-restricted-syntax': 'off',
    },
  },
];
