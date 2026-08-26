import { libraryConfig } from '@patchpilot/eslint-config/library';

export default [
  {
    ignores: ['dist/**', 'coverage/**'],
  },
  ...libraryConfig,
  {
    files: ['src/**/*.test.ts'],
    rules: {
      'no-restricted-syntax': 'off',
    },
  },
];
