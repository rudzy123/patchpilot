import { libraryConfig } from '@patchpilot/eslint-config/library';

export default [
  {
    ignores: ['dist/**', 'coverage/**'],
  },
  ...libraryConfig,
];
