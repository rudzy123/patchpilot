import { nodeConfig } from '@patchpilot/eslint-config/node';

export default [
  {
    ignores: ['dist/**', 'coverage/**', 'src/generated/**'],
  },
  ...nodeConfig,
];
