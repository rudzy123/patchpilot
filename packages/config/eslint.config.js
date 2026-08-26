import { nodeAllowEnvConfig } from '@patchpilot/eslint-config/node-allow-env';

export default [
  {
    ignores: ['dist/**', 'coverage/**'],
  },
  ...nodeAllowEnvConfig,
];
