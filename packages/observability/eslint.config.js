import { nodeConfig } from '@patchpilot/eslint-config/node';

export default [
  {
    ignores: ['dist/**', 'coverage/**'],
  },
  ...nodeConfig,
  {
    files: ['src/**/*.test.ts'],
    rules: {
      'no-restricted-syntax': [
        'error',
        {
          selector:
            'CallExpression[callee.object.name="console"][callee.property.name=/^(debug|info|warn|error|log)$/]',
          message: 'Use @patchpilot/logger instead of console in application code.',
        },
      ],
    },
  },
];
