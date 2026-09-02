import { libraryConfig } from '@patchpilot/eslint-config/library';

export default [
  {
    ignores: ['dist/**', 'coverage/**'],
  },
  ...libraryConfig,
  {
    files: ['src/**/*.test.ts', 'src/**/*.integration.test.ts'],
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
