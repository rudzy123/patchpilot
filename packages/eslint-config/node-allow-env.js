import globals from 'globals';

import { baseConfig } from './base.js';

export const nodeAllowEnvConfig = [
  ...baseConfig,
  {
    languageOptions: {
      globals: {
        ...globals.node,
      },
    },
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

export default nodeAllowEnvConfig;
