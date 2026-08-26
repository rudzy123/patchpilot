import globals from 'globals';

import { baseConfig } from './base.js';

const processEnvRestriction = {
  selector: 'MemberExpression[object.name="process"][property.name="env"]',
  message: 'Read process.env only in @patchpilot/config.',
};

export const nodeConfig = [
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
        processEnvRestriction,
      ],
    },
  },
];

export default nodeConfig;
