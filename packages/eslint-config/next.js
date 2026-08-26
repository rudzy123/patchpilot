import globals from 'globals';

import { baseConfig } from './base.js';

export const nextConfig = [
  ...baseConfig,
  {
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: '@patchpilot/config',
              message:
                'Import @patchpilot/config/public only. Server configuration must not enter the web app.',
            },
            {
              name: '@prisma/client',
              message: 'The web app must not import Prisma. Call apps/api instead.',
            },
            {
              name: '@patchpilot/database',
              message: 'The web app must not import Prisma persistence. Call apps/api instead.',
            },
            {
              name: 'fastify',
              message: 'The web app must not import the API framework.',
            },
            {
              name: 'ioredis',
              message: 'The web app must not import Redis.',
            },
            {
              name: 'bullmq',
              message: 'The web app must not import BullMQ.',
            },
          ],
          patterns: [
            {
              group: ['@patchpilot/config/server', '@patchpilot/config/env'],
              message: 'Browser and Next.js client code may import public configuration only.',
            },
            {
              group: ['@prisma/*', 'fastify/*', 'bullmq/*', 'ioredis/*'],
              message: 'The web app must not import server infrastructure SDKs.',
            },
          ],
        },
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: 'MemberExpression[object.name="process"][property.name="env"]',
          message:
            'Read process.env only in @patchpilot/config. The web app must use typed public configuration.',
        },
      ],
    },
  },
];

export default nextConfig;
