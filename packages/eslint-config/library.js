import { nodeConfig } from './node.js';

export const libraryConfig = [
  ...nodeConfig,
  {
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: 'fastify',
              message: 'Library packages must not import Fastify.',
            },
            {
              name: 'next',
              message: 'Library packages must not import Next.js.',
            },
            {
              name: '@prisma/client',
              message: 'Library packages must not import Prisma. Use a port and adapter.',
            },
            {
              name: 'ioredis',
              message: 'Library packages must not import Redis clients.',
            },
            {
              name: 'bullmq',
              message: 'Library packages must not import BullMQ.',
            },
            {
              name: 'minio',
              message: 'Library packages must not import MinIO.',
            },
          ],
          patterns: [
            {
              group: ['fastify/*', 'next/*', '@prisma/*', 'ioredis/*', 'bullmq/*', 'minio/*'],
              message:
                'Library packages must not import application frameworks or infrastructure SDKs.',
            },
          ],
        },
      ],
    },
  },
];

export default libraryConfig;
