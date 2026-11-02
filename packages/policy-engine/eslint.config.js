import { libraryConfig } from '@patchpilot/eslint-config/library';

// Flat config replaces `no-restricted-imports` instead of merging options.
// Repeat the library paths, then add this package's boundary.
const libraryRestrictedImportPaths = [
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
  {
    name: '@patchpilot/database',
    message: 'Library packages must not import Prisma persistence. Depend on a port instead.',
  },
  {
    name: '@patchpilot/api',
    message: 'Packages must not depend on applications.',
  },
  {
    name: '@patchpilot/web',
    message: 'Packages must not depend on applications.',
  },
  {
    name: '@patchpilot/worker',
    message: 'Packages must not depend on applications.',
  },
];

const libraryRestrictedImportPatterns = [
  {
    group: [
      'fastify/*',
      'next/*',
      '@prisma/*',
      'ioredis/*',
      'bullmq/*',
      'minio/*',
      '@patchpilot/database/*',
      '@patchpilot/api/*',
      '@patchpilot/web/*',
      '@patchpilot/worker/*',
    ],
    message:
      'Library packages must not import application frameworks, apps, or infrastructure SDKs.',
  },
];

const policyEngineRestrictedImportPaths = [
  ...libraryRestrictedImportPaths,
  {
    name: '@patchpilot/domain',
    message:
      'The policy engine must not import @patchpilot/domain. Domain defines a port and the worker injects this engine.',
  },
  {
    name: '@patchpilot/config',
    message:
      'The policy engine must not import @patchpilot/config. This package reads no environment configuration.',
  },
];

const policyEngineRestrictedImportPatterns = [
  ...libraryRestrictedImportPatterns,
  {
    group: ['@patchpilot/domain/*', '@patchpilot/config/*'],
    message: 'The policy engine must not import @patchpilot/domain or @patchpilot/config.',
  },
];

const nodeBuiltinImportPattern = {
  group: ['node:*', 'node:*/*'],
  message: 'The policy engine must not import Node.js built-in modules.',
};

/**
 * @param {Array<{ group: string[], message: string }>} patterns
 */
function restrictedImports(patterns) {
  return [
    'error',
    {
      paths: policyEngineRestrictedImportPaths,
      patterns,
    },
  ];
}

export default [
  {
    ignores: ['dist/**', 'coverage/**'],
  },
  ...libraryConfig,
  {
    rules: {
      'no-restricted-imports': restrictedImports([
        ...policyEngineRestrictedImportPatterns,
        nodeBuiltinImportPattern,
      ]),
    },
  },
  {
    // package-boundary.test.ts reads the tree through node:fs. Engine source stays restricted.
    files: ['src/**/*.test.ts'],
    rules: {
      'no-restricted-imports': restrictedImports(policyEngineRestrictedImportPatterns),
    },
  },
];
