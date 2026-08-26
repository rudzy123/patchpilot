import { nextConfig } from '@patchpilot/eslint-config/next';
import nextVitals from 'eslint-config-next/core-web-vitals';
import nextTs from 'eslint-config-next/typescript';

const eslintConfig = [
  {
    ignores: [
      '.next/**',
      'coverage/**',
      'playwright-report/**',
      'test-results/**',
      'next-env.d.ts',
    ],
  },
  ...nextConfig,
  ...nextVitals,
  ...nextTs,
];

export default eslintConfig;
