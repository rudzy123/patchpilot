import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  transpilePackages: ['@patchpilot/config', '@patchpilot/contracts'],
  agentRules: false,
};

export default nextConfig;
