import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  transpilePackages: ['@patchpilot/config', '@patchpilot/contracts'],
};

export default nextConfig;
