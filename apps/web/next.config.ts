import type { NextConfig } from 'next';

const frameAncestorsHeader = {
  key: 'Content-Security-Policy',
  value: "frame-ancestors 'none'",
} as const;

const nextConfig: NextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  transpilePackages: ['@patchpilot/config', '@patchpilot/contracts'],
  agentRules: false,
  async headers() {
    return [
      { source: '/', headers: [frameAncestorsHeader] },
      { source: '/:path*', headers: [frameAncestorsHeader] },
    ];
  },
};

export default nextConfig;
