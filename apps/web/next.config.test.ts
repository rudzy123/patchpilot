import { describe, expect, it } from 'vitest';

import nextConfig from './next.config';

describe('web clickjacking header', () => {
  it('sets Content-Security-Policy frame-ancestors none on every route', async () => {
    expect(nextConfig.headers).toEqual(expect.any(Function));
    const headers = await nextConfig.headers?.();
    expect(headers).toEqual([
      {
        source: '/',
        headers: [{ key: 'Content-Security-Policy', value: "frame-ancestors 'none'" }],
      },
      {
        source: '/:path*',
        headers: [{ key: 'Content-Security-Policy', value: "frame-ancestors 'none'" }],
      },
    ]);
    const serialized = JSON.stringify(headers);
    expect(serialized).not.toContain('unsafe-inline');
    expect(serialized).not.toContain('script-src');
  });
});
