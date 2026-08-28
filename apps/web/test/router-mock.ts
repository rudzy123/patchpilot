import { vi } from 'vitest';

export const navigationMocks = {
  replace: vi.fn(),
  push: vi.fn(),
};

vi.mock('next/navigation', () => ({
  useRouter: () => ({
    replace: navigationMocks.replace,
    push: navigationMocks.push,
    prefetch: vi.fn(),
    refresh: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
  }),
}));
