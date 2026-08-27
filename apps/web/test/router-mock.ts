import { vi } from 'vitest';

export const navigationMocks = {
  replace: vi.fn(),
};

vi.mock('next/navigation', () => ({
  useRouter: () => ({
    replace: navigationMocks.replace,
    push: vi.fn(),
    prefetch: vi.fn(),
    refresh: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
  }),
}));
