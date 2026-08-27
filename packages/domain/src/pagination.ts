export const DEFAULT_PAGE_SIZE = 20;
export const MAX_PAGE_SIZE = 100;
export const MIN_PAGE_SIZE = 1;

export type PageRequest = {
  limit?: number;
  afterId?: string;
};

export type Page<T> = {
  items: T[];
  nextCursor: { id: string } | undefined;
};

export function boundPageSize(limit: number | undefined): number {
  if (limit === undefined) {
    return DEFAULT_PAGE_SIZE;
  }

  if (!Number.isInteger(limit) || limit < MIN_PAGE_SIZE) {
    return MIN_PAGE_SIZE;
  }

  if (limit > MAX_PAGE_SIZE) {
    return MAX_PAGE_SIZE;
  }

  return limit;
}
