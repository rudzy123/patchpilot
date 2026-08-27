import { boundPageSize, type Page, type PageRequest } from '@patchpilot/domain';

export { boundPageSize, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE } from '@patchpilot/domain';

export async function paginateById<T extends { id: string }>(
  query: (args: { take: number; cursorId: string | undefined }) => Promise<T[]>,
  page: PageRequest | undefined,
): Promise<Page<T>> {
  const limit = boundPageSize(page?.limit);
  const items = await query({
    take: limit + 1,
    cursorId: page?.afterId,
  });

  if (items.length > limit) {
    const pageItems = items.slice(0, limit);
    const last = pageItems[pageItems.length - 1];
    return {
      items: pageItems,
      nextCursor: last === undefined ? undefined : { id: last.id },
    };
  }

  return { items, nextCursor: undefined };
}

export function afterIdWhere(
  cursorId: string | undefined,
): { id: { gt: string } } | Record<string, never> {
  if (cursorId === undefined) {
    return {};
  }

  return { id: { gt: cursorId } };
}
