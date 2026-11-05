import type { ReactElement } from 'react';

import { ProductMatchEvaluationsPageClient } from './product-match-evaluations-page-client';

export default async function ProductMatchEvaluationsPage({
  params,
}: {
  params: Promise<{ assetId: string }>;
}): Promise<ReactElement> {
  const { assetId } = await params;
  return <ProductMatchEvaluationsPageClient key={assetId} assetId={assetId} />;
}
