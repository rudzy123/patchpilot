import type { ReactElement } from 'react';

import { AssetDetailPageClient } from './asset-detail-page-client';

export default async function AssetDetailPage({
  params,
}: {
  params: Promise<{ assetId: string }>;
}): Promise<ReactElement> {
  const { assetId } = await params;
  return <AssetDetailPageClient key={assetId} assetId={assetId} />;
}
