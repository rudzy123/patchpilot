import type { ReactElement } from 'react';

import { ControlledFindingTargetsPageClient } from './controlled-finding-targets-page-client';

export default async function ControlledFindingTargetsPage({
  params,
}: {
  params: Promise<{ assetId: string }>;
}): Promise<ReactElement> {
  const { assetId } = await params;
  return <ControlledFindingTargetsPageClient key={assetId} assetId={assetId} />;
}
