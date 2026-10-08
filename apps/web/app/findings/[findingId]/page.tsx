import type { ReactElement } from 'react';

import { FindingInspectionPageClient } from './finding-inspection-page-client';

export default async function FindingInspectionPage({
  params,
}: {
  params: Promise<{ findingId: string }>;
}): Promise<ReactElement> {
  const { findingId } = await params;
  return <FindingInspectionPageClient key={findingId} findingId={findingId} />;
}
