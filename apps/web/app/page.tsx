import { loadPublicConfig } from '@patchpilot/config/public';
import type { ReactElement } from 'react';

import { Landing } from './landing';

export default function HomePage(): ReactElement {
  return <Landing publicConfig={loadPublicConfig()} />;
}
