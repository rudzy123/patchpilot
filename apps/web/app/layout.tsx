import type { Metadata } from 'next';
import type { ReactElement, ReactNode } from 'react';

import { loadPublicConfig } from '@patchpilot/config/public';

import { AppProviders } from '../components/app-providers';
import './globals.css';

export const metadata: Metadata = {
  title: 'PatchPilot',
  description:
    'Self-hosted vulnerability prioritization and remediation. Fully useful without an AI provider.',
};

export default function RootLayout({ children }: { children: ReactNode }): ReactElement {
  const publicConfig = loadPublicConfig();
  return (
    <html lang="en">
      <body>
        <AppProviders apiBaseUrl={publicConfig.apiBaseUrl}>{children}</AppProviders>
      </body>
    </html>
  );
}
