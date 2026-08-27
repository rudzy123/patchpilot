import type { PublicConfig } from '@patchpilot/config/public';
import type { ReactElement } from 'react';

export function Landing({ publicConfig }: { publicConfig: PublicConfig }): ReactElement {
  return (
    <main>
      <header>
        <h1>{publicConfig.appName}</h1>
        <p>
          Self-hosted vulnerability prioritization and remediation. The product remains fully useful
          without an AI provider.
        </p>
      </header>
      <p>
        This repository is under active development. Application shells, local infrastructure, and
        health checks are being established. Product workflows are not available yet.
      </p>
      <p>
        Public environment label: <span>{publicConfig.deploymentEnvironment}</span>
      </p>
      <p>
        <a href="/login">Sign in</a>
      </p>
      <p>
        <a href="/health">Service health</a>
      </p>
    </main>
  );
}
