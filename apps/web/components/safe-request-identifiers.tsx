import type { ReactElement } from 'react';

export function SafeRequestIdentifiers({
  requestId,
  correlationId,
}: {
  requestId: string | null;
  correlationId: string | null;
}): ReactElement | null {
  if (requestId === null && correlationId === null) {
    return null;
  }

  const parts = [
    requestId === null ? null : `Request ID: ${requestId}`,
    correlationId === null ? null : `Correlation ID: ${correlationId}`,
  ].filter((part) => part !== null);

  return <p>{parts.join(' ')}</p>;
}
