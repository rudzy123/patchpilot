const SAFE_ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

export function isSafeId(value: string): boolean {
  return SAFE_ID_PATTERN.test(value);
}

export function resolveRequestIdentifiers(input: {
  requestIdHeader: string | undefined;
  correlationIdHeader: string | undefined;
  generateId: () => string;
}): {
  requestId: string;
  correlationId: string;
  requestIdGenerated: boolean;
  correlationIdGenerated: boolean;
} {
  const requestIdProvided =
    input.requestIdHeader !== undefined && isSafeId(input.requestIdHeader)
      ? input.requestIdHeader
      : undefined;
  const correlationIdProvided =
    input.correlationIdHeader !== undefined && isSafeId(input.correlationIdHeader)
      ? input.correlationIdHeader
      : undefined;

  if (requestIdProvided !== undefined && correlationIdProvided !== undefined) {
    return {
      requestId: requestIdProvided,
      correlationId: correlationIdProvided,
      requestIdGenerated: false,
      correlationIdGenerated: false,
    };
  }

  if (requestIdProvided !== undefined) {
    return {
      requestId: requestIdProvided,
      correlationId: input.generateId(),
      requestIdGenerated: false,
      correlationIdGenerated: true,
    };
  }

  if (correlationIdProvided !== undefined) {
    return {
      requestId: input.generateId(),
      correlationId: correlationIdProvided,
      requestIdGenerated: true,
      correlationIdGenerated: false,
    };
  }

  const generated = input.generateId();
  return {
    requestId: generated,
    correlationId: generated,
    requestIdGenerated: true,
    correlationIdGenerated: true,
  };
}
