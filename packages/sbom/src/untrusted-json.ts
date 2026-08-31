import secureJsonParse from 'secure-json-parse';

const PARSE_OPTIONS = {
  protoAction: 'error',
  constructorAction: 'error',
} as const;

export function parseUntrustedJson(text: string): unknown {
  return secureJsonParse(text, PARSE_OPTIONS);
}
