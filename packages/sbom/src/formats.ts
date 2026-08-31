/**
 * Syntactic format checks used by vendored CycloneDX JSON schemas.
 * A format-valid IRI or email is never treated as permission to fetch, resolve
 * DNS, or deliver mail.
 */

function hasAsciiControlOrSpace(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x20 || code === 0x7f) {
      return true;
    }
  }
  return false;
}

export function isSyntacticIriReference(value: string): boolean {
  return !hasAsciiControlOrSpace(value);
}

export function isSyntacticIdnEmail(value: string): boolean {
  if (hasAsciiControlOrSpace(value)) {
    return false;
  }
  const at = value.lastIndexOf('@');
  return at > 0 && at < value.length - 1;
}
