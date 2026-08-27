/**
 * Direct socket peer IP for login rate limits. Fastify `trustProxy` stays false;
 * callers must pass `socket.remoteAddress`, never `X-Forwarded-For`.
 */
export type DirectPeerIpInput = {
  socketRemoteAddress: string | undefined;
  /**
   * Accepted only so HTTP adapters can pass request headers without this
   * selector reading them. Must not influence the returned IP.
   */
  xForwardedFor?: string;
};

export function selectDirectPeerIp(input: DirectPeerIpInput): string | undefined {
  const peer = normalizeDirectPeerIp(input.socketRemoteAddress);
  if (peer === undefined) {
    return undefined;
  }

  return peer;
}

export function normalizeDirectPeerIp(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }

  let peer = value.trim();
  if (peer.length === 0) {
    return undefined;
  }

  if (peer.includes(',')) {
    return undefined;
  }

  if (peer.startsWith('[') && peer.endsWith(']')) {
    peer = peer.slice(1, -1);
  }

  const zoneIndex = peer.indexOf('%');
  if (zoneIndex >= 0) {
    peer = peer.slice(0, zoneIndex);
  }

  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(peer);
  const ipv4 = mapped?.[1];
  if (ipv4 !== undefined) {
    return ipv4;
  }

  return peer;
}
