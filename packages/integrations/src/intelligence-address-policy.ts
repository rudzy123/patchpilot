import { isIP } from 'node:net';

export type IntelligenceIpFamily = 4 | 6;

export type IntelligenceResolvedAddress = {
  address: string;
  family: IntelligenceIpFamily;
};

const IPV4_BLOCKED_CIDRS = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.0.0.0/24',
  '192.0.2.0/24',
  '192.88.99.0/24',
  '192.168.0.0/16',
  '198.18.0.0/15',
  '198.51.100.0/24',
  '203.0.113.0/24',
  '224.0.0.0/4',
  '240.0.0.0/4',
] as const;

const IPV4_METADATA = '169.254.169.254';
const IPV4_BROADCAST = '255.255.255.255';

const IPV6_UNSPECIFIED = 0n;
const IPV6_LOOPBACK = 1n;
const IPV6_ULA_PREFIX = 0xfc00n << 112n;
const IPV6_ULA_MASK = 0xfe00n << 112n;
const IPV6_LINK_LOCAL_PREFIX = 0xfe80n << 112n;
const IPV6_LINK_LOCAL_MASK = 0xffc0n << 112n;
const IPV6_MULTICAST_PREFIX = 0xff00n << 112n;
const IPV6_MULTICAST_MASK = 0xff00n << 112n;
const IPV6_DOCUMENTATION_PREFIX = 0x2001_0db8n << 96n;
const IPV6_DOCUMENTATION_MASK = 0xffff_ffffn << 96n;
const IPV6_DOCUMENTATION_V2_PREFIX = 0x3fff0n << 108n;
const IPV6_DOCUMENTATION_V2_MASK = 0xfffffn << 108n;
const IPV6_DISCARD_PREFIX = 0x0100n << 112n;
const IPV6_DISCARD_MASK = 0xffff_ffff_ffff_ffffn << 64n;
const IPV6_SITE_LOCAL_PREFIX = 0xfec0n << 112n;
const IPV6_TEREDO_PREFIX = 0x2001_0000n << 96n;
const IPV6_TEREDO_MASK = 0xffff_ffffn << 96n;
const IPV6_6TO4_PREFIX = 0x2002n << 112n;
const IPV6_6TO4_MASK = 0xffffn << 112n;
const IPV6_PREFIX_96_MASK = ((1n << 96n) - 1n) << 32n;
const IPV6_MAPPED_PREFIX = 0xffffn << 32n;
const IPV6_NAT64_PREFIX = 0x64_ff9bn << 96n;
const IPV6_NAT64_LOCAL_PREFIX = 0x0064_ff9b_0001n << 80n;
const IPV6_NAT64_LOCAL_MASK = ((1n << 48n) - 1n) << 80n;
const IPV6_AWS_IMDS = 0xfd00_0ec2n << 96n;

function ipv4ToInt(address: string): number | undefined {
  const parts = address.split('.');
  if (parts.length !== 4) {
    return undefined;
  }

  let value = 0;
  for (const part of parts) {
    if (part.length === 0 || (part.length > 1 && part.startsWith('0'))) {
      return undefined;
    }

    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
      return undefined;
    }

    value = (value << 8) + octet;
  }

  return value >>> 0;
}

function ipv4InCidr(addressInt: number, cidr: string): boolean {
  const [prefix, bitsText] = cidr.split('/');
  if (prefix === undefined || bitsText === undefined) {
    return false;
  }

  const prefixInt = ipv4ToInt(prefix);
  const bits = Number(bitsText);
  if (prefixInt === undefined || !Number.isInteger(bits) || bits < 0 || bits > 32) {
    return false;
  }

  if (bits === 0) {
    return true;
  }

  const mask = bits === 32 ? 0xffffffff : ~((1 << (32 - bits)) - 1) >>> 0;
  return (addressInt & mask) === (prefixInt & mask);
}

function expandIpv6Groups(address: string): string[] | undefined {
  const explicitIpv4 = address.includes('.')
    ? address.slice(address.lastIndexOf(':') + 1)
    : undefined;
  const ipv6Part =
    explicitIpv4 === undefined ? address : address.slice(0, address.lastIndexOf(':'));
  if (explicitIpv4 !== undefined) {
    const ipv4 = ipv4ToInt(explicitIpv4);
    if (ipv4 === undefined) {
      return undefined;
    }

    const high = ((ipv4 >>> 16) & 0xffff).toString(16);
    const low = (ipv4 & 0xffff).toString(16);
    return expandIpv6Groups(`${ipv6Part}:${high}:${low}`);
  }

  if ((ipv6Part.match(/::/g) ?? []).length > 1) {
    return undefined;
  }

  const [left, right] = ipv6Part.split('::');
  const leftGroups = left === undefined || left === '' ? [] : left.split(':');
  const rightGroups = right === undefined || right === '' ? [] : right.split(':');
  if (leftGroups.length + rightGroups.length > 8) {
    return undefined;
  }

  const missing = 8 - leftGroups.length - rightGroups.length;
  const groups = [...leftGroups, ...Array.from({ length: missing }, () => '0'), ...rightGroups];
  if (groups.length !== 8) {
    return undefined;
  }

  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) {
      return undefined;
    }
  }

  return groups;
}

function parseIpv6ToBigInt(address: string): bigint | undefined {
  const groups = expandIpv6Groups(address);
  if (groups === undefined) {
    return undefined;
  }

  return groups.reduce((sum, group) => (sum << 16n) + BigInt(Number.parseInt(group, 16)), 0n);
}

function extractEmbeddedIpv4(
  value: bigint,
  prefixMask: bigint,
  prefix: bigint,
): string | undefined {
  if ((value & prefixMask) !== prefix) {
    return undefined;
  }

  const ipv4 = Number(value & 0xffffffffn);
  return [(ipv4 >>> 24) & 0xff, (ipv4 >>> 16) & 0xff, (ipv4 >>> 8) & 0xff, ipv4 & 0xff].join('.');
}

export function isApprovedPublicIpv4(address: string): boolean {
  if (isIP(address) !== 4 || address === IPV4_METADATA || address === IPV4_BROADCAST) {
    return false;
  }

  const value = ipv4ToInt(address);
  if (value === undefined) {
    return false;
  }

  return !IPV4_BLOCKED_CIDRS.some((cidr) => ipv4InCidr(value, cidr));
}

export function isApprovedPublicIpv6(address: string): boolean {
  if (isIP(address) !== 6) {
    return false;
  }

  const value = parseIpv6ToBigInt(address);
  if (value === undefined) {
    return false;
  }

  if (
    value === IPV6_UNSPECIFIED ||
    value === IPV6_LOOPBACK ||
    (value & IPV6_ULA_MASK) === IPV6_ULA_PREFIX ||
    (value & IPV6_LINK_LOCAL_MASK) === IPV6_LINK_LOCAL_PREFIX ||
    (value & IPV6_LINK_LOCAL_MASK) === IPV6_SITE_LOCAL_PREFIX ||
    (value & IPV6_MULTICAST_MASK) === IPV6_MULTICAST_PREFIX ||
    (value & IPV6_DOCUMENTATION_MASK) === IPV6_DOCUMENTATION_PREFIX ||
    (value & IPV6_DOCUMENTATION_V2_MASK) === IPV6_DOCUMENTATION_V2_PREFIX ||
    (value & IPV6_DISCARD_MASK) === IPV6_DISCARD_PREFIX ||
    (value & IPV6_TEREDO_MASK) === IPV6_TEREDO_PREFIX ||
    value === IPV6_AWS_IMDS
  ) {
    return false;
  }

  const mapped = extractEmbeddedIpv4(value, IPV6_PREFIX_96_MASK, IPV6_MAPPED_PREFIX);
  if (mapped !== undefined) {
    return isApprovedPublicIpv4(mapped);
  }

  const nat64 = extractEmbeddedIpv4(value, IPV6_PREFIX_96_MASK, IPV6_NAT64_PREFIX);
  if (nat64 !== undefined) {
    return isApprovedPublicIpv4(nat64);
  }

  const nat64Local = extractEmbeddedIpv4(value, IPV6_NAT64_LOCAL_MASK, IPV6_NAT64_LOCAL_PREFIX);
  if (nat64Local !== undefined) {
    return isApprovedPublicIpv4(nat64Local);
  }

  if ((value & IPV6_6TO4_MASK) === IPV6_6TO4_PREFIX) {
    const embedded = Number((value >> 80n) & 0xffffffffn);
    const sixToFour = [
      (embedded >>> 24) & 0xff,
      (embedded >>> 16) & 0xff,
      (embedded >>> 8) & 0xff,
      embedded & 0xff,
    ].join('.');
    return isApprovedPublicIpv4(sixToFour);
  }

  /**
   * IPv4-compatible IPv6 (RFC 4291, deprecated): high 96 bits are zero and
   * the low 32 bits are an IPv4 address (`::10.0.0.1`). Distinct from
   * IPv4-mapped (`::ffff:x.x.x.x`), NAT64 (`64:ff9b::/96`), and 6to4
   * (`2002::/16`). Ordinary public native IPv6 has a non-zero high 96 bits
   * and is not treated as embedded IPv4. `::` and `::1` are rejected above.
   */
  const ipv4Compatible = extractEmbeddedIpv4(value, IPV6_PREFIX_96_MASK, 0n);
  if (ipv4Compatible !== undefined) {
    return isApprovedPublicIpv4(ipv4Compatible);
  }

  return true;
}

export function isApprovedPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) {
    return isApprovedPublicIpv4(address);
  }

  if (family === 6) {
    return isApprovedPublicIpv6(address);
  }

  return false;
}

export function selectPinnedPublicAddress(
  addresses: readonly IntelligenceResolvedAddress[],
): IntelligenceResolvedAddress | undefined {
  const ipv4 = addresses.find((entry) => entry.family === 4 && isApprovedPublicIpv4(entry.address));
  if (ipv4 !== undefined) {
    return ipv4;
  }

  return addresses.find((entry) => entry.family === 6 && isApprovedPublicIpv6(entry.address));
}

export function canonicalSocketAddress(
  remoteAddress: string | undefined,
  remoteFamily: string | undefined,
): IntelligenceResolvedAddress | undefined {
  if (remoteAddress === undefined) {
    return undefined;
  }

  if (remoteFamily === 'IPv4' || isIP(remoteAddress) === 4) {
    return { address: remoteAddress, family: 4 };
  }

  if (remoteFamily === 'IPv6' || isIP(remoteAddress) === 6) {
    const mapped = extractEmbeddedIpv4(
      parseIpv6ToBigInt(remoteAddress) ?? -1n,
      IPV6_PREFIX_96_MASK,
      IPV6_MAPPED_PREFIX,
    );
    if (mapped !== undefined) {
      return { address: mapped, family: 4 };
    }

    return { address: remoteAddress, family: 6 };
  }

  return undefined;
}

export function pinnedAddressMatchesSocket(
  pinned: IntelligenceResolvedAddress,
  remoteAddress: string | undefined,
  remoteFamily: string | undefined,
): boolean {
  const observed = canonicalSocketAddress(remoteAddress, remoteFamily);
  if (observed === undefined) {
    return false;
  }

  if (pinned.family === 4 && observed.family === 4) {
    return pinned.address === observed.address;
  }

  if (pinned.family === 6 && observed.family === 6) {
    const left = parseIpv6ToBigInt(pinned.address);
    const right = parseIpv6ToBigInt(observed.address);
    return left !== undefined && right !== undefined && left === right;
  }

  return false;
}
