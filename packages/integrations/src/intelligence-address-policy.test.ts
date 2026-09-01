import { describe, expect, it } from 'vitest';

import {
  isApprovedPublicIpv4,
  isApprovedPublicIpv6,
  pinnedAddressMatchesSocket,
  selectPinnedPublicAddress,
} from './intelligence-address-policy.js';

describe('intelligence address policy', () => {
  it('accepts public IPv4 and prefers it over public IPv6', () => {
    expect(isApprovedPublicIpv4('1.1.1.1')).toBe(true);
    expect(isApprovedPublicIpv4('8.8.8.8')).toBe(true);
    const selected = selectPinnedPublicAddress([
      { address: '2001:4860:4860::8888', family: 6 },
      { address: '1.1.1.1', family: 4 },
    ]);
    expect(selected).toEqual({ address: '1.1.1.1', family: 4 });
  });

  it('accepts public IPv6 when no public IPv4 remains', () => {
    expect(isApprovedPublicIpv6('2001:4860:4860::8888')).toBe(true);
    const selected = selectPinnedPublicAddress([
      { address: '10.0.0.1', family: 4 },
      { address: '2001:4860:4860::8888', family: 6 },
    ]);
    expect(selected).toEqual({ address: '2001:4860:4860::8888', family: 6 });
  });

  it('rejects blocked IPv4 ranges including metadata', () => {
    expect(isApprovedPublicIpv4('0.0.0.0')).toBe(false);
    expect(isApprovedPublicIpv4('10.1.2.3')).toBe(false);
    expect(isApprovedPublicIpv4('100.64.0.1')).toBe(false);
    expect(isApprovedPublicIpv4('127.0.0.1')).toBe(false);
    expect(isApprovedPublicIpv4('169.254.1.1')).toBe(false);
    expect(isApprovedPublicIpv4('169.254.169.254')).toBe(false);
    expect(isApprovedPublicIpv4('172.16.0.1')).toBe(false);
    expect(isApprovedPublicIpv4('192.0.0.1')).toBe(false);
    expect(isApprovedPublicIpv4('192.0.2.1')).toBe(false);
    expect(isApprovedPublicIpv4('192.88.99.1')).toBe(false);
    expect(isApprovedPublicIpv4('192.168.1.1')).toBe(false);
    expect(isApprovedPublicIpv4('198.18.0.1')).toBe(false);
    expect(isApprovedPublicIpv4('198.51.100.1')).toBe(false);
    expect(isApprovedPublicIpv4('203.0.113.1')).toBe(false);
    expect(isApprovedPublicIpv4('224.0.0.1')).toBe(false);
    expect(isApprovedPublicIpv4('240.0.0.1')).toBe(false);
    expect(isApprovedPublicIpv4('255.255.255.255')).toBe(false);
  });

  it('rejects blocked IPv6 ranges, mapped private IPv4, and NAT64 private IPv4', () => {
    expect(isApprovedPublicIpv6('::')).toBe(false);
    expect(isApprovedPublicIpv6('::1')).toBe(false);
    expect(isApprovedPublicIpv6('fc00::1')).toBe(false);
    expect(isApprovedPublicIpv6('fd12:3456::1')).toBe(false);
    expect(isApprovedPublicIpv6('fe80::1')).toBe(false);
    expect(isApprovedPublicIpv6('ff02::1')).toBe(false);
    expect(isApprovedPublicIpv6('2001:db8::1')).toBe(false);
    expect(isApprovedPublicIpv6('3fff::1')).toBe(false);
    expect(isApprovedPublicIpv6('100::1')).toBe(false);
    expect(isApprovedPublicIpv6('fd00:ec2::')).toBe(false);
    expect(isApprovedPublicIpv6('fec0::1')).toBe(false);
    expect(isApprovedPublicIpv6('2001::1')).toBe(false);
    expect(isApprovedPublicIpv6('::ffff:10.0.0.1')).toBe(false);
    expect(isApprovedPublicIpv6('::ffff:127.0.0.1')).toBe(false);
    expect(isApprovedPublicIpv6('::ffff:169.254.169.254')).toBe(false);
    expect(isApprovedPublicIpv6('64:ff9b::10.0.0.1')).toBe(false);
    expect(isApprovedPublicIpv6('64:ff9b::1.1.1.1')).toBe(true);
    expect(isApprovedPublicIpv6('64:ff9b:1::10.0.0.1')).toBe(false);
    expect(isApprovedPublicIpv6('64:ff9b:1::1.1.1.1')).toBe(true);
    expect(isApprovedPublicIpv6('2002:0a00:0001::1')).toBe(false);
    expect(isApprovedPublicIpv6('2002:a9fe:a9fe::1')).toBe(false);
    expect(isApprovedPublicIpv6('2002:0808:0808::1')).toBe(true);
  });

  it('rejects a pin mismatch after connect', () => {
    expect(pinnedAddressMatchesSocket({ address: '1.1.1.1', family: 4 }, '8.8.8.8', 'IPv4')).toBe(
      false,
    );
    expect(pinnedAddressMatchesSocket({ address: '1.1.1.1', family: 4 }, '1.1.1.1', 'IPv4')).toBe(
      true,
    );
    expect(
      pinnedAddressMatchesSocket({ address: '1.1.1.1', family: 4 }, '::ffff:1.1.1.1', 'IPv6'),
    ).toBe(true);
  });
});
