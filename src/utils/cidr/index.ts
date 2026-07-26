import {
    IPV4_BYTE_LENGTH,
    IPV4_MAX_PREFIX_LENGTH,
    IPV6_BYTE_LENGTH,
    IPV6_GROUP_COUNT,
    IPV6_MAX_PREFIX_LENGTH,
} from './constants.js';
import type { Cidr, IpVersion } from './constants.js';

export type { Cidr, IpVersion } from './constants.js';

function parseIpv4(value: string): Uint8Array {
    const parts = value.split('.');

    if (parts.length !== 4) {
        throw new Error(`Invalid IPv4 address: ${value}`);
    }

    const address = new Uint8Array(IPV4_BYTE_LENGTH);

    for (const [index, part] of parts.entries()) {
        if (!/^\d{1,3}$/.test(part)) {
            throw new Error(`Invalid IPv4 address: ${value}`);
        }

        const octet = Number(part);

        if (octet > 255) {
            throw new Error(`Invalid IPv4 address: ${value}`);
        }

        address[index] = octet;
    }

    return address;
}

function parseIpv6(value: string): Uint8Array {
    if (
        value.includes(':::') ||
        value.indexOf('::') !== value.lastIndexOf('::')
    ) {
        throw new Error(`Invalid IPv6 address: ${value}`);
    }

    const [leftText, rightText] = value.split('::');
    const left = leftText ? leftText.split(':') : [];
    const right = rightText ? rightText.split(':') : [];

    const expandIpv4 = (parts: string[]): string[] => {
        const last = parts.at(-1);

        if (!last?.includes('.')) {
            return parts;
        }

        const ipv4 = parseIpv4(last);
        const first = ((ipv4[0]! << 8) | ipv4[1]!).toString(16);
        const second = ((ipv4[2]! << 8) | ipv4[3]!).toString(16);

        return [...parts.slice(0, -1), first, second];
    };

    const expandedLeft = expandIpv4(left);
    const expandedRight = expandIpv4(right);
    const parts = [...expandedLeft, ...expandedRight];

    if (!value.includes('::') && parts.length !== 8) {
        throw new Error(`Invalid IPv6 address: ${value}`);
    }

    if (value.includes('::') && parts.length >= 8) {
        throw new Error(`Invalid IPv6 address: ${value}`);
    }

    const zeroCount = IPV6_GROUP_COUNT - parts.length;
    const groups = [
        ...expandedLeft,
        ...(value.includes('::')
            ? Array.from({ length: zeroCount }, () => '0')
            : []),
        ...expandedRight,
    ];
    const address = new Uint8Array(IPV6_BYTE_LENGTH);

    for (const [index, part] of groups.entries()) {
        if (!/^[0-9a-fA-F]{1,4}$/.test(part)) {
            throw new Error(`Invalid IPv6 address: ${value}`);
        }

        const group = Number.parseInt(part, 16);
        address[index * 2] = group >>> 8;
        address[index * 2 + 1] = group & 0xff;
    }

    return address;
}

export function parseIp(value: string): Uint8Array {
    const trimmed = value.trim();

    if (trimmed.includes(':')) {
        return parseIpv6(trimmed);
    }

    return parseIpv4(trimmed);
}

export function getIpVersion(address: Uint8Array): IpVersion {
    if (address.length === 4) {
        return 4;
    }

    if (address.length === 16) {
        return 6;
    }

    throw new Error('An IP address must contain 4 or 16 bytes');
}

export function maskIp(address: Uint8Array, prefixLength: number): Uint8Array {
    const version = getIpVersion(address);
    const maxPrefixLength =
        version === 4 ? IPV4_MAX_PREFIX_LENGTH : IPV6_MAX_PREFIX_LENGTH;

    if (
        !Number.isInteger(prefixLength) ||
        prefixLength < 0 ||
        prefixLength > maxPrefixLength
    ) {
        throw new Error(`Invalid prefix length: ${prefixLength}`);
    }

    const masked = new Uint8Array(address);
    const fullBytes = Math.floor(prefixLength / 8);
    const remainingBits = prefixLength % 8;

    if (remainingBits > 0) {
        masked[fullBytes] = masked[fullBytes]! & (0xff << (8 - remainingBits));
    }

    for (
        let index = fullBytes + (remainingBits > 0 ? 1 : 0);
        index < masked.length;
        index++
    ) {
        masked[index] = 0;
    }

    return masked;
}

export function parseCidr(value: string): Cidr {
    const separator = value.lastIndexOf('/');

    if (separator < 1 || separator === value.length - 1) {
        throw new Error(`Invalid CIDR: ${value}`);
    }

    const address = parseIp(value.slice(0, separator));
    const prefixText = value.slice(separator + 1);

    if (!/^\d+$/.test(prefixText)) {
        throw new Error(`Invalid CIDR prefix length: ${prefixText}`);
    }

    const prefixLength = Number(prefixText);
    const version = getIpVersion(address);
    const maxPrefixLength =
        version === 4 ? IPV4_MAX_PREFIX_LENGTH : IPV6_MAX_PREFIX_LENGTH;

    if (prefixLength > maxPrefixLength) {
        throw new Error(`Invalid CIDR prefix length: ${prefixText}`);
    }

    return {
        address: maskIp(address, prefixLength),
        prefixLength,
        version,
    };
}

export function containsIp(
    cidr: Cidr | string,
    ip: Uint8Array | string,
): boolean {
    const network = typeof cidr === 'string' ? parseCidr(cidr) : cidr;
    const address = typeof ip === 'string' ? parseIp(ip) : ip;

    if (getIpVersion(address) !== network.version) {
        return false;
    }

    const masked = maskIp(address, network.prefixLength);

    return network.address.every((byte, index) => byte === masked[index]);
}

export function formatIp(address: Uint8Array): string {
    const version = getIpVersion(address);

    if (version === 4) {
        return Array.from(address).join('.');
    }

    const groups = Array.from({ length: IPV6_GROUP_COUNT }, (_, index) =>
        ((address[index * 2]! << 8) | address[index * 2 + 1]!).toString(16),
    );
    let bestStart = -1;
    let bestLength = 0;

    for (let index = 0; index < groups.length; index++) {
        if (groups[index] !== '0') {
            continue;
        }

        let end = index;
        while (end < groups.length && groups[end] === '0') {
            end++;
        }

        if (end - index > bestLength) {
            bestStart = index;
            bestLength = end - index;
        }

        index = end - 1;
    }

    if (bestLength < 2) {
        return groups.join(':');
    }

    const before = groups.slice(0, bestStart).join(':');
    const after = groups.slice(bestStart + bestLength).join(':');

    return `${before}::${after}`;
}

export function formatCidr(cidr: Cidr): string {
    return `${formatIp(cidr.address)}/${cidr.prefixLength}`;
}

export function normalizeCidr(value: string): string {
    return formatCidr(parseCidr(value));
}
