import { parseIp } from './cidr/index.js';

export type IpType = 'ipv4' | 'ipv6';

export function getIpType(value: string): IpType | null {
    try {
        return parseIp(value).length === 4 ? 'ipv4' : 'ipv6';
    } catch {
        return null;
    }
}

export function isIpv4(value: string): boolean {
    return getIpType(value) === 'ipv4';
}

export function isIpv6(value: string): boolean {
    return getIpType(value) === 'ipv6';
}
