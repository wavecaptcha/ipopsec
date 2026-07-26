import { getIpType } from '../utils/type.js';

type DnsAnswer = {
    type: number;
    data?: string;
};

type DnsResponse = {
    Answer?: DnsAnswer[];
};

function getReverseDnsName(ip: string): string {
    const version = getIpType(ip);

    if (version === 'ipv4') {
        return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
    }

    if (version === 'ipv6') {
        const [left = '', right = ''] = ip.split('::');
        const parts = [
            ...(left ? left.split(':') : []),
            ...Array(
                8 -
                    (left ? left.split(':').length : 0) -
                    (right ? right.split(':').length : 0),
            ).fill('0'),
            ...(right ? right.split(':') : []),
        ];

        return `${parts
            .map((part) => part.padStart(4, '0'))
            .join('')
            .split('')
            .reverse()
            .join('.')}.ip6.arpa`;
    }
    throw new Error(`Invalid IP address: ${ip}`);
}

export async function getHostname(ip: string): Promise<string | null> {
    const name = getReverseDnsName(ip);
    const url = new URL('https://dns.google/resolve');

    url.searchParams.set('name', name);
    url.searchParams.set('type', 'PTR');

    const response = await fetch(url);

    if (!response.ok) {
        throw new Error(`Google DNS returned HTTP ${response.status}`);
    }

    const data = (await response.json()) as DnsResponse;

    return (
        data.Answer?.find((record) => record.type === 12)?.data?.replace(
            /\.$/,
            '',
        ) ?? null
    );
}
