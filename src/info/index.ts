import { getIpType } from '../utils/type.js';
import { lookupAsn } from './asn.js';
import type { AsnLookup } from './asn.js';
import { getHostname } from './hostname.js';
import { lookupTor } from './tor.js';
import type { TorLookup } from './tor.js';
import { lookupVpn } from './vpn.js';

type Category = 'hosting' | 'tor' | 'vpn';

export type InfoLookup = {
    asn: AsnLookup;
    hostname: string | null;
    categories: Record<Category, boolean>;
    metadata: {
        tor: TorLookup['metadata'] | null;
        vpn: { providers: string[] } | null;
    };
};

export async function getInfo(ip: string): Promise<InfoLookup> {
    const type = getIpType(ip);

    if (type === null) {
        throw new Error('Invalid IP string.');
    }

    const [asn, tor, vpn, hostname] = await Promise.all([
        lookupAsn(ip),
        lookupTor(ip),
        lookupVpn(ip),
        getHostname(ip),
    ]);

    return {
        hostname,
        categories: {
            tor: tor.isTor,
            vpn: vpn.isVpn,
            hosting: asn.asn?.type === 'Hosting',
        },
        metadata: {
            tor: tor.metadata,
            vpn: { providers: vpn.providers },
        },
        asn,
    };
}
