import { getIpType } from '../utils/type.js';
import { lookupAsn } from './asn.js';
import type { AsnLookup } from './asn.js';
import { getHostname } from './hostname.js';
import { lookupTor, TorLookup } from './tor.js';
import { lookupVpn } from './vpn.js';
import type { VpnLookup } from './vpn.js';

type Category = 'hosting' | 'tor' | 'vpn';

export async function getInfo(ip: string): Promise<{
    asn: AsnLookup;
    hostname: string | null;
    categories: Record<Category, boolean>;
    metadata: {
        tor: TorLookup['metadata'] | null;
        vpn: { providers: string[] } | null;
    };
    vpn: VpnLookup;
}> {
    const type = getIpType(ip);

    if (type === null) {
        throw new Error('Invalid IP string.');
    }

    const asn = await lookupAsn(ip);
    const tor = await lookupTor(ip);
    const vpn = await lookupVpn(ip);
    const hostname = await getHostname(ip);
    const location = { country: null, city: null };

    const categories = { tor: tor.isTor, vpn: vpn.isVpn, hosting: false };

    return {
        hostname,
        categories,
        metadata: { tor: tor?.metadata, vpn: { providers: vpn?.providers } },
        asn,
        vpn,
    };
}
