type RipeStatResponse<T> = {
    status: string;
    message?: string;
    data: T;
};

type NetworkInfo = {
    prefix?: string | null;
    asns?: (number | string)[];
};

type AsBlock = {
    resource: string;
    desc: string;
    name: string;
};

type AsOverview = {
    holder?: string | null;
    announced?: boolean;
    block?: AsBlock | null;
};

export type AsnMetadata = {
    asn: number;
    holder: string | null;
    announced: boolean;
    block: AsBlock | null;
};

export type AsnLookup = {
    ip: string;
    prefix: string | null;
    asn: AsnMetadata | null;
    asns: AsnMetadata[];
};

async function fetchRipeStat<T>(url: URL, errorMessage: string): Promise<T> {
    const response = await fetch(url);

    if (!response.ok) {
        throw new Error(`${errorMessage}: HTTP ${response.status}`);
    }

    const payload = (await response.json()) as RipeStatResponse<T>;

    if (payload.status !== 'ok') {
        throw new Error(payload.message ?? errorMessage);
    }

    return payload.data;
}

export async function lookupAsn(ip: string): Promise<AsnLookup> {
    const networkUrl = new URL(
        'https://stat.ripe.net/data/network-info/data.json',
    );

    networkUrl.searchParams.set('resource', ip);

    const network = await fetchRipeStat<NetworkInfo>(
        networkUrl,
        'RIPEstat network lookup failed',
    );
    const metadata = await Promise.all(
        (network.asns ?? []).map(async (asn): Promise<AsnMetadata> => {
            const numericAsn = Number(asn);

            if (!Number.isSafeInteger(numericAsn)) {
                throw new Error(`Invalid ASN returned by RIPEstat: ${asn}`);
            }

            const asUrl = new URL(
                'https://stat.ripe.net/data/as-overview/data.json',
            );

            asUrl.searchParams.set('resource', `AS${numericAsn}`);

            const overview = await fetchRipeStat<AsOverview>(
                asUrl,
                `RIPEstat ASN lookup failed for AS${numericAsn}`,
            );

            return {
                asn: numericAsn,
                holder: overview.holder ?? null,
                announced: overview.announced ?? false,
                block: overview.block ?? null,
            };
        }),
    );

    return {
        ip,
        prefix: network.prefix ?? null,
        asn: metadata[0] ?? null,
        asns: metadata,
    };
}
