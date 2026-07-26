type OnionooRelay = {
    nickname?: string;
    fingerprint?: string;
    or_addresses?: string[];
    flags?: string[];
    country?: string;
    as_number?: string;
    as_name?: string;
    first_seen?: string;
    last_seen?: string;
    running?: boolean;
    measured?: boolean;
    exit_addresses?: string[];
    version?: string;
};

type OnionooResponse = {
    relays?: OnionooRelay[];
};

export type TorRelay = {
    nickname: string | null;
    fingerprint: string | null;
    addresses: string[];
    flags: string[];
    country: string | null;
    asn: string | null;
    asName: string | null;
    firstSeen: string | null;
    lastSeen: string | null;
    running: boolean;
    measured: boolean;
    exitAddresses: string[];
    version: string | null;
};

export type TorLookup = {
    ip: string;
    isTor: boolean;
    isExit: boolean;
    metadata: { relays: TorRelay[] };
};

const ONIONOO_URL = 'https://onionoo.torproject.org/details';

export async function lookupTor(ip: string): Promise<TorLookup> {
    const url = new URL(ONIONOO_URL);
    url.searchParams.set('search', ip);
    url.searchParams.set('type', 'relay');
    url.searchParams.set(
        'fields',
        [
            'nickname',
            'fingerprint',
            'or_addresses',
            'flags',
            'country',
            'as_number',
            'as_name',
            'first_seen',
            'last_seen',
            'running',
            'measured',
            'exit_addresses',
            'version',
        ].join(','),
    );

    const response = await fetch(url);

    if (!response.ok) {
        throw new Error(`Onionoo relay lookup failed: HTTP ${response.status}`);
    }

    const payload = (await response.json()) as OnionooResponse;
    const relays = (payload.relays ?? []).map((relay): TorRelay => ({
        nickname: relay.nickname ?? null,
        fingerprint: relay.fingerprint ?? null,
        addresses: relay.or_addresses ?? [],
        flags: relay.flags ?? [],
        country: relay.country ?? null,
        asn: relay.as_number ?? null,
        asName: relay.as_name ?? null,
        firstSeen: relay.first_seen ?? null,
        lastSeen: relay.last_seen ?? null,
        running: relay.running ?? false,
        measured: relay.measured ?? false,
        exitAddresses: relay.exit_addresses ?? [],
        version: relay.version ?? null,
    }));

    return {
        ip,
        isTor: relays.length > 0,
        isExit: relays.some(
            (relay) =>
                relay.flags.includes('Exit') ||
                relay.exitAddresses.includes(ip),
        ),
        metadata: { relays },
    };
}
