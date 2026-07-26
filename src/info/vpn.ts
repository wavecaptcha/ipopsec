import {
    formatCidr,
    formatIp,
    getIpVersion,
    maskIp,
    parseCidr,
    parseIp,
} from '../utils/cidr/index.js';

const VPN_DATA_URL =
    'https://raw.githubusercontent.com/wavecaptcha/ipopsec/data/data/vpn.csv.gz';

export type VpnLookup = {
    ip: string;
    isVpn: boolean;
    cidr: string | null;
    providers: string[];
};

type VpnIndex = Map<string, Set<string>>;

let vpnIndexPromise: Promise<VpnIndex> | undefined;

function unquoteCsvField(value: string): string {
    const trimmed = value.trim();

    if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
        return trimmed.slice(1, -1).replaceAll('""', '"');
    }

    return trimmed;
}

function parseCsvRow(line: string): { cidr: string; provider: string } | null {
    const separator = line.indexOf(',');

    if (separator === -1) {
        return null;
    }

    const cidr = unquoteCsvField(line.slice(0, separator));
    const provider = unquoteCsvField(line.slice(separator + 1));

    if (!cidr || !provider) {
        return null;
    }

    return { cidr, provider };
}

async function loadVpnIndex(): Promise<VpnIndex> {
    const response = await fetch(VPN_DATA_URL);

    if (!response.ok) {
        throw new Error(`VPN data lookup failed: HTTP ${response.status}`);
    }

    const compressed = await response.arrayBuffer();
    const decompressed = new Response(
        new Response(compressed).body!.pipeThrough(
            new DecompressionStream('gzip'),
        ),
    );
    const index: VpnIndex = new Map();
    const text = await decompressed.text();
    const lines = text.split(/\r?\n/);

    for (const line of lines.slice(1)) {
        const row = parseCsvRow(line);

        if (!row) {
            continue;
        }

        try {
            const cidr = formatCidr(parseCidr(row.cidr));
            const providers = index.get(cidr) ?? new Set<string>();

            providers.add(row.provider);
            index.set(cidr, providers);
        } catch {
            // Ignore malformed third-party feed rows.
        }
    }

    return index;
}

function getVpnIndex(): Promise<VpnIndex> {
    vpnIndexPromise ??= loadVpnIndex();
    return vpnIndexPromise;
}

export async function lookupVpn(ip: string): Promise<VpnLookup> {
    const address = parseIp(ip);
    const version = getIpVersion(address);
    const maxPrefixLength = version === 4 ? 32 : 128;
    const index = await getVpnIndex();

    for (
        let prefixLength = maxPrefixLength;
        prefixLength >= 0;
        prefixLength--
    ) {
        const network = maskIp(address, prefixLength);
        const cidr = `${formatIp(network)}/${prefixLength}`;
        const providers = index.get(cidr);

        if (providers) {
            return {
                ip,
                isVpn: true,
                cidr,
                providers: [...providers],
            };
        }
    }

    return {
        ip,
        isVpn: false,
        cidr: null,
        providers: [],
    };
}
