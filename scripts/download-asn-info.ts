import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { Readable } from 'node:stream';
import { createGunzip, gzip as gzipBuffer } from 'node:zlib';
import { promisify } from 'node:util';

const DATA_DIR = path.resolve('./src/data/asn');
const gzip = promisify(gzipBuffer);
const DATABASE_MAGIC = [0x49, 0x50, 0x44, 0x42]; // IPDB
const DATABASE_HEADER_SIZE = 12;
const DATABASE_RECORD_PREFIX_SIZE = 1 + 4 + 4;

const URLS = {
    routesV4: 'https://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz',
    routesV6: 'https://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz',
    as2org: 'https://data.caida.org/datasets/as-organizations/latest.as-org2info.txt.gz',
} as const;

type DownloadFiles = Record<keyof typeof URLS, string>;

type Route = {
    asn: number;
    prefix: string;
    ipVersion: 4 | 6;
};

type AsnInfo = {
    asnName: string;
    orgId: string;
    asnChanged: string;
    opaqueId: string;
    registry: string;
};

type OrganizationInfo = {
    organization: string;
    country: string;
    orgChanged: string;
    registry: string;
};

type BinaryRoute = {
    address: Uint8Array;
    prefixLength: number;
    asn: number;
    metadataId: number;
};

async function download(url: string, destination: string): Promise<void> {
    const temporary = `${destination}.part`;

    console.error(`Downloading ${url}`);

    const response = await fetch(url, {
        headers: {
            'User-Agent': 'asn-database-builder/1.0',
            Accept: '*/*',
        },
        redirect: 'follow',
        signal: AbortSignal.timeout(120_000),
    });

    if (!response.ok) {
        throw new Error(`Download failed with HTTP ${response.status}: ${url}`);
    }

    if (!response.body) {
        throw new Error(`Response body is empty: ${url}`);
    }

    const output = fs.createWriteStream(temporary);
    const input = Readable.fromWeb(
        response.body as unknown as import('node:stream/web').ReadableStream<Uint8Array>,
    );

    try {
        await new Promise<void>((resolve, reject) => {
            input.pipe(output);

            input.on('error', reject);
            output.on('error', reject);
            output.on('finish', resolve);
        });

        await fs.promises.rename(temporary, destination);
    } catch (error) {
        input.destroy();
        output.destroy();

        await fs.promises.rm(temporary, {
            force: true,
        });

        throw error;
    }
}

async function ensureDownloads(): Promise<DownloadFiles> {
    await fs.promises.mkdir(DATA_DIR, {
        recursive: true,
    });

    const files = {} as DownloadFiles;

    for (const [name, url] of Object.entries(URLS) as [
        keyof typeof URLS,
        string,
    ][]) {
        const fileName = path.basename(new URL(url).pathname);
        const destination = path.join(DATA_DIR, fileName);

        files[name] = destination;

        await download(url, destination);
    }

    return files;
}

async function* readGzipLines(filePath: string): AsyncGenerator<string> {
    const input = fs.createReadStream(filePath);
    const gunzip = createGunzip();
    const decoder = new TextDecoder();

    input.on('error', (error) => {
        gunzip.destroy(error);
    });

    const stream = input.pipe(gunzip);

    let remaining = '';

    for await (const chunk of stream) {
        const text =
            remaining +
            decoder.decode(chunk, {
                stream: true,
            });

        const lines = text.split('\n');

        remaining = lines.pop() ?? '';

        for (const line of lines) {
            yield line.endsWith('\r') ? line.slice(0, -1) : line;
        }
    }

    remaining += decoder.decode();

    if (remaining.length > 0) {
        yield remaining.endsWith('\r') ? remaining.slice(0, -1) : remaining;
    }
}

function normalizeOrigin(origin: string): number | null {
    const normalized = origin.trim().toUpperCase().replace(/^AS/, '');

    if (!/^\d+$/.test(normalized)) {
        return null;
    }

    const asn = Number(normalized);

    if (!Number.isSafeInteger(asn)) {
        return null;
    }

    return asn;
}

async function parseAs2Org(filePath: string): Promise<{
    asns: Map<number, AsnInfo>;
    organizations: Map<string, OrganizationInfo>;
}> {
    const asns = new Map<number, AsnInfo>();
    const organizations = new Map<string, OrganizationInfo>();
    let section: 'asn' | 'organization' | null = null;

    for await (const line of readGzipLines(filePath)) {
        if (line.startsWith('# format:aut|')) {
            section = 'asn';
            continue;
        }

        if (line.startsWith('# format:org_id|')) {
            section = 'organization';
            continue;
        }

        if (!line || line.startsWith('#')) {
            continue;
        }

        const fields = line.split('|');

        if (section === 'asn' && fields.length >= 6) {
            const [asnText, changed, asnName, orgId, opaqueId, registry] =
                fields as [string, string, string, string, string, string];
            const asn = Number(asnText);

            if (/^\d+$/.test(asnText) && Number.isSafeInteger(asn)) {
                asns.set(asn, {
                    asnName,
                    orgId,
                    asnChanged: changed,
                    opaqueId,
                    registry,
                });
            }
        } else if (section === 'organization' && fields.length >= 5) {
            const [orgId, changed, organization, country, registry] =
                fields as [string, string, string, string, string];

            organizations.set(orgId, {
                organization,
                country,
                orgChanged: changed,
                registry,
            });
        }
    }

    return { asns, organizations };
}

function getIpVersion(prefix: string): 4 | 6 {
    return prefix.includes(':') ? 6 : 4;
}

function normalizePrefix(prefix: string): string | null {
    const trimmed = prefix.trim();
    const slashIndex = trimmed.lastIndexOf('/');

    if (slashIndex === -1) {
        return null;
    }

    const address = trimmed.slice(0, slashIndex);
    const lengthText = trimmed.slice(slashIndex + 1);
    const prefixLength = Number(lengthText);
    const version = getIpVersion(address);

    if (!Number.isInteger(prefixLength)) {
        return null;
    }

    if (version === 4 && (prefixLength < 0 || prefixLength > 32)) {
        return null;
    }

    if (version === 6 && (prefixLength < 0 || prefixLength > 128)) {
        return null;
    }

    return `${address}/${prefixLength}`;
}

function parseBinaryRoute(route: Route): BinaryRoute {
    const separator = route.prefix.lastIndexOf('/');
    const address = parseIpBytes(route.prefix.slice(0, separator));

    return {
        address,
        prefixLength: Number(route.prefix.slice(separator + 1)),
        asn: route.asn,
        metadataId: route.asn,
    };
}

function parseIpBytes(value: string): Uint8Array {
    if (value.includes(':')) {
        const [leftText, rightText] = value.split('::');
        const left = leftText ? leftText.split(':') : [];
        const right = rightText ? rightText.split(':') : [];
        const groups = [
            ...left,
            ...Array.from(
                { length: 8 - left.length - right.length },
                () => '0',
            ),
            ...right,
        ];
        const address = new Uint8Array(16);

        for (const [index, group] of groups.entries()) {
            const value = Number.parseInt(group, 16);
            address[index * 2] = value >>> 8;
            address[index * 2 + 1] = value & 0xff;
        }

        return address;
    }

    return Uint8Array.from(value.split('.').map(Number));
}

function encodeDatabase(ipVersion: 4 | 6, input: BinaryRoute[]): Uint8Array {
    const addressSize = ipVersion === 4 ? 4 : 16;
    const recordSize = addressSize + DATABASE_RECORD_PREFIX_SIZE;
    const records = [...input].sort((left, right) => {
        for (let index = 0; index < addressSize; index++) {
            const difference = left.address[index]! - right.address[index]!;

            if (difference !== 0) {
                return difference;
            }
        }

        return left.prefixLength - right.prefixLength;
    });
    const bytes = new Uint8Array(
        DATABASE_HEADER_SIZE + recordSize * records.length,
    );
    const view = new DataView(bytes.buffer);

    bytes.set(DATABASE_MAGIC);
    view.setUint8(4, 1);
    view.setUint8(5, ipVersion);
    view.setUint16(6, recordSize, false);
    view.setUint32(8, records.length, false);

    records.forEach((record, index) => {
        const offset = DATABASE_HEADER_SIZE + index * recordSize;

        bytes.set(record.address, offset);
        view.setUint8(offset + addressSize, record.prefixLength);
        view.setUint32(offset + addressSize + 1, record.asn, false);
        view.setUint32(offset + addressSize + 5, record.metadataId, false);
    });

    return bytes;
}

async function writeDatabaseModule(
    outputPath: string,
    compressed: Uint8Array,
): Promise<void> {
    const base64 = Buffer.from(compressed).toString('base64');
    const source = `const data = '${base64}';\n\nexport default data;\n`;

    await fs.promises.writeFile(outputPath, source);
}

function encodeMetadata(
    asns: Map<number, AsnInfo>,
    organizations: Map<string, OrganizationInfo>,
): Uint8Array {
    const encoder = new TextEncoder();
    const records = [...asns.entries()].map(([asn, asInfo]) => {
        const orgInfo = organizations.get(asInfo.orgId);
        const fields = [
            asInfo.asnName,
            asInfo.asnChanged,
            orgInfo?.country ?? '',
            asInfo.opaqueId,
            orgInfo?.orgChanged ?? '',
            asInfo.orgId,
            orgInfo?.organization ?? '',
            asInfo.registry || orgInfo?.registry || '',
        ].map((value) => encoder.encode(value));

        return { asn, fields };
    });
    const size =
        9 +
        records.reduce(
            (total, record) =>
                total +
                4 +
                record.fields.reduce(
                    (bytes, field) => bytes + 4 + field.byteLength,
                    0,
                ),
            0,
        );
    const data = new Uint8Array(size);
    const view = new DataView(data.buffer);
    let offset = 9;

    data.set([0x49, 0x50, 0x4d, 0x44]);
    view.setUint8(4, 1);
    view.setUint32(5, records.length, false);

    for (const record of records) {
        view.setUint32(offset, record.asn, false);
        offset += 4;

        for (const field of record.fields) {
            view.setUint32(offset, field.byteLength, false);
            offset += 4;
            data.set(field, offset);
            offset += field.byteLength;
        }
    }

    return data;
}

async function* parseRisWhois(filePath: string): AsyncGenerator<Route> {
    for await (const line of readGzipLines(filePath)) {
        if (line.startsWith('%') || line.startsWith('#')) {
            continue;
        }

        const [rawOrigin, rawPrefix] = line.split('\t');

        if (!rawOrigin || !rawPrefix) {
            continue;
        }

        const asn = normalizeOrigin(rawOrigin);
        const prefix = normalizePrefix(rawPrefix);

        if (asn !== null && prefix !== null) {
            yield {
                asn,
                prefix,
                ipVersion: getIpVersion(prefix),
            };
        }
    }
}

async function buildDatabase(
    files: DownloadFiles,
    asns: Map<number, AsnInfo>,
    organizations: Map<string, OrganizationInfo>,
): Promise<void> {
    const seen = new Set<string>();
    const binaryRoutes: Record<4 | 6, BinaryRoute[]> = {
        4: [],
        6: [],
    };

    let written = 0;

    for (const routesFile of [files.routesV4, files.routesV6]) {
        console.error(`Parsing ${routesFile}`);

        for await (const route of parseRisWhois(routesFile)) {
            const duplicateKey = `${route.asn}\0${route.prefix}`;

            if (seen.has(duplicateKey)) {
                continue;
            }

            seen.add(duplicateKey);
            binaryRoutes[route.ipVersion].push(parseBinaryRoute(route));

            written++;

            if (written % 100_000 === 0) {
                console.error(
                    `Written ${written.toLocaleString('en-US')} mappings`,
                );
            }
        }
    }

    for (const ipVersion of [4, 6] as const) {
        const binary = encodeDatabase(ipVersion, binaryRoutes[ipVersion]);
        const compressed = await gzip(binary);
        const outputPath = path.join(DATA_DIR, `asn-v${ipVersion}.ts`);

        await writeDatabaseModule(outputPath, compressed);
        await fs.promises.rm(path.join(DATA_DIR, `asn-v${ipVersion}.bin.gz`), {
            force: true,
        });
        console.error(
            `Saved ${binaryRoutes[ipVersion].length.toLocaleString('en-US')} ` +
                `IPv${ipVersion} binary mappings to ${outputPath}`,
        );
    }

    const metadata = await gzip(encodeMetadata(asns, organizations));
    const metadataPath = path.join(DATA_DIR, 'asn-metadata.ts');

    await writeDatabaseModule(metadataPath, metadata);
    console.error(
        `Saved ${asns.size.toLocaleString('en-US')} ASN metadata to ${metadataPath}`,
    );

    console.error(
        `Saved ${written.toLocaleString('en-US')} ASN-prefix mappings`,
    );
}

async function main(): Promise<void> {
    const downloadedPaths = Object.values(URLS).map((url) =>
        path.join(DATA_DIR, path.basename(new URL(url).pathname)),
    );

    try {
        const files = await ensureDownloads();
        const { asns, organizations } = await parseAs2Org(files.as2org);
        await buildDatabase(files, asns, organizations);
    } finally {
        await Promise.all(
            downloadedPaths.flatMap((filePath) => [
                fs.promises.rm(filePath, { force: true }),
                fs.promises.rm(`${filePath}.part`, { force: true }),
            ]),
        );
    }
}

main().catch((error) => {
    console.error(
        error instanceof Error ? (error.stack ?? error.message) : error,
    );
    process.exitCode = 1;
});
