#!/usr/bin/env node

import fs from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { createGunzip } from 'node:zlib';

type AsnFeatures = {
    asn: number;
    name: string;
    organization: string;
    country: string;
    prefixCount: number;
    prefixLengthTotal: number;
    ranges: [number, number][];
    visibilityTotal: number;
    visibilityMax: number;
    providerCount: number;
    peerCount: number;
    customerCount: number;
};

function getArgument(name: string): string {
    const index = process.argv.indexOf(name);
    const value = index === -1 ? undefined : process.argv[index + 1];
    if (!value || value.startsWith('--')) {
        throw new Error(`Missing required argument: ${name}`);
    }
    return value;
}

function escapeCsv(value: string | number): string {
    const string = String(value);
    return /[,"\r\n]/.test(string)
        ? `"${string.replaceAll('"', '""')}"`
        : string;
}

function inputLines(filePath: string) {
    const input = filePath.endsWith('.bz2')
        ? spawn('bzip2', ['-cd', filePath], {
              stdio: ['ignore', 'pipe', 'inherit'],
          }).stdout
        : createReadStream(filePath);
    return createInterface({
        input: filePath.endsWith('.gz') ? input.pipe(createGunzip()) : input,
        crlfDelay: Infinity,
    });
}

function createFeatures(asn: number): AsnFeatures {
    return {
        asn,
        name: '',
        organization: '',
        country: '',
        prefixCount: 0,
        prefixLengthTotal: 0,
        ranges: [],
        visibilityTotal: 0,
        visibilityMax: 0,
        providerCount: 0,
        peerCount: 0,
        customerCount: 0,
    };
}

function ipv4ToNumber(address: string): number | null {
    const octets = address.split('.').map(Number);
    if (
        octets.length !== 4 ||
        octets.some(
            (octet) => !Number.isInteger(octet) || octet < 0 || octet > 255,
        )
    ) {
        return null;
    }

    return octets.reduce((value, octet) => value * 256 + octet, 0);
}

function uniqueAddressCount(ranges: [number, number][]): number {
    ranges.sort((left, right) => left[0] - right[0]);
    let total = 0;
    let end = -1;

    for (const [start, stop] of ranges) {
        if (stop <= end) {
            continue;
        }
        total += start > end + 1 ? stop - start + 1 : stop - end;
        end = stop;
    }

    return total;
}

async function readRisDump(
    filePath: string,
    features: Map<number, AsnFeatures>,
): Promise<void> {
    for await (const line of inputLines(filePath)) {
        if (line.startsWith('%')) {
            continue;
        }

        const [origin, prefix, peers] = line.split('\t');
        const asn = Number(origin);
        const [address, prefixLengthText] = prefix?.split('/') ?? [];
        const prefixLength = Number(prefixLengthText);
        const start = address ? ipv4ToNumber(address) : null;
        const visibility = Number(peers);
        if (
            !Number.isSafeInteger(asn) ||
            start === null ||
            !Number.isInteger(prefixLength) ||
            prefixLength < 1 ||
            prefixLength > 32 ||
            !Number.isFinite(visibility)
        ) {
            continue;
        }

        const feature = features.get(asn) ?? createFeatures(asn);
        feature.prefixCount += 1;
        feature.prefixLengthTotal += prefixLength;
        feature.ranges.push([start, start + 2 ** (32 - prefixLength) - 1]);
        feature.visibilityTotal += visibility;
        feature.visibilityMax = Math.max(feature.visibilityMax, visibility);
        features.set(asn, feature);
    }
}

async function readAsRelationships(
    filePath: string,
    features: Map<number, AsnFeatures>,
): Promise<void> {
    for await (const line of inputLines(filePath)) {
        if (!line || line.startsWith('#')) {
            continue;
        }

        const [leftText, rightText, relationshipText] = line.split('|');
        const leftAsn = Number(leftText);
        const rightAsn = Number(rightText);
        const relationship = Number(relationshipText);
        if (!Number.isSafeInteger(leftAsn) || !Number.isSafeInteger(rightAsn)) {
            continue;
        }

        const left = features.get(leftAsn);
        const right = features.get(rightAsn);
        if (relationship === -1) {
            if (left) {
                left.customerCount += 1;
            }
            if (right) {
                right.providerCount += 1;
            }
        } else if (relationship === 0) {
            if (left) {
                left.peerCount += 1;
            }
            if (right) {
                right.peerCount += 1;
            }
        }
    }
}

async function readAsOrganizations(
    filePath: string,
    features: Map<number, AsnFeatures>,
): Promise<void> {
    const organizations = new Map<string, { name: string; country: string }>();
    const asns = new Map<number, { name: string; organization: string }>();

    for await (const line of inputLines(filePath)) {
        if (!line || line.startsWith('#')) {
            continue;
        }

        const fields = line.split('|');
        if (fields.length === 5) {
            const [id, , name, country] = fields;
            if (id && name && country) {
                organizations.set(id, { name, country });
            }
        } else if (fields.length === 6) {
            const [value, , name, organization] = fields;
            const asn = Number(value);
            if (Number.isSafeInteger(asn) && name && organization) {
                asns.set(asn, { name, organization });
            }
        }
    }

    for (const [asn, feature] of features) {
        const record = asns.get(asn);
        if (!record) {
            continue;
        }
        const organization = organizations.get(record.organization);
        feature.name = record.name;
        feature.organization = organization?.name ?? '';
        feature.country = organization?.country ?? '';
    }
}

async function main(): Promise<void> {
    const risPath = path.resolve(getArgument('--ris'));
    const asOrganizationPath = path.resolve(getArgument('--as-org'));
    const asRelationshipPath = path.resolve(getArgument('--as-rel'));
    const outputPath = path.resolve(getArgument('--output'));
    const features = new Map<number, AsnFeatures>();

    await readRisDump(risPath, features);
    await readAsOrganizations(asOrganizationPath, features);
    await readAsRelationships(asRelationshipPath, features);

    const activeFeatures = [...features.values()].sort(
        (left, right) => left.asn - right.asn,
    );
    const csv = [
        'asn,name,organization,country,prefix_count,unique_ipv4_addresses,mean_prefix_length,visibility_mean,visibility_max,provider_count,peer_count,customer_count,is_stub',
        ...activeFeatures.map((feature) =>
            [
                feature.asn,
                feature.name,
                feature.organization,
                feature.country,
                feature.prefixCount,
                uniqueAddressCount(feature.ranges),
                feature.prefixLengthTotal / feature.prefixCount,
                feature.visibilityTotal / feature.prefixCount,
                feature.visibilityMax,
                feature.providerCount,
                feature.peerCount,
                feature.customerCount,
                feature.customerCount === 0,
            ]
                .map(escapeCsv)
                .join(','),
        ),
        '',
    ].join('\n');

    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await fs.writeFile(outputPath, csv);
    console.error(
        `Wrote ${activeFeatures.length.toLocaleString('en-US')} active ASN feature rows to ${outputPath}`,
    );
}

main().catch((error: unknown) => {
    console.error(
        error instanceof Error ? (error.stack ?? error.message) : error,
    );
    process.exitCode = 1;
});
