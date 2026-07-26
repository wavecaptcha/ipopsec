#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { isIP } from 'node:net';

const FEEDS_URL =
    'https://raw.githubusercontent.com/tn3w/IPBlocklist/refs/heads/master/feeds.json';
const OUTPUT_PATH = path.resolve('data/vpn.csv');

type Feed = {
    name: string;
    url: string;
    regex: string;
    flags?: string[];
    provider_name?: string;
    is_asn?: boolean;
};

type CsvRow = {
    cidr: string;
    provider: string;
};

function escapeCsv(value: string): string {
    return /[,"\r\n]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value;
}

function normalizeCidr(value: string): string | null {
    const cleaned = value.trim().replace(/^['"]|['"]$/g, '');
    const separator = cleaned.lastIndexOf('/');
    const address = separator === -1 ? cleaned : cleaned.slice(0, separator);
    const version = isIP(address);

    if (version === 0) {
        return null;
    }

    const prefixLength =
        separator === -1
            ? version === 4
                ? 32
                : 128
            : Number(cleaned.slice(separator + 1));
    const maxPrefixLength = version === 4 ? 32 : 128;

    if (
        !Number.isInteger(prefixLength) ||
        prefixLength < 0 ||
        prefixLength > maxPrefixLength
    ) {
        return null;
    }

    return `${address}/${prefixLength}`;
}

async function fetchFeed(feed: Feed): Promise<CsvRow[]> {
    console.error(`Downloading ${feed.name}: ${feed.url}`);

    const response = await fetch(feed.url, {
        headers: {
            'User-Agent': 'ipopsec-vpn-database-builder/1.0',
            Accept: '*/*',
        },
        signal: AbortSignal.timeout(120_000),
    });

    if (!response.ok) {
        throw new Error(`${feed.name} failed with HTTP ${response.status}`);
    }

    const text = await response.text();
    const matcher = new RegExp(feed.regex, 'gm');
    const provider = feed.provider_name ?? feed.name;
    const rows: CsvRow[] = [];

    for (const match of text.matchAll(matcher)) {
        const candidate = match.slice(1).find(Boolean) ?? match[0];
        const cidr = normalizeCidr(candidate);

        if (cidr) {
            rows.push({ cidr, provider });
        }
    }

    console.error(
        `Found ${rows.length.toLocaleString('en-US')} entries from ${feed.name}`,
    );
    return rows;
}

async function main(): Promise<void> {
    const manifestResponse = await fetch(FEEDS_URL);

    if (!manifestResponse.ok) {
        throw new Error(
            `Feed manifest failed with HTTP ${manifestResponse.status}`,
        );
    }

    const feeds = (await manifestResponse.json()) as Feed[];
    const vpnFeeds = feeds.filter(
        (feed) => feed.flags?.includes('is_vpn') && feed.url && !feed.is_asn,
    );
    const results = await Promise.allSettled(vpnFeeds.map(fetchFeed));
    const rows: CsvRow[] = [];

    results.forEach((result, index) => {
        if (result.status === 'fulfilled') {
            for (const row of result.value) {
                rows.push(row);
            }
            return;
        }

        console.error(
            `Skipping ${vpnFeeds[index]?.name ?? 'unknown feed'}:`,
            result.reason,
        );
    });
    const uniqueRows = new Map(
        rows.map((row) => [`${row.cidr}\0${row.provider}`, row]),
    );
    const csv = [
        'cidr,provider',
        ...[...uniqueRows.values()]
            .sort((left, right) => left.cidr.localeCompare(right.cidr))
            .map((row) => `${escapeCsv(row.cidr)},${escapeCsv(row.provider)}`),
        '',
    ].join('\n');

    await fs.mkdir(path.dirname(OUTPUT_PATH), { recursive: true });
    await fs.writeFile(OUTPUT_PATH, csv);
    console.error(
        `Saved ${uniqueRows.size.toLocaleString('en-US')} VPN CIDRs to ${OUTPUT_PATH}`,
    );
}

main().catch((error: unknown) => {
    console.error(
        error instanceof Error ? (error.stack ?? error.message) : error,
    );
    process.exitCode = 1;
});
