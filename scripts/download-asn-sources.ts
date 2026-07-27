#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';

const RIS_URL = 'https://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz';
const AS_ORG_URL =
    'https://publicdata.caida.org/datasets/as-organizations/latest.as-org2info.txt.gz';
const AS_REL_BASE_URL =
    'https://publicdata.caida.org/datasets/as-relationships/serial-1/';
const ASDB_DATA_URL = 'https://asdb.stanford.edu/static-website/data/';

function getArgument(name: string): string {
    const index = process.argv.indexOf(name);
    const value = index === -1 ? undefined : process.argv[index + 1];
    if (!value || value.startsWith('--')) {
        throw new Error(`Missing required argument: ${name}`);
    }
    return value;
}

async function fetchResponse(url: string): Promise<Response> {
    const response = await fetch(url, {
        headers: { 'User-Agent': 'ipopsec-asn-database-builder/1.0' },
        signal: AbortSignal.timeout(180_000),
    });
    if (!response.ok) {
        throw new Error(`${url} failed with HTTP ${response.status}`);
    }
    return response;
}

async function latestFile(indexUrl: string, pattern: RegExp): Promise<string> {
    const html = await (await fetchResponse(indexUrl)).text();
    const matches = [...html.matchAll(pattern)].map((match) => match[1]);
    const filename = matches.filter(Boolean).sort().at(-1);
    if (!filename) {
        throw new Error(`No matching files found at ${indexUrl}`);
    }
    return filename;
}

async function latestAsdbUrl(): Promise<string> {
    const date = new Date();
    for (let offset = 0; offset < 24; offset += 1) {
        const filename = `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}_categorized_ases.csv`;
        const url = new URL(filename, ASDB_DATA_URL).toString();
        const response = await fetch(url, {
            method: 'HEAD',
            headers: { 'User-Agent': 'ipopsec-asn-database-builder/1.0' },
            signal: AbortSignal.timeout(30_000),
        });
        if (response.ok) {
            return url;
        }
        date.setUTCMonth(date.getUTCMonth() - 1);
    }
    throw new Error('No recent public Stanford ASDB snapshot found');
}

async function download(url: string, outputPath: string): Promise<void> {
    console.error(`Downloading ${url}`);
    const response = await fetchResponse(url);
    await fs.writeFile(outputPath, Buffer.from(await response.arrayBuffer()));
}

async function main(): Promise<void> {
    const outputDirectory = path.resolve(getArgument('--output'));
    await fs.mkdir(outputDirectory, { recursive: true });

    const [relationshipFile, asdbUrl] = await Promise.all([
        latestFile(AS_REL_BASE_URL, /href="(\d{8}\.as-rel\.txt\.bz2)"/g),
        latestAsdbUrl(),
    ]);

    await Promise.all([
        download(RIS_URL, path.join(outputDirectory, 'riswhoisdump.IPv4.gz')),
        download(AS_ORG_URL, path.join(outputDirectory, 'as-org2info.txt.gz')),
        download(
            new URL(relationshipFile, AS_REL_BASE_URL).toString(),
            path.join(outputDirectory, 'as-rel.txt.bz2'),
        ),
        download(asdbUrl, path.join(outputDirectory, 'asdb.csv')),
    ]);
}

main().catch((error: unknown) => {
    console.error(
        error instanceof Error ? (error.stack ?? error.message) : error,
    );
    process.exitCode = 1;
});
