#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { gzip as gzipBuffer } from 'node:zlib';
import { promisify } from 'node:util';
import { getAsnType } from '../src/utils/asn.ts';

const gzip = promisify(gzipBuffer);

type AsnType = 'Hosting' | 'ISP' | 'Business';

type Row = {
    asn: number;
    name: string;
    organization: string;
    numbers: number[];
};

type Example = {
    row: Row;
    type: AsnType;
    source: 'reviewed' | 'asdb' | 'weak';
};

const TYPES: AsnType[] = ['Hosting', 'ISP', 'Business'];
const HASH_DIMENSIONS = 4_096;
const NUMERIC_FEATURES = 10;
const DIMENSIONS = HASH_DIMENSIONS + NUMERIC_FEATURES + 1;
const EPOCHS = 15;
const BUSINESS_SEED_TERMS = [
    ' university',
    ' university of ',
    ' college',
    ' school district',
    ' ministry of ',
    ' government of ',
    ' city of ',
    ' county of ',
    ' state of ',
    ' national laboratory',
    ' hospital',
    ' bank ',
    ' bank of ',
    ' insurance ',
    ' airport authority',
];
const HOSTING_SEED_TERMS = [
    ' cloud ',
    ' cloud hosting',
    ' data center',
    ' datacenter',
    ' hosting ',
    ' hosting provider',
    ' server ',
    ' servers ',
    ' vps ',
    ' colocation',
];
const ISP_SEED_TERMS = [
    ' broadband',
    ' cable ',
    ' communications',
    ' fiber ',
    ' fibre ',
    ' internet service',
    ' mobile ',
    ' telecom',
    ' telecommunication',
    ' telemanagement',
    ' wireless',
];

function getArgument(name: string): string {
    const index = process.argv.indexOf(name);
    const value = index === -1 ? undefined : process.argv[index + 1];
    if (!value || value.startsWith('--')) {
        throw new Error(`Missing required argument: ${name}`);
    }
    return value;
}

function csvFields(line: string): string[] {
    const fields: string[] = [];
    let field = '';
    let quoted = false;

    for (let index = 0; index < line.length; index += 1) {
        const character = line[index];
        if (character === '"') {
            if (quoted && line[index + 1] === '"') {
                field += character;
                index += 1;
            } else {
                quoted = !quoted;
            }
        } else if (character === ',' && !quoted) {
            fields.push(field);
            field = '';
        } else {
            field += character;
        }
    }

    fields.push(field);
    return fields;
}

function hash(value: string): number {
    let result = 2_166_136_261;
    for (let index = 0; index < value.length; index += 1) {
        result ^= value.charCodeAt(index);
        result = Math.imul(result, 16_777_619);
    }
    return result >>> 0;
}

function normalizeText(value: string): string {
    return value
        .normalize('NFKD')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
}

function textFeatures(value: string): Map<number, number> {
    const normalized = normalizeText(value);
    const result = new Map<number, number>();
    const add = (token: string) => {
        const tokenHash = hash(token);
        const index = tokenHash % HASH_DIMENSIONS;
        const sign = (tokenHash & 0x80000000) === 0 ? 1 : -1;
        result.set(index, (result.get(index) ?? 0) + sign);
    };

    for (const word of normalized.split(' ')) {
        if (word.length >= 2) {
            add(`w:${word}`);
        }
    }
    const compact = `^${normalized.replaceAll(' ', '_')}$`;
    for (const size of [3, 4, 5]) {
        for (let index = 0; index <= compact.length - size; index += 1) {
            add(`c:${compact.slice(index, index + size)}`);
        }
    }

    return result;
}

function numericFeatures(row: Row): number[] {
    const [
        prefixCount,
        ipv4Addresses,
        meanPrefixLength,
        visibilityMean,
        visibilityMax,
        providers,
        peers,
        customers,
        isStub,
    ] = row.numbers;
    return [
        Math.log1p(prefixCount ?? 0),
        Math.log1p(ipv4Addresses ?? 0),
        meanPrefixLength ?? 0,
        Math.log1p(visibilityMean ?? 0),
        Math.log1p(visibilityMax ?? 0),
        Math.log1p(providers ?? 0),
        Math.log1p(peers ?? 0),
        Math.log1p(customers ?? 0),
        isStub ?? 0,
        Math.log1p((ipv4Addresses ?? 0) / Math.max(1, prefixCount ?? 0)),
    ];
}

function rowFeatures(
    row: Row,
    means: number[],
    deviations: number[],
): Map<number, number> {
    const result = textFeatures(`${row.name} ${row.organization}`);
    numericFeatures(row).forEach((value, index) => {
        result.set(
            HASH_DIMENSIONS + index,
            (value - (means[index] ?? 0)) / (deviations[index] ?? 1),
        );
    });
    result.set(DIMENSIONS - 1, 1);
    return result;
}

function parseRows(contents: string): Row[] {
    const [headerLine, ...lines] = contents.trim().split(/\r?\n/);
    const header = csvFields(headerLine ?? '');
    const index = (name: string) => {
        const value = header.indexOf(name);
        if (value === -1) {
            throw new Error(`Missing feature column: ${name}`);
        }
        return value;
    };
    const indexes = {
        asn: index('asn'),
        name: index('name'),
        organization: index('organization'),
        prefixCount: index('prefix_count'),
        ipv4Addresses: index('unique_ipv4_addresses'),
        meanPrefixLength: index('mean_prefix_length'),
        visibilityMean: index('visibility_mean'),
        visibilityMax: index('visibility_max'),
        providers: index('provider_count'),
        peers: index('peer_count'),
        customers: index('customer_count'),
        isStub: index('is_stub'),
    };

    return lines.flatMap((line) => {
        const fields = csvFields(line);
        const asn = Number(fields[indexes.asn]);
        if (!Number.isSafeInteger(asn)) {
            return [];
        }
        return [
            {
                asn,
                name: fields[indexes.name] ?? '',
                organization: fields[indexes.organization] ?? '',
                numbers: [
                    Number(fields[indexes.prefixCount]),
                    Number(fields[indexes.ipv4Addresses]),
                    Number(fields[indexes.meanPrefixLength]),
                    Number(fields[indexes.visibilityMean]),
                    Number(fields[indexes.visibilityMax]),
                    Number(fields[indexes.providers]),
                    Number(fields[indexes.peers]),
                    Number(fields[indexes.customers]),
                    fields[indexes.isStub] === 'true' ? 1 : 0,
                ],
            },
        ];
    });
}

function parseReviewedLabels(contents: string): Map<number, AsnType> {
    const labels = new Map<number, AsnType>();
    for (const line of contents.trim().split(/\r?\n/).slice(1)) {
        const [asnText, type] = csvFields(line);
        const asn = Number(asnText);
        if (Number.isSafeInteger(asn) && TYPES.includes(type as AsnType)) {
            labels.set(asn, type as AsnType);
        }
    }
    return labels;
}

function parseAsdbLabels(contents: string): Map<number, AsnType> {
    const labels = new Map<number, AsnType>();
    for (const line of contents.trim().split(/\r?\n/).slice(1)) {
        const fields = csvFields(line);
        const asn = Number(fields[0]?.replace(/^AS/i, ''));
        if (!Number.isSafeInteger(asn)) {
            continue;
        }

        const categories = fields
            .slice(1)
            .map((value) => value.trim().toLowerCase())
            .filter(Boolean);
        const hosting = categories.some(
            (value) =>
                value.includes('hosting') ||
                value.includes('cloud provider') ||
                value.includes('data center') ||
                value.includes('server colocation'),
        );
        const isp = categories.some(
            (value) =>
                value.includes('internet service provider') ||
                value === 'phone provider',
        );

        if (hosting === isp) {
            if (!hosting && categories.some((value) => value !== 'unknown')) {
                labels.set(asn, 'Business');
            }
            continue;
        }
        labels.set(asn, hosting ? 'Hosting' : 'ISP');
    }
    return labels;
}

function weakType(row: Row): AsnType | null {
    const text = `${row.name} ${row.organization}`;
    const namedType = getAsnType(text);
    if (namedType !== 'Unknown') {
        return namedType;
    }
    const normalized = ` ${normalizeText(text)} `;
    if (HOSTING_SEED_TERMS.some((term) => normalized.includes(term))) {
        return 'Hosting';
    }
    if (ISP_SEED_TERMS.some((term) => normalized.includes(term))) {
        return 'ISP';
    }
    return BUSINESS_SEED_TERMS.some((term) => normalized.includes(term))
        ? 'Business'
        : null;
}

function normalization(rows: Row[]): { means: number[]; deviations: number[] } {
    const values = rows.map(numericFeatures);
    const means = Array.from(
        { length: NUMERIC_FEATURES },
        (_, index) =>
            values.reduce((sum, row) => sum + (row[index] ?? 0), 0) /
            values.length,
    );
    const deviations = means.map((mean, index) =>
        Math.max(
            0.000001,
            Math.sqrt(
                values.reduce(
                    (sum, row) => sum + ((row[index] ?? 0) - mean) ** 2,
                    0,
                ) / values.length,
            ),
        ),
    );
    return { means, deviations };
}

function shuffledIndexes(length: number, epoch: number): number[] {
    const indexes = Array.from({ length }, (_, index) => index);
    let state = (0x9e3779b9 ^ epoch) >>> 0;
    const random = () => {
        state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
        return state / 2 ** 32;
    };
    for (let index = length - 1; index > 0; index -= 1) {
        const other = Math.floor(random() * (index + 1));
        [indexes[index], indexes[other]] = [indexes[other]!, indexes[index]!];
    }
    return indexes;
}

function probabilities(
    weights: Float64Array[],
    features: Map<number, number>,
): number[] {
    const scores = weights.map((classWeights) => {
        let score = 0;
        for (const [index, value] of features) {
            score += (classWeights[index] ?? 0) * value;
        }
        return score;
    });
    const maximum = Math.max(...scores);
    const exponentials = scores.map((score) => Math.exp(score - maximum));
    const total = exponentials.reduce((sum, value) => sum + value, 0);
    return exponentials.map((value) => value / total);
}

function train(
    examples: Example[],
    means: number[],
    deviations: number[],
): Float64Array[] {
    const weights = TYPES.map(() => new Float64Array(DIMENSIONS));
    const counts = TYPES.map(
        (type) => examples.filter((example) => example.type === type).length,
    );
    const classWeights = counts.map(
        (count) => examples.length / (TYPES.length * Math.max(1, count)),
    );

    for (let epoch = 0; epoch < EPOCHS; epoch += 1) {
        const learningRate = 0.08 / Math.sqrt(epoch + 1);
        for (const exampleIndex of shuffledIndexes(examples.length, epoch)) {
            const example = examples[exampleIndex];
            if (!example) {
                continue;
            }
            const features = rowFeatures(example.row, means, deviations);
            const predicted = probabilities(weights, features);
            const target = TYPES.indexOf(example.type);
            const importance =
                (classWeights[target] ?? 1) *
                (example.source === 'reviewed'
                    ? 40
                    : example.source === 'asdb'
                      ? 1
                      : 0.35);
            for (let typeIndex = 0; typeIndex < TYPES.length; typeIndex += 1) {
                const error =
                    ((typeIndex === target ? 1 : 0) -
                        (predicted[typeIndex] ?? 0)) *
                    importance;
                const classWeight = weights[typeIndex];
                if (!classWeight) {
                    continue;
                }
                for (const [featureIndex, value] of features) {
                    classWeight[featureIndex] =
                        (classWeight[featureIndex] ?? 0) *
                            (1 - learningRate * 0.00001) +
                        learningRate * error * value;
                }
            }
        }
    }
    return weights;
}

function organizationKey(row: Row): string {
    return normalizeText(row.organization || row.name);
}

function isValidationOrganization(row: Row): boolean {
    return hash(organizationKey(row)) % 5 === 0;
}

function printEvaluation(
    weights: Float64Array[],
    examples: Example[],
    means: number[],
    deviations: number[],
): void {
    const confusion = TYPES.map(() => TYPES.map(() => 0));
    const predictions: { correct: boolean; confidence: number }[] = [];
    for (const example of examples) {
        const result = predict(weights, example.row, means, deviations);
        confusion[TYPES.indexOf(example.type)]![TYPES.indexOf(result.type)]! +=
            1;
        predictions.push({
            correct: result.type === example.type,
            confidence: result.confidence,
        });
    }

    let correct = 0;
    let total = 0;
    for (let expected = 0; expected < TYPES.length; expected += 1) {
        const row = confusion[expected] ?? [];
        const classTotal = row.reduce((sum, value) => sum + value, 0);
        const classCorrect = row[expected] ?? 0;
        correct += classCorrect;
        total += classTotal;
        console.log(
            `${TYPES[expected]} recall: ${classTotal === 0 ? 'n/a' : `${((classCorrect / classTotal) * 100).toFixed(1)}%`} (${classCorrect}/${classTotal})`,
        );
    }
    console.log(
        `Organization-held-out accuracy: ${((correct / Math.max(1, total)) * 100).toFixed(1)}% (${correct}/${total})`,
    );
    console.log('Confusion rows: expected Hosting, ISP, Business');
    confusion.forEach((row) => console.log(row.join(',')));
    for (const threshold of [0.6, 0.7, 0.8, 0.9]) {
        const accepted = predictions.filter(
            (prediction) => prediction.confidence >= threshold,
        );
        const acceptedCorrect = accepted.filter(
            (prediction) => prediction.correct,
        ).length;
        console.log(
            `At ${(threshold * 100).toFixed(0)}% confidence: ${((acceptedCorrect / Math.max(1, accepted.length)) * 100).toFixed(1)}% accuracy, ${((accepted.length / predictions.length) * 100).toFixed(1)}% coverage`,
        );
    }
}

function predict(
    weights: Float64Array[],
    row: Row,
    means: number[],
    deviations: number[],
): { type: AsnType; confidence: number } {
    const result = probabilities(weights, rowFeatures(row, means, deviations));
    const winner = result.indexOf(Math.max(...result));
    return {
        type: TYPES[winner] ?? 'Business',
        confidence: result[winner] ?? 0,
    };
}

async function main(): Promise<void> {
    const inputPath = path.resolve(getArgument('--input'));
    const labelsPath = path.resolve(getArgument('--labels'));
    const asdbPath = path.resolve(getArgument('--asdb'));
    const outputPath = path.resolve(getArgument('--output'));
    const evaluate = process.argv.includes('--evaluate');
    const crossValidate = process.argv.includes('--cross-validate');
    const rows = parseRows(await fs.readFile(inputPath, 'utf8'));
    const reviewed = parseReviewedLabels(await fs.readFile(labelsPath, 'utf8'));
    const asdb = parseAsdbLabels(await fs.readFile(asdbPath, 'utf8'));
    const examples = rows.flatMap((row): Example[] => {
        const reviewedType = reviewed.get(row.asn);
        if (reviewedType && !evaluate) {
            return [{ row, type: reviewedType, source: 'reviewed' }];
        }
        if (reviewedType) {
            return [];
        }
        const asdbType = asdb.get(row.asn);
        if (asdbType) {
            if (crossValidate && isValidationOrganization(row)) {
                return [];
            }
            return [{ row, type: asdbType, source: 'asdb' }];
        }
        const type = weakType(row);
        return type ? [{ row, type, source: 'weak' }] : [];
    });
    const { means, deviations } = normalization(rows);
    const weights = train(examples, means, deviations);

    if (crossValidate) {
        const validation = rows.flatMap((row): Example[] => {
            const type = asdb.get(row.asn);
            return type && isValidationOrganization(row)
                ? [{ row, type, source: 'asdb' }]
                : [];
        });
        printEvaluation(weights, validation, means, deviations);
        return;
    }

    if (evaluate) {
        let correct = 0;
        for (const [asn, expected] of reviewed) {
            const row = rows.find((candidate) => candidate.asn === asn);
            if (!row) {
                continue;
            }
            const result = predict(weights, row, means, deviations);
            correct += result.type === expected ? 1 : 0;
            console.log(
                `AS${asn}: ${result.type} ${(result.confidence * 100).toFixed(1)}% (expected ${expected})`,
            );
        }
        console.log(`Held-out accuracy: ${correct}/${reviewed.size}`);
        return;
    }

    const csv = [
        'asn,type,confidence,source',
        ...rows.map((row) => {
            const reviewedType = reviewed.get(row.asn);
            if (reviewedType) {
                return `${row.asn},${reviewedType},1,reviewed`;
            }
            const result = predict(weights, row, means, deviations);
            const asdbType = asdb.get(row.asn);
            if (asdbType) {
                return `${row.asn},${asdbType},1,asdb`;
            }
            const type = result.confidence >= 0.8 ? result.type : 'Unknown';
            return `${row.asn},${type},${result.confidence.toFixed(6)},ml`;
        }),
        '',
    ].join('\n');
    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await fs.writeFile(
        outputPath,
        outputPath.endsWith('.gz') ? await gzip(Buffer.from(csv)) : csv,
    );
    console.error(
        `Trained on ${examples.length.toLocaleString('en-US')} ASNs and classified ${rows.length.toLocaleString('en-US')} ASNs (${asdb.size.toLocaleString('en-US')} ASDB labels available)`,
    );
}

main().catch((error: unknown) => {
    console.error(
        error instanceof Error ? (error.stack ?? error.message) : error,
    );
    process.exitCode = 1;
});
