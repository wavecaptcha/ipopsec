import {
    IPV4_BYTE_LENGTH,
    IPV6_BYTE_LENGTH,
    IPV6_MAX_PREFIX_LENGTH,
} from '../utils/cidr/constants.js';
import { getIpVersion, maskIp, parseIp } from '../utils/cidr/index.js';

const MAGIC = [0x49, 0x50, 0x44, 0x42]; // IPDB
const HEADER_SIZE = 12;
const VERSION = 1;
const RECORD_PREFIX_SIZE = 1 + 4 + 4;
const METADATA_MAGIC = [0x49, 0x50, 0x4d, 0x44]; // IPMD
const METADATA_HEADER_SIZE = 9;
const METADATA_FIELD_COUNT = 8;

export type DatabaseRecord = {
    asn: number;
    metadataId: number;
    prefixLength: number;
};

export type DatabaseRecordInput = DatabaseRecord & {
    address: Uint8Array;
};

export type MetadataRecord = {
    asnName: string;
    asnChanged: string;
    country: string;
    opaqueId: string;
    orgChanged: string;
    orgId: string;
    organization: string;
    registry: string;
};

export type MetadataRecordInput = MetadataRecord & {
    asn: number;
};

type DatabaseHeader = {
    ipVersion: 4 | 6;
    recordCount: number;
    recordSize: number;
};

export class CidrDatabase {
    readonly #bytes: Uint8Array;
    readonly #view: DataView;
    readonly #header: DatabaseHeader;
    readonly #addressSize: number;

    private constructor(bytes: Uint8Array, header: DatabaseHeader) {
        this.#bytes = bytes;
        this.#view = new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        );
        this.#header = header;
        this.#addressSize =
            header.ipVersion === 4 ? IPV4_BYTE_LENGTH : IPV6_BYTE_LENGTH;
    }

    static from(data: Uint8Array): CidrDatabase {
        if (data.byteLength < HEADER_SIZE) {
            throw new Error('CIDR database is smaller than its header');
        }

        const bytes = new Uint8Array(data);
        const view = new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        );

        for (const [index, byte] of MAGIC.entries()) {
            if (view.getUint8(index) !== byte) {
                throw new Error('Invalid CIDR database magic');
            }
        }

        if (view.getUint8(4) !== VERSION) {
            throw new Error(
                `Unsupported CIDR database version: ${view.getUint8(4)}`,
            );
        }

        const ipVersion = view.getUint8(5);

        if (ipVersion !== 4 && ipVersion !== 6) {
            throw new Error(`Invalid CIDR database IP version: ${ipVersion}`);
        }

        const addressSize =
            ipVersion === 4 ? IPV4_BYTE_LENGTH : IPV6_BYTE_LENGTH;
        const recordSize = view.getUint16(6, false);
        const recordCount = view.getUint32(8, false);
        const expectedRecordSize = addressSize + RECORD_PREFIX_SIZE;

        if (recordSize !== expectedRecordSize) {
            throw new Error(`Invalid CIDR database record size: ${recordSize}`);
        }

        if (HEADER_SIZE + recordSize * recordCount > bytes.byteLength) {
            throw new Error('CIDR database is truncated');
        }

        return new CidrDatabase(bytes, {
            ipVersion,
            recordCount,
            recordSize,
        });
    }

    get ipVersion(): 4 | 6 {
        return this.#header.ipVersion;
    }

    get recordCount(): number {
        return this.#header.recordCount;
    }

    lookup(ip: string | Uint8Array): DatabaseRecord[] {
        const address = typeof ip === 'string' ? parseIp(ip) : ip;

        if (getIpVersion(address) !== this.#header.ipVersion) {
            return [];
        }

        const maxPrefixLength =
            this.#header.ipVersion === 4 ? 32 : IPV6_MAX_PREFIX_LENGTH;

        for (
            let prefixLength = maxPrefixLength;
            prefixLength >= 0;
            prefixLength--
        ) {
            const network = maskIp(address, prefixLength);
            const first = this.#findFirst(network, prefixLength);

            if (first === -1) {
                continue;
            }

            const matches: DatabaseRecord[] = [];

            for (let index = first; index < this.#header.recordCount; index++) {
                const record = this.#readRecord(index);

                if (
                    record.prefixLength !== prefixLength ||
                    !this.#sameAddress(index, network)
                ) {
                    break;
                }

                matches.push(record);
            }

            return matches;
        }

        return [];
    }

    lookupWithMetadata(
        ip: string | Uint8Array,
        metadata: CidrMetadata,
    ): (DatabaseRecord & { metadata: MetadataRecord | undefined })[] {
        return this.lookup(ip).map((record) => ({
            ...record,
            metadata: metadata.get(record.metadataId),
        }));
    }

    #recordOffset(index: number): number {
        return HEADER_SIZE + index * this.#header.recordSize;
    }

    #readRecord(index: number): DatabaseRecord {
        const offset = this.#recordOffset(index) + this.#addressSize;

        return {
            prefixLength: this.#view.getUint8(offset),
            asn: this.#view.getUint32(offset + 1, false),
            metadataId: this.#view.getUint32(offset + 5, false),
        };
    }

    #sameAddress(index: number, address: Uint8Array): boolean {
        const offset = this.#recordOffset(index);

        for (let byte = 0; byte < this.#addressSize; byte++) {
            if (this.#bytes[offset + byte] !== address[byte]) {
                return false;
            }
        }

        return true;
    }

    #compare(index: number, address: Uint8Array, prefixLength: number): number {
        const offset = this.#recordOffset(index);

        for (let byte = 0; byte < this.#addressSize; byte++) {
            const difference = this.#bytes[offset + byte]! - address[byte]!;

            if (difference !== 0) {
                return difference;
            }
        }

        return this.#view.getUint8(offset + this.#addressSize) - prefixLength;
    }

    #findFirst(address: Uint8Array, prefixLength: number): number {
        let low = 0;
        let high = this.#header.recordCount;

        while (low < high) {
            const middle = Math.floor((low + high) / 2);

            if (this.#compare(middle, address, prefixLength) < 0) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }

        if (
            low >= this.#header.recordCount ||
            this.#compare(low, address, prefixLength) !== 0
        ) {
            return -1;
        }

        return low;
    }
}

export class CidrMetadata {
    readonly #records: Map<number, MetadataRecord>;

    private constructor(records: Map<number, MetadataRecord>) {
        this.#records = records;
    }

    static from(data: Uint8Array): CidrMetadata {
        const view = new DataView(
            data.buffer,
            data.byteOffset,
            data.byteLength,
        );

        if (data.byteLength < METADATA_HEADER_SIZE) {
            throw new Error('CIDR metadata is smaller than its header');
        }

        for (const [index, byte] of METADATA_MAGIC.entries()) {
            if (view.getUint8(index) !== byte) {
                throw new Error('Invalid CIDR metadata magic');
            }
        }

        if (view.getUint8(4) !== VERSION) {
            throw new Error('Unsupported CIDR metadata version');
        }

        const recordCount = view.getUint32(5, false);
        let offset = METADATA_HEADER_SIZE;
        const records = new Map<number, MetadataRecord>();
        const decoder = new TextDecoder();

        for (let index = 0; index < recordCount; index++) {
            if (offset + 4 > data.byteLength) {
                throw new Error('CIDR metadata is truncated');
            }

            const asn = view.getUint32(offset, false);
            offset += 4;
            const fields: string[] = [];

            for (let field = 0; field < METADATA_FIELD_COUNT; field++) {
                if (offset + 4 > data.byteLength) {
                    throw new Error('CIDR metadata is truncated');
                }

                const length = view.getUint32(offset, false);
                offset += 4;

                if (offset + length > data.byteLength) {
                    throw new Error('CIDR metadata is truncated');
                }

                fields.push(
                    decoder.decode(data.subarray(offset, offset + length)),
                );
                offset += length;
            }

            const [
                asnName,
                asnChanged,
                country,
                opaqueId,
                orgChanged,
                orgId,
                organization,
                registry,
            ] = fields;

            records.set(asn, {
                asnName: asnName!,
                asnChanged: asnChanged!,
                country: country!,
                opaqueId: opaqueId!,
                orgChanged: orgChanged!,
                orgId: orgId!,
                organization: organization!,
                registry: registry!,
            });
        }

        return new CidrMetadata(records);
    }

    get(asn: number): MetadataRecord | undefined {
        return this.#records.get(asn);
    }
}

export function encodeDatabase(
    ipVersion: 4 | 6,
    input: DatabaseRecordInput[],
): Uint8Array {
    const addressSize = ipVersion === 4 ? IPV4_BYTE_LENGTH : IPV6_BYTE_LENGTH;
    const recordSize = addressSize + RECORD_PREFIX_SIZE;
    const records = input.map((record) => ({
        ...record,
        address: new Uint8Array(record.address),
    }));

    records.sort((left, right) => {
        for (let index = 0; index < addressSize; index++) {
            const difference = left.address[index]! - right.address[index]!;

            if (difference !== 0) {
                return difference;
            }
        }

        return left.prefixLength - right.prefixLength;
    });

    const bytes = new Uint8Array(HEADER_SIZE + recordSize * records.length);
    const view = new DataView(bytes.buffer);

    bytes.set(MAGIC, 0);
    view.setUint8(4, VERSION);
    view.setUint8(5, ipVersion);
    view.setUint16(6, recordSize, false);
    view.setUint32(8, records.length, false);

    records.forEach((record, index) => {
        const offset = HEADER_SIZE + index * recordSize;

        bytes.set(record.address, offset);
        view.setUint8(offset + addressSize, record.prefixLength);
        view.setUint32(offset + addressSize + 1, record.asn, false);
        view.setUint32(offset + addressSize + 5, record.metadataId, false);
    });

    return bytes;
}

export function encodeMetadata(input: MetadataRecordInput[]): Uint8Array {
    const encoder = new TextEncoder();
    const records = [...input].sort((left, right) => left.asn - right.asn);
    const encoded: { asn: number; fields: Uint8Array[] }[] = records.map(
        (record) => ({
            asn: record.asn,
            fields: [
                record.asnName,
                record.asnChanged,
                record.country,
                record.opaqueId,
                record.orgChanged,
                record.orgId,
                record.organization,
                record.registry,
            ].map((value) => encoder.encode(value)),
        }),
    );
    const size =
        METADATA_HEADER_SIZE +
        encoded.reduce(
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
    let offset = METADATA_HEADER_SIZE;

    data.set(METADATA_MAGIC);
    view.setUint8(4, VERSION);
    view.setUint32(5, records.length, false);

    for (const record of encoded) {
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
