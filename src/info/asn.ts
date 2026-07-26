import asnV4Data from '../data/asn/asn-v4.js';
import asnV6Data from '../data/asn/asn-v6.js';
import metadataData from '../data/asn/asn-metadata.js';

import { CidrDatabase, CidrMetadata } from '../data/db.js';
import { decodeB64, ungzip } from '../data/compressor.js';
import { getIpType } from '../utils/type.js';

async function loadDatabase(data: string): Promise<Uint8Array> {
    return ungzip(decodeB64(data));
}

const [dbV4, dbV6, metadata] = await Promise.all([
    loadDatabase(asnV4Data).then((data) => CidrDatabase.from(data)),
    loadDatabase(asnV6Data).then((data) => CidrDatabase.from(data)),
    loadDatabase(metadataData).then((data) => CidrMetadata.from(data)),
]);

export function lookupAsn(ip: string) {
    const type = getIpType(ip);

    const database = type === 'ipv4' ? dbV4 : dbV6;

    return database.lookupWithMetadata(ip, metadata);
}
