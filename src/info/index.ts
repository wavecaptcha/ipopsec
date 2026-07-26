import { DatabaseRecord, MetadataRecord } from '../data/db.js';
import { getIpType } from '../utils/type.js';
import { lookupAsn } from './asn.js';

export function getInfo(ip: string): {
    asn: (DatabaseRecord & { metadata: MetadataRecord | undefined })[];
} {
    const type = getIpType(ip);

    if (type === null) throw new Error('Invalid IP string.');

    return { asn: lookupAsn(ip) };
}
