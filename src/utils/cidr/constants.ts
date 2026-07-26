export type IpVersion = 4 | 6;

export type Cidr = {
    address: Uint8Array;
    prefixLength: number;
    version: IpVersion;
};

export const IPV4_BYTE_LENGTH = 4;
export const IPV4_MAX_PREFIX_LENGTH = 32;
export const IPV6_BYTE_LENGTH = 16;
export const IPV6_GROUP_COUNT = 8;
export const IPV6_MAX_PREFIX_LENGTH = 128;
