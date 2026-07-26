export async function gzip(data: Uint8Array): Promise<Uint8Array> {
    return transform(data, new CompressionStream('gzip'));
}

export async function ungzip(data: Uint8Array): Promise<Uint8Array> {
    return transform(data, new DecompressionStream('gzip'));
}

export function decodeB64(value: string): Uint8Array {
    const binary = atob(value);

    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function transform(
    data: Uint8Array,
    stream: TransformStream,
): Promise<Uint8Array> {
    const input = new Response(data).body;

    if (!input) {
        throw new Error('Unable to create input stream');
    }

    const output = input.pipeThrough(stream);
    const buffer = await new Response(output).arrayBuffer();

    return new Uint8Array(buffer);
}
