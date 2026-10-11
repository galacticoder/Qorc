import { readUint32BE } from './bytes.js';

const MAX_PNG_CHUNKS = 512;
const PNG_METADATA_CHUNKS = new Set(['tEXt', 'zTXt', 'iTXt', 'iCCP', 'eXIf']);
export function dimensionsWithinLimits(dimensions, limits) {
    return (Number.isSafeInteger(dimensions.width) &&
        Number.isSafeInteger(dimensions.height) &&
        dimensions.width > 0 &&
        dimensions.height > 0 &&
        dimensions.width <= limits.maxWidth &&
        dimensions.height <= limits.maxHeight &&
        dimensions.width * dimensions.height <= limits.maxPixels);
}
const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const PNG_CRC_TABLE = (() => {
    const table = new Uint32Array(256);
    for (let index = 0; index < table.length; index += 1) {
        let value = index;
        for (let bit = 0; bit < 8; bit += 1) {
            value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
        }
        table[index] = value >>> 0;
    }
    return table;
})();
function pngCrc32(bytes, start, end) {
    let crc = 0xffffffff;
    for (let offset = start; offset < end; offset += 1) {
        crc = PNG_CRC_TABLE[(crc ^ bytes[offset]) & 0xff] ^ (crc >>> 8);
    }
    return (crc ^ 0xffffffff) >>> 0;
}
function isPngChunkName(bytes, offset) {
    for (let index = 0; index < 4; index += 1) {
        const value = bytes[offset + index];
        if (!((value >= 0x41 && value <= 0x5a) || (value >= 0x61 && value <= 0x7a)))
            return false;
    }
    return (bytes[offset + 2] & 0x20) === 0;
}
function validPngBitDepth(bitDepth, colorType) {
    if (colorType === 0)
        return [1, 2, 4, 8, 16].includes(bitDepth);
    if (colorType === 2 || colorType === 4 || colorType === 6)
        return bitDepth === 8 || bitDepth === 16;
    return colorType === 3 && [1, 2, 4, 8].includes(bitDepth);
}
export function validatePngContainer(bytes, limits, onMetadataChunk = null) {
    if (bytes.length < 45)
        throw new Error('Invalid image PNG');
    for (let index = 0; index < PNG_SIGNATURE.length; index += 1) {
        if (bytes[index] !== PNG_SIGNATURE[index])
            throw new Error('Invalid image PNG signature');
    }
    let offset = PNG_SIGNATURE.length;
    let chunkCount = 0;
    let dimensions = null;
    let bitDepth = 0;
    let colorType = -1;
    let paletteEntries = 0;
    let sawIdat = false;
    let endedIdat = false;
    let idatBytes = 0;
    const seen = new Set();
    while (offset + 12 <= bytes.length) {
        chunkCount += 1;
        if (chunkCount > MAX_PNG_CHUNKS)
            throw new Error('Image PNG has too many chunks');
        const dataLength = readUint32BE(bytes, offset);
        const typeOffset = offset + 4;
        const dataOffset = typeOffset + 4;
        if (!isPngChunkName(bytes, typeOffset) || dataLength > bytes.length - dataOffset - 4) {
            throw new Error('Invalid image PNG chunk');
        }
        const dataEnd = dataOffset + dataLength;
        const chunkEnd = dataEnd + 4;
        const chunkType = String.fromCharCode(bytes[typeOffset], bytes[typeOffset + 1], bytes[typeOffset + 2], bytes[typeOffset + 3]);
        if (pngCrc32(bytes, typeOffset, dataEnd) !== readUint32BE(bytes, dataEnd)) {
            throw new Error('Invalid image PNG chunk checksum');
        }
        if (chunkType === 'IHDR') {
            if (chunkCount !== 1 || seen.has(chunkType) || dataLength !== 13) {
                throw new Error('Invalid image PNG header');
            }
            const width = readUint32BE(bytes, dataOffset);
            const height = readUint32BE(bytes, dataOffset + 4);
            bitDepth = bytes[dataOffset + 8];
            colorType = bytes[dataOffset + 9];
            if (!dimensionsWithinLimits({ width, height }, limits)) {
                throw new Error(`Image PNG dimensions ${width}×${height} exceed limits (${limits.maxWidth}×${limits.maxHeight}, ${limits.maxPixels} pixels)`);
            }
            if (width > 0x7fffffff || height > 0x7fffffff ||
                !validPngBitDepth(bitDepth, colorType) ||
                bytes[dataOffset + 10] !== 0 ||
                bytes[dataOffset + 11] !== 0 ||
                bytes[dataOffset + 12] > 1) {
                throw new Error('Invalid image PNG header');
            }
            dimensions = { width, height };
            seen.add(chunkType);
            offset = chunkEnd;
            continue;
        }
        if (!dimensions)
            throw new Error('Image PNG header must be first');
        if (chunkType === 'IDAT') {
            if (endedIdat || (colorType === 3 && paletteEntries === 0)) {
                throw new Error('Invalid image PNG data ordering');
            }
            sawIdat = true;
            idatBytes += dataLength;
            if (!Number.isSafeInteger(idatBytes))
                throw new Error('Invalid image PNG data size');
            offset = chunkEnd;
            continue;
        }
        if (sawIdat)
            endedIdat = true;
        if (PNG_METADATA_CHUNKS.has(chunkType) && typeof onMetadataChunk === 'function') {
            onMetadataChunk(offset, chunkEnd);
            offset = chunkEnd;
            continue;
        }
        if (chunkType === 'IEND') {
            if (seen.has(chunkType) || dataLength !== 0 || !sawIdat || idatBytes === 0 || chunkEnd !== bytes.length) {
                throw new Error('Invalid image PNG termination');
            }
            if (colorType === 3 && paletteEntries === 0)
                throw new Error('Image PNG palette is missing');
            return dimensions;
        }
        if (seen.has(chunkType))
            throw new Error('Duplicate image PNG chunk');
        if (chunkType === 'PLTE') {
            if (sawIdat || colorType === 0 || colorType === 4 || dataLength === 0 || dataLength % 3 !== 0) {
                throw new Error('Invalid image PNG palette');
            }
            paletteEntries = dataLength / 3;
            if (paletteEntries > 256 || (colorType === 3 && paletteEntries > (1 << bitDepth))) {
                throw new Error('Invalid image PNG palette');
            }
        }
        else if (chunkType === 'tRNS') {
            const expectedLength = colorType === 0 ? 2 : colorType === 2 ? 6 : -1;
            if (sawIdat ||
                colorType === 4 || colorType === 6 ||
                (colorType === 3
                    ? paletteEntries === 0 || dataLength === 0 || dataLength > paletteEntries
                    : dataLength !== expectedLength)) {
                throw new Error('Invalid image PNG transparency chunk');
            }
        }
        else if (chunkType === 'cHRM') {
            if (sawIdat || paletteEntries !== 0 || dataLength !== 32)
                throw new Error('Invalid image PNG color chunk');
        }
        else if (chunkType === 'gAMA') {
            if (sawIdat || paletteEntries !== 0 || dataLength !== 4)
                throw new Error('Invalid image PNG gamma chunk');
        }
        else if (chunkType === 'sBIT') {
            const expected = colorType === 0 ? 1 : colorType === 2 || colorType === 3 ? 3 : colorType === 4 ? 2 : 4;
            if (sawIdat || paletteEntries !== 0 || dataLength !== expected)
                throw new Error('Invalid image PNG significant-bits chunk');
        }
        else if (chunkType === 'sRGB') {
            if (sawIdat || paletteEntries !== 0 || dataLength !== 1 || bytes[dataOffset] > 3) {
                throw new Error('Invalid image PNG color-space chunk');
            }
        }
        else if (chunkType === 'pHYs') {
            if (sawIdat || dataLength !== 9 || bytes[dataOffset + 8] > 1)
                throw new Error('Invalid image PNG density chunk');
        }
        else if (chunkType === 'bKGD') {
            const expected = colorType === 0 || colorType === 4 ? 2 : colorType === 3 ? 1 : 6;
            if (sawIdat || dataLength !== expected ||
                (colorType === 3 && (paletteEntries === 0 || bytes[dataOffset] >= paletteEntries))) {
                throw new Error('Invalid image PNG background chunk');
            }
        }
        else if (chunkType === 'hIST') {
            if (sawIdat || paletteEntries === 0 || dataLength !== paletteEntries * 2) {
                throw new Error('Invalid image PNG histogram chunk');
            }
        }
        else if (chunkType === 'tIME') {
            if (sawIdat || dataLength !== 7)
                throw new Error('Invalid image PNG time chunk');
        }
        else {
            throw new Error('Unsupported image PNG chunk');
        }
        seen.add(chunkType);
        offset = chunkEnd;
    }
    throw new Error('Image PNG is incomplete');
}
