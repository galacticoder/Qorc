import { asciiMatchesAt, readUint32BE } from './byte-utils';

export interface ImageDimensions {
    width: number;
    height: number;
}

export interface ImageDimensionLimits {
    maxWidth: number;
    maxHeight: number;
    maxPixels: number;
}

const JPEG_SOF_MARKERS = new Set([
    0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7,
    0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf
]);
const SUPPORTED_JPEG_SOF_MARKERS = new Set([0xc0, 0xc2]);
const MAX_JPEG_SEGMENTS = 512;
const MAX_JPEG_SCANS = 16;
const MAX_PNG_CHUNKS = 512;
const MAX_WEBP_CHUNKS = 4;

function readUint24LE(bytes: Uint8Array, offset: number): number {
    return bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16);
}

function readUint32LE(bytes: Uint8Array, offset: number): number {
    return (
        bytes[offset] |
        (bytes[offset + 1] << 8) |
        (bytes[offset + 2] << 16) |
        (bytes[offset + 3] << 24)
    ) >>> 0;
}

function dimensionsWithinLimits(dimensions: ImageDimensions, limits: ImageDimensionLimits): boolean {
    return (
        Number.isSafeInteger(dimensions.width) &&
        Number.isSafeInteger(dimensions.height) &&
        dimensions.width > 0 &&
        dimensions.height > 0 &&
        dimensions.width <= limits.maxWidth &&
        dimensions.height <= limits.maxHeight &&
        dimensions.width * dimensions.height <= limits.maxPixels
    );
}

export function validateJpegContainer(
    bytes: Uint8Array,
    limits: ImageDimensionLimits,
    errorNoun = 'image JPEG',
    dimensionError = 'Decoded image dimensions exceed limit'
): ImageDimensions {
    const subject = `${errorNoun.charAt(0).toUpperCase()}${errorNoun.slice(1)}`;
    if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) {
        throw new Error(`Invalid ${errorNoun}`);
    }

    let offset = 2;
    let dimensions: ImageDimensions | null = null;
    let componentIds: Set<number> | null = null;
    let segmentCount = 0;
    let scanCount = 0;

    while (offset < bytes.length) {
        if (bytes[offset] !== 0xff) throw new Error(`Invalid ${errorNoun} marker`);
        while (offset < bytes.length && bytes[offset] === 0xff) offset += 1;
        if (offset >= bytes.length) throw new Error(`Truncated ${errorNoun} marker`);
        const marker = bytes[offset++];

        segmentCount += 1;
        if (segmentCount > MAX_JPEG_SEGMENTS) {
            throw new Error(`${subject} has too many segments`);
        }
        if (marker === 0x00 || marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
            throw new Error(`Invalid ${errorNoun} marker placement`);
        }
        if (marker === 0xd9) {
            if (!dimensions || scanCount === 0 || offset !== bytes.length) {
                throw new Error(`Invalid ${errorNoun} termination`);
            }
            return dimensions;
        }
        if (offset + 1 >= bytes.length) throw new Error(`Truncated ${errorNoun} segment`);
        const segmentLength = (bytes[offset] << 8) | bytes[offset + 1];
        const segmentEnd = offset + segmentLength;
        if (segmentLength < 2 || segmentEnd > bytes.length) {
            throw new Error(`Invalid ${errorNoun} segment length`);
        }

        if (JPEG_SOF_MARKERS.has(marker)) {
            if (!SUPPORTED_JPEG_SOF_MARKERS.has(marker) || dimensions) {
                throw new Error(`Unsupported or duplicate ${errorNoun} frame header`);
            }
            if (segmentLength < 11 || bytes[offset + 2] !== 8) {
                throw new Error(`Invalid ${errorNoun} frame header`);
            }
            const height = (bytes[offset + 3] << 8) | bytes[offset + 4];
            const width = (bytes[offset + 5] << 8) | bytes[offset + 6];
            const componentCount = bytes[offset + 7];
            if (
                (componentCount !== 1 && componentCount !== 3) ||
                segmentLength !== 8 + (3 * componentCount)
            ) {
                throw new Error(`Invalid ${errorNoun} component layout`);
            }
            if (!dimensionsWithinLimits({ width, height }, limits)) {
                throw new Error(dimensionError);
            }

            componentIds = new Set<number>();
            for (let index = 0; index < componentCount; index += 1) {
                const componentOffset = offset + 8 + (index * 3);
                const componentId = bytes[componentOffset];
                const sampling = bytes[componentOffset + 1];
                const horizontalSampling = sampling >>> 4;
                const verticalSampling = sampling & 0x0f;
                const quantizationTable = bytes[componentOffset + 2];
                if (
                    componentIds.has(componentId) ||
                    horizontalSampling < 1 || horizontalSampling > 4 ||
                    verticalSampling < 1 || verticalSampling > 4 ||
                    quantizationTable > 3
                ) {
                    throw new Error(`Invalid ${errorNoun} component`);
                }
                componentIds.add(componentId);
            }
            dimensions = { width, height };
            offset = segmentEnd;
            continue;
        }

        const isAllowedVariableSegment = (
            marker === 0xc4 ||
            marker === 0xdb ||
            marker === 0xdd ||
            marker === 0xfe ||
            (marker >= 0xe0 && marker <= 0xef)
        );
        if (isAllowedVariableSegment) {
            offset = segmentEnd;
            continue;
        }
        if (marker !== 0xda || !dimensions || !componentIds) {
            throw new Error(`Unsupported ${errorNoun} segment`);
        }

        scanCount += 1;
        if (scanCount > MAX_JPEG_SCANS) throw new Error(`${subject} has too many scans`);
        const scanComponentCount = bytes[offset + 2];
        if (
            scanComponentCount < 1 ||
            scanComponentCount > componentIds.size ||
            segmentLength !== 6 + (2 * scanComponentCount)
        ) {
            throw new Error(`Invalid ${errorNoun} scan header`);
        }
        const scanComponentIds = new Set<number>();
        for (let index = 0; index < scanComponentCount; index += 1) {
            const componentOffset = offset + 3 + (index * 2);
            const componentId = bytes[componentOffset];
            const tableSelectors = bytes[componentOffset + 1];
            if (
                !componentIds.has(componentId) ||
                scanComponentIds.has(componentId) ||
                (tableSelectors >>> 4) > 3 ||
                (tableSelectors & 0x0f) > 3
            ) {
                throw new Error(`Invalid ${errorNoun} scan component`);
            }
            scanComponentIds.add(componentId);
        }

        offset = segmentEnd;
        let foundNextMarker = false;
        while (offset < bytes.length) {
            if (bytes[offset] !== 0xff) {
                offset += 1;
                continue;
            }
            const markerStart = offset;
            while (offset < bytes.length && bytes[offset] === 0xff) offset += 1;
            if (offset >= bytes.length) throw new Error(`Truncated ${errorNoun} entropy data`);
            const entropyMarker = bytes[offset];
            if (
                entropyMarker === 0x00 ||
                entropyMarker === 0x01 ||
                (entropyMarker >= 0xd0 && entropyMarker <= 0xd7)
            ) {
                offset += 1;
                continue;
            }
            offset = markerStart;
            foundNextMarker = true;
            break;
        }
        if (!foundNextMarker) throw new Error(`${subject} is missing an end marker`);
    }
    throw new Error(`${subject} is incomplete`);
}

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] as const;
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

function pngCrc32(bytes: Uint8Array, start: number, end: number): number {
    let crc = 0xffffffff;
    for (let offset = start; offset < end; offset += 1) {
        crc = PNG_CRC_TABLE[(crc ^ bytes[offset]) & 0xff] ^ (crc >>> 8);
    }
    return (crc ^ 0xffffffff) >>> 0;
}

function isPngChunkName(bytes: Uint8Array, offset: number): boolean {
    for (let index = 0; index < 4; index += 1) {
        const value = bytes[offset + index];
        if (!((value >= 0x41 && value <= 0x5a) || (value >= 0x61 && value <= 0x7a))) return false;
    }
    return (bytes[offset + 2] & 0x20) === 0;
}

function validPngBitDepth(bitDepth: number, colorType: number): boolean {
    if (colorType === 0) return [1, 2, 4, 8, 16].includes(bitDepth);
    if (colorType === 2 || colorType === 4 || colorType === 6) return bitDepth === 8 || bitDepth === 16;
    return colorType === 3 && [1, 2, 4, 8].includes(bitDepth);
}

export function validatePngContainer(bytes: Uint8Array, limits: ImageDimensionLimits): ImageDimensions {
    if (bytes.length < 45) throw new Error('Invalid image PNG');
    for (let index = 0; index < PNG_SIGNATURE.length; index += 1) {
        if (bytes[index] !== PNG_SIGNATURE[index]) throw new Error('Invalid image PNG signature');
    }

    let offset: number = PNG_SIGNATURE.length;
    let chunkCount = 0;
    let dimensions: ImageDimensions | null = null;
    let bitDepth = 0;
    let colorType = -1;
    let paletteEntries = 0;
    let sawIdat = false;
    let endedIdat = false;
    let idatBytes = 0;
    const seen = new Set<string>();

    while (offset + 12 <= bytes.length) {
        chunkCount += 1;
        if (chunkCount > MAX_PNG_CHUNKS) throw new Error('Image PNG has too many chunks');

        const dataLength = readUint32BE(bytes, offset);
        const typeOffset = offset + 4;
        const dataOffset = typeOffset + 4;
        if (!isPngChunkName(bytes, typeOffset) || dataLength > bytes.length - dataOffset - 4) {
            throw new Error('Invalid image PNG chunk');
        }
        const dataEnd = dataOffset + dataLength;
        const chunkEnd = dataEnd + 4;
        const chunkType = String.fromCharCode(
            bytes[typeOffset], bytes[typeOffset + 1], bytes[typeOffset + 2], bytes[typeOffset + 3]
        );
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
            if (
                !dimensionsWithinLimits({ width, height }, limits) ||
                width > 0x7fffffff || height > 0x7fffffff ||
                !validPngBitDepth(bitDepth, colorType) ||
                bytes[dataOffset + 10] !== 0 ||
                bytes[dataOffset + 11] !== 0 ||
                bytes[dataOffset + 12] > 1
            ) {
                throw new Error('Invalid image PNG header');
            }
            dimensions = { width, height };
            seen.add(chunkType);
            offset = chunkEnd;
            continue;
        }
        if (!dimensions) throw new Error('Image PNG header must be first');

        if (chunkType === 'IDAT') {
            if (endedIdat || (colorType === 3 && paletteEntries === 0)) {
                throw new Error('Invalid image PNG data ordering');
            }
            sawIdat = true;
            idatBytes += dataLength;
            if (!Number.isSafeInteger(idatBytes)) throw new Error('Invalid image PNG data size');
            offset = chunkEnd;
            continue;
        }
        if (sawIdat) endedIdat = true;

        if (chunkType === 'IEND') {
            if (seen.has(chunkType) || dataLength !== 0 || !sawIdat || idatBytes === 0 || chunkEnd !== bytes.length) {
                throw new Error('Invalid image PNG termination');
            }
            if (colorType === 3 && paletteEntries === 0) throw new Error('Image PNG palette is missing');
            return dimensions;
        }
        if (seen.has(chunkType)) throw new Error('Duplicate image PNG chunk');

        if (chunkType === 'PLTE') {
            if (sawIdat || colorType === 0 || colorType === 4 || dataLength === 0 || dataLength % 3 !== 0) {
                throw new Error('Invalid image PNG palette');
            }
            paletteEntries = dataLength / 3;
            if (paletteEntries > 256 || (colorType === 3 && paletteEntries > (1 << bitDepth))) {
                throw new Error('Invalid image PNG palette');
            }
        } else if (chunkType === 'tRNS') {
            const expectedLength = colorType === 0 ? 2 : colorType === 2 ? 6 : -1;
            if (
                sawIdat ||
                colorType === 4 || colorType === 6 ||
                (colorType === 3
                    ? paletteEntries === 0 || dataLength === 0 || dataLength > paletteEntries
                    : dataLength !== expectedLength)
            ) {
                throw new Error('Invalid image PNG transparency chunk');
            }
        } else if (chunkType === 'cHRM') {
            if (sawIdat || paletteEntries !== 0 || dataLength !== 32) throw new Error('Invalid image PNG color chunk');
        } else if (chunkType === 'gAMA') {
            if (sawIdat || paletteEntries !== 0 || dataLength !== 4) throw new Error('Invalid image PNG gamma chunk');
        } else if (chunkType === 'sBIT') {
            const expected = colorType === 0 ? 1 : colorType === 2 || colorType === 3 ? 3 : colorType === 4 ? 2 : 4;
            if (sawIdat || paletteEntries !== 0 || dataLength !== expected) throw new Error('Invalid image PNG significant-bits chunk');
        } else if (chunkType === 'sRGB') {
            if (sawIdat || paletteEntries !== 0 || dataLength !== 1 || bytes[dataOffset] > 3) {
                throw new Error('Invalid image PNG color-space chunk');
            }
        } else if (chunkType === 'pHYs') {
            if (sawIdat || dataLength !== 9 || bytes[dataOffset + 8] > 1) throw new Error('Invalid image PNG density chunk');
        } else if (chunkType === 'bKGD') {
            const expected = colorType === 0 || colorType === 4 ? 2 : colorType === 3 ? 1 : 6;
            if (
                sawIdat || dataLength !== expected ||
                (colorType === 3 && (paletteEntries === 0 || bytes[dataOffset] >= paletteEntries))
            ) {
                throw new Error('Invalid image PNG background chunk');
            }
        } else if (chunkType === 'hIST') {
            if (sawIdat || paletteEntries === 0 || dataLength !== paletteEntries * 2) {
                throw new Error('Invalid image PNG histogram chunk');
            }
        } else if (chunkType === 'tIME') {
            if (sawIdat || dataLength !== 7) throw new Error('Invalid image PNG time chunk');
        } else {
            throw new Error('Unsupported image PNG chunk');
        }

        seen.add(chunkType);
        offset = chunkEnd;
    }
    throw new Error('Image PNG is incomplete');
}

interface WebpChunk {
    type: string;
    dataOffset: number;
    dataLength: number;
}

function webpLossyDimensions(bytes: Uint8Array, chunk: WebpChunk): ImageDimensions {
    const offset = chunk.dataOffset;
    if (
        chunk.dataLength < 10 ||
        (bytes[offset] & 1) !== 0 ||
        !asciiMatchesAt(bytes, offset + 3, String.fromCharCode(0x9d, 0x01, 0x2a))
    ) {
        throw new Error('Invalid image WebP lossy frame');
    }
    return {
        width: (bytes[offset + 6] | (bytes[offset + 7] << 8)) & 0x3fff,
        height: (bytes[offset + 8] | (bytes[offset + 9] << 8)) & 0x3fff
    };
}

function webpLosslessDimensions(bytes: Uint8Array, chunk: WebpChunk): ImageDimensions {
    const offset = chunk.dataOffset;
    if (chunk.dataLength < 5 || bytes[offset] !== 0x2f || (bytes[offset + 4] & 0xe0) !== 0) {
        throw new Error('Invalid image WebP lossless frame');
    }
    return {
        width: 1 + ((bytes[offset + 1] | (bytes[offset + 2] << 8)) & 0x3fff),
        height: 1 + (((bytes[offset + 2] >> 6) | (bytes[offset + 3] << 2) | (bytes[offset + 4] << 10)) & 0x3fff)
    };
}

export function validateWebpContainer(bytes: Uint8Array, limits: ImageDimensionLimits): ImageDimensions {
    if (
        bytes.length < 30 ||
        !asciiMatchesAt(bytes, 0, 'RIFF') ||
        !asciiMatchesAt(bytes, 8, 'WEBP') ||
        readUint32LE(bytes, 4) + 8 !== bytes.length
    ) {
        throw new Error('Invalid image WebP container');
    }

    const chunks: WebpChunk[] = [];
    let offset = 12;
    while (offset + 8 <= bytes.length) {
        if (chunks.length >= MAX_WEBP_CHUNKS) throw new Error('Image WebP has too many chunks');
        const type = String.fromCharCode(bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]);
        const dataLength = readUint32LE(bytes, offset + 4);
        const dataOffset = offset + 8;
        const paddedLength = dataLength + (dataLength & 1);
        if (dataLength > bytes.length - dataOffset || paddedLength > bytes.length - dataOffset) {
            throw new Error('Invalid image WebP chunk length');
        }
        if ((dataLength & 1) !== 0 && bytes[dataOffset + dataLength] !== 0) {
            throw new Error('Invalid image WebP chunk padding');
        }
        chunks.push({ type, dataOffset, dataLength });
        offset = dataOffset + paddedLength;
    }
    if (offset !== bytes.length || chunks.length === 0) throw new Error('Invalid image WebP termination');

    let dimensions: ImageDimensions;
    if (chunks[0].type === 'VP8 ') {
        if (chunks.length !== 1) throw new Error('Unexpected image WebP chunks');
        dimensions = webpLossyDimensions(bytes, chunks[0]);
    } else if (chunks[0].type === 'VP8L') {
        if (chunks.length !== 1) throw new Error('Unexpected image WebP chunks');
        dimensions = webpLosslessDimensions(bytes, chunks[0]);
    } else if (chunks[0].type === 'VP8X') {
        const extended = chunks[0];
        if (
            extended.dataLength !== 10 ||
            (bytes[extended.dataOffset] & ~0x10) !== 0 ||
            bytes[extended.dataOffset + 1] !== 0 ||
            bytes[extended.dataOffset + 2] !== 0 ||
            bytes[extended.dataOffset + 3] !== 0
        ) {
            throw new Error('Invalid image WebP extended header');
        }
        dimensions = {
            width: readUint24LE(bytes, extended.dataOffset + 4) + 1,
            height: readUint24LE(bytes, extended.dataOffset + 7) + 1
        };
        const hasAlpha = (bytes[extended.dataOffset] & 0x10) !== 0;
        const imageChunk = chunks[hasAlpha ? 2 : 1];
        if (
            chunks.length !== (hasAlpha ? 3 : 2) ||
            (hasAlpha && (chunks[1].type !== 'ALPH' || chunks[1].dataLength < 1)) ||
            !imageChunk || imageChunk.type !== 'VP8 '
        ) {
            throw new Error('Invalid image WebP extended chunk sequence');
        }
        if (hasAlpha) {
            const alphaHeader = bytes[chunks[1].dataOffset];
            if ((alphaHeader & 0xc3) !== 0 || ((alphaHeader >>> 4) & 0x03) > 1) {
                throw new Error('Invalid image WebP alpha header');
            }
        }
        const encodedDimensions = webpLossyDimensions(bytes, imageChunk);
        if (
            encodedDimensions.width !== dimensions.width ||
            encodedDimensions.height !== dimensions.height
        ) {
            throw new Error('Conflicting image WebP dimensions');
        }
    } else {
        throw new Error('Unsupported image WebP encoding');
    }

    if (!dimensionsWithinLimits(dimensions, limits)) {
        throw new Error('Decoded image dimensions exceed limit');
    }
    return dimensions;
}
