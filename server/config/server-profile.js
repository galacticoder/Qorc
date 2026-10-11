import { constants, openSync, closeSync, fstatSync, readSync } from 'node:fs';
import { resolve } from 'node:path';
import sharp from 'sharp';
import { SERVER_ICON_MAX_BYTES, SERVER_ICON_MAX_DIMENSION, SERVER_NAME_MAX_LENGTH, validateServerIcon, validateServerProfile } from '../../shared/server-profile.js';
import { validatePngContainer } from '../../shared/image-png.js';

export const SERVER_ICON_SOURCE_MAX_BYTES = 4 * 1024 * 1024;
export const SERVER_ICON_SOURCE_MAX_DIMENSION = 8192;
export const SERVER_ICON_SOURCE_MAX_PIXELS = 16 * 1024 * 1024;
const SERVER_ICON_ENCODING_TIMEOUT_MS = 10_000;

async function prepareServerIcon(bytes) {
  const metadata = [];
  validatePngContainer(bytes, {
    maxWidth: SERVER_ICON_SOURCE_MAX_DIMENSION,
    maxHeight: SERVER_ICON_SOURCE_MAX_DIMENSION,
    maxPixels: SERVER_ICON_SOURCE_MAX_PIXELS,
  }, (start, end) => metadata.push({ start, end }));
  if (metadata.length) {
    const chunks = [];
    let offset = 0;
    for (const { start, end } of metadata) {
      chunks.push(bytes.subarray(offset, start));
      offset = end;
    }
    chunks.push(bytes.subarray(offset));
    bytes = Buffer.concat(chunks);
  }
  const original = `data:image/png;base64,${bytes.toString('base64')}`;
  if (validateServerIcon(original)) return original;
  const deadline = performance.now() + SERVER_ICON_ENCODING_TIMEOUT_MS;
  for (let dimension = SERVER_ICON_MAX_DIMENSION; dimension >= 16; dimension = Math.floor(dimension * 0.75)) {
    const remaining = deadline - performance.now();
    if (remaining <= 0) throw new Error('Server icon compression deadline exceeded');
    const encoded = await sharp(bytes, {
      failOn: 'warning',
      limitInputPixels: SERVER_ICON_SOURCE_MAX_PIXELS,
      limitInputChannels: 4,
    })
      .resize({ width: dimension, height: dimension, fit: 'inside', withoutEnlargement: true })
      .png({ compressionLevel: 9, adaptiveFiltering: true, palette: true, colours: 256, dither: 0.5 })
      .timeout({ seconds: Math.max(1, Math.ceil(remaining / 1000)) })
      .toBuffer();
    if (encoded.length <= SERVER_ICON_MAX_BYTES) {
      const icon = `data:image/png;base64,${encoded.toString('base64')}`;
      if (!validateServerIcon(icon)) throw new Error('Compressed server icon failed validation');
      return icon;
    }
  }
  throw new Error('Server icon could not be compressed within the image size limit');
}

export async function loadServerProfile(serverId) {
  const profile = { name: process.env.SERVER_NAME?.trim() || serverId, icon: null };
  if (process.env.SERVER_ICON_PATH) {
    const iconPath = resolve(process.env.SERVER_ICON_PATH);
    const descriptor = openSync(iconPath, constants.O_RDONLY | constants.O_NONBLOCK);
    try {
      const stat = fstatSync(descriptor);
      if (!stat.isFile() || stat.size > SERVER_ICON_SOURCE_MAX_BYTES) {
        throw new Error(`SERVER_ICON_PATH must be a regular PNG file no larger than ${SERVER_ICON_SOURCE_MAX_BYTES} bytes`);
      }
      const bytes = Buffer.alloc(SERVER_ICON_SOURCE_MAX_BYTES + 1);
      let length = 0;
      while (length < bytes.length) {
        const count = readSync(descriptor, bytes, length, bytes.length - length, null);
        if (count === 0) break;
        length += count;
      }
      if (length > SERVER_ICON_SOURCE_MAX_BYTES) throw new Error('SERVER_ICON_PATH exceeds the source image size limit');
      profile.icon = await prepareServerIcon(bytes.subarray(0, length));
    } finally {
      closeSync(descriptor);
    }
  }
  if (!validateServerProfile(profile)) {
    throw new Error(`Invalid server profile: use a name of 1–${SERVER_NAME_MAX_LENGTH} characters and a static PNG icon up to ${SERVER_ICON_MAX_DIMENSION}×${SERVER_ICON_MAX_DIMENSION} and ${SERVER_ICON_MAX_BYTES} bytes`);
  }
  return Object.freeze(profile);
}
