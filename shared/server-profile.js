import { canonicalBase64Shape } from './canonical-base64.js';
import { validatePngContainer } from './image-png.js';
import { SERVER_PROFILE_SIGNATURE_CONTEXT } from './protocol-keys.js';
import { ML_DSA_87_PUBLIC_KEY_BYTES, ML_KEM_1024_PUBLIC_KEY_BYTES } from './crypto-sizes.js';

export const SERVER_ICON_MAX_BYTES = 8192;
export const SERVER_ICON_MAX_DIMENSION = 128;
export const SERVER_NAME_MAX_LENGTH = 80;

export function validateServerIcon(icon) {
  if (icon === null) return true;
  if (typeof icon !== 'string' || !icon.startsWith('data:image/png;base64,')) return false;
  const encoded = icon.slice('data:image/png;base64,'.length);
  if (!canonicalBase64Shape(encoded, { minBytes: 57, maxBytes: SERVER_ICON_MAX_BYTES })) return false;
  const decoded = Uint8Array.from(atob(encoded), (character) => character.charCodeAt(0));
  try {
    validatePngContainer(decoded, {
      maxWidth: SERVER_ICON_MAX_DIMENSION,
      maxHeight: SERVER_ICON_MAX_DIMENSION,
      maxPixels: SERVER_ICON_MAX_DIMENSION * SERVER_ICON_MAX_DIMENSION,
    });
    return true;
  } catch {
    return false;
  }
}

export function validateServerProfile(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join(',') === 'icon,name' &&
    typeof value.name === 'string' && value.name === value.name.trim() &&
    value.name.length > 0 && value.name.length <= SERVER_NAME_MAX_LENGTH &&
    !/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u.test(value.name) &&
    validateServerIcon(value.icon);
}

export function encodeServerProfileTranscript({ serverId, hybridKeys, serverProfile }) {
  if (typeof serverId !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(serverId) ||
    !validateServerProfile(serverProfile) || !hybridKeys ||
    !canonicalBase64Shape(hybridKeys.kyberPublicBase64, { exactBytes: ML_KEM_1024_PUBLIC_KEY_BYTES }) ||
    !canonicalBase64Shape(hybridKeys.dilithiumPublicBase64, { exactBytes: ML_DSA_87_PUBLIC_KEY_BYTES }) ||
    !canonicalBase64Shape(hybridKeys.x25519PublicBase64, { exactBytes: 32 })) {
    throw new Error('Invalid server profile transcript');
  }
  return new TextEncoder().encode(JSON.stringify([
    SERVER_PROFILE_SIGNATURE_CONTEXT,
    serverId,
    hybridKeys.kyberPublicBase64,
    hybridKeys.dilithiumPublicBase64,
    hybridKeys.x25519PublicBase64,
    serverProfile.name,
    serverProfile.icon,
  ]));
}
