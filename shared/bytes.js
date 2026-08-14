export function concatUint8Arrays(...arrays) {
  if (arrays.length === 0) return new Uint8Array(0);
  if (arrays.length === 1) return new Uint8Array(arrays[0]);
  const totalLength = arrays.reduce((sum, array) => sum + array.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const array of arrays) {
    result.set(array, offset);
    offset += array.length;
  }
  return result;
}

export function bytesToHex(bytes) {
  let output = '';
  for (const byte of bytes) output += byte.toString(16).padStart(2, '0');
  return output;
}

export function isHex(value, { exactBytes, allowUppercase = false } = {}) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 2 !== 0) return false;
  if (exactBytes !== undefined && value.length !== exactBytes * 2) return false;
  const pattern = allowUppercase ? /^[a-fA-F0-9]+$/ : /^[a-f0-9]+$/;
  return pattern.test(value);
}

export function hexToBytes(value, options) {
  if (!isHex(value, options)) return null;
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

export function constantTimeBytesEqual(left, right) {
  if (!left || !right || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

export function bytesMatchAt(bytes, offset, expected) {
  if (offset < 0 || offset + expected.length > bytes.length) return false;
  for (let index = 0; index < expected.length; index += 1) {
    if (bytes[offset + index] !== expected[index]) return false;
  }
  return true;
}

export function asciiMatchesAt(bytes, offset, expected) {
  if (offset < 0 || offset + expected.length > bytes.length) return false;
  for (let index = 0; index < expected.length; index += 1) {
    if (bytes[offset + index] !== expected.charCodeAt(index)) return false;
  }
  return true;
}

export function readUint32BE(bytes, offset) {
  return (
    ((bytes[offset] << 24) >>> 0) |
    (bytes[offset + 1] << 16) |
    (bytes[offset + 2] << 8) |
    bytes[offset + 3]
  ) >>> 0;
}
