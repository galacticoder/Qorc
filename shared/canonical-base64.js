function base64Sextet(charCode) {
  if (charCode >= 65 && charCode <= 90) return charCode - 65;
  if (charCode >= 97 && charCode <= 122) return charCode - 71;
  if (charCode >= 48 && charCode <= 57) return charCode + 4;
  if (charCode === 43) return 62;
  if (charCode === 47) return 63;
  return -1;
}

export function canonicalBase64Shape(value, { exactBytes, minBytes = 1, maxBytes } = {}) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0) return false;
  const byteLimit = exactBytes ?? maxBytes;
  if (byteLimit !== undefined && value.length > 4 * Math.ceil(byteLimit / 3)) return false;
  const finalCode = value.charCodeAt(value.length - 1);
  const penultimateCode = value.charCodeAt(value.length - 2);
  const padding = finalCode === 61 ? (penultimateCode === 61 ? 2 : 1) : 0;
  const decodedBytes = (value.length / 4) * 3 - padding;
  if (exactBytes !== undefined && decodedBytes !== exactBytes) return false;
  if (decodedBytes < minBytes || (maxBytes !== undefined && decodedBytes > maxBytes)) return false;
  const dataEnd = value.length - padding;
  for (let index = 0; index < dataEnd; index += 1) {
    if (base64Sextet(value.charCodeAt(index)) < 0) return false;
  }
  for (let index = dataEnd; index < value.length; index += 1) {
    if (value.charCodeAt(index) !== 61) return false;
  }
  if (padding === 2) {
    const sextet = base64Sextet(value.charCodeAt(value.length - 3));
    if (sextet < 0 || (sextet & 0x0f) !== 0) return false;
  } else if (padding === 1) {
    const sextet = base64Sextet(value.charCodeAt(value.length - 2));
    if (sextet < 0 || (sextet & 0x03) !== 0) return false;
  }
  return true;
}
