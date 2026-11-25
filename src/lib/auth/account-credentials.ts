import {
  AUTH_USERNAME_REGEX,
  ACCOUNT_CREDENTIALS_IS_VALID_ACCOUNT_CREDENTIAL_VALUE_LENGTH_LIMIT,
} from '../constants';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

export function isValidAccountCredential(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > ACCOUNT_CREDENTIALS_IS_VALID_ACCOUNT_CREDENTIAL_VALUE_LENGTH_LIMIT) return false;
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit === 0) return false;
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++index);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

export function encodeAccountAuthSecret(username: string, password: string, passphrase: string): Uint8Array {
  if (
    !AUTH_USERNAME_REGEX.test(username) ||
    !isValidAccountCredential(password) ||
    !isValidAccountCredential(passphrase)
  ) throw new Error('Invalid authentication secret');
  const encoder = new TextEncoder();
  const fields = [
    encoder.encode(username),
    encoder.encode(password),
    encoder.encode(passphrase),
  ];
  const domain = encoder.encode(PROTOCOL_KEYS.ACCOUNT_AUTH_SECRET);
  try {
    const data = new Uint8Array(domain.length + 12 + fields.reduce((size, field) => size + field.length, 0));
    data.set(domain, 0);
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    let offset = domain.length;
    for (const field of fields) {
      view.setUint32(offset, field.length, false);
      offset += 4;
      data.set(field, offset);
      offset += field.length;
    }
    return data;
  } finally {
    domain.fill(0);
    for (const field of fields) field.fill(0);
  }
}
