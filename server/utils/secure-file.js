import fs from 'node:fs';
import path from 'node:path';

const DEFAULT_MAX_BYTES = 1024 * 1024;

export function readSecureRegularFile(filePath, {
  maxBytes = DEFAULT_MAX_BYTES,
  privateFile = false,
  label = 'Secure file',
} = {}) {
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath)) {
    throw new Error(`${label} path must be absolute`);
  }
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new Error(`${label} maximum size is invalid`);
  }

  const openFlags = fs.constants.O_RDONLY |
    (fs.constants.O_CLOEXEC ?? 0) |
    (fs.constants.O_NOFOLLOW ?? 0);
  let descriptor;
  let contents;
  try {
    descriptor = fs.openSync(filePath, openFlags);
    const before = fs.fstatSync(descriptor, { bigint: true });
    const forbiddenMode = privateFile ? 0o077n : 0o022n;
    if (
      !before.isFile() ||
      before.nlink !== 1n ||
      before.size < 1n ||
      before.size > BigInt(maxBytes) ||
      (before.mode & forbiddenMode) !== 0n
    ) {
      throw new Error(privateFile
        ? `${label} must be a private regular file`
        : `${label} must be a non-writable regular file`);
    }

    contents = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (
      after.dev !== before.dev ||
      after.ino !== before.ino ||
      after.size !== before.size ||
      after.mtimeNs !== before.mtimeNs ||
      after.ctimeNs !== before.ctimeNs
    ) {
      throw new Error(`${label} changed while it was being read`);
    }
    return contents;
  } catch (error) {
    contents?.fill(0);
    throw error;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

export function readSecureTlsFile(filePath, { privateKey = false } = {}) {
  return readSecureRegularFile(filePath, {
    privateFile: privateKey,
    label: privateKey ? 'TLS private key' : 'TLS certificate',
  });
}
