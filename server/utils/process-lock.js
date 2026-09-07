import fsConstants from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';

import { parseStrictProcessId, processMatchesNodeScript } from './process-identity.js';

const LOCK_FILE_MAX_BYTES = 16;
const LOCK_OPEN_FLAGS = fsConstants.constants.O_RDONLY |
  fsConstants.constants.O_NOFOLLOW |
  fsConstants.constants.O_CLOEXEC;
const LOCK_CREATE_FLAGS = fsConstants.constants.O_WRONLY |
  fsConstants.constants.O_CREAT |
  fsConstants.constants.O_EXCL |
  fsConstants.constants.O_NOFOLLOW |
  fsConstants.constants.O_CLOEXEC;

function validLockStat(stat) {
  const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
  return stat.isFile() &&
    stat.nlink === 1 &&
    (stat.mode & 0o022) === 0 &&
    stat.size >= 1 &&
    stat.size <= LOCK_FILE_MAX_BYTES &&
    (currentUid === null || stat.uid === currentUid);
}

async function readLockSnapshot(lockPath) {
  let handle;
  try {
    handle = await fs.open(lockPath, LOCK_OPEN_FLAGS);
    const stat = await handle.stat();
    if (!validLockStat(stat)) return { pid: null, stat };
    const contents = await handle.readFile({ encoding: 'utf8' });
    return { pid: parseStrictProcessId(contents), stat };
  } catch {
    return null;
  } finally {
    await handle?.close().catch(() => { });
  }
}

async function removeUnchangedLock(lockPath, snapshot) {
  if (!snapshot?.stat) return false;
  try {
    const current = await fs.lstat(lockPath);
    if (current.dev !== snapshot.stat.dev || current.ino !== snapshot.stat.ino) return false;
    await fs.unlink(lockPath);
    return true;
  } catch {
    return false;
  }
}

async function createLock(lockPath) {
  let handle;
  let complete = false;
  try {
    handle = await fs.open(lockPath, LOCK_CREATE_FLAGS, 0o600);
    await handle.writeFile(`${process.pid}\n`, { encoding: 'utf8' });
    await handle.sync();
    complete = true;
  } finally {
    await handle?.close().catch(() => { });
    if (handle && !complete) {
      try { await fs.unlink(lockPath); } catch { }
    }
  }
}

export async function acquireProcessLock(lockPath, expectedScript) {
  if (
    typeof lockPath !== 'string' ||
    !path.isAbsolute(lockPath) ||
    typeof expectedScript !== 'string' ||
    !path.isAbsolute(expectedScript)
  ) throw new Error('Process lock paths must be absolute');

  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      await createLock(lockPath);
      return { acquired: true, pid: process.pid };
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
    }

    const snapshot = await readLockSnapshot(lockPath);
    if (
      snapshot?.pid &&
      await processMatchesNodeScript(snapshot.pid, expectedScript)
    ) return { acquired: false, pid: snapshot.pid };

    if (snapshot && !await removeUnchangedLock(lockPath, snapshot)) continue;
    if (!snapshot) {
      try {
        const stat = await fs.lstat(lockPath);
        if (stat.isSymbolicLink()) await fs.unlink(lockPath);
      } catch { }
    }
  }
  throw new Error('Process lock changed repeatedly during acquisition');
}

export async function releaseProcessLock(lockPath) {
  const snapshot = await readLockSnapshot(lockPath);
  if (!snapshot || snapshot.pid !== process.pid) return false;
  return removeUnchangedLock(lockPath, snapshot);
}
