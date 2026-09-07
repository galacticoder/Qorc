import fs from 'node:fs/promises';
import fsConstants from 'node:fs';
import path from 'node:path';

const MAX_PROCESS_ID = 2_147_483_647;
const PID_FILE_MAX_BYTES = 16;
const PID_FILE_OPEN_FLAGS = fsConstants.constants.O_RDONLY |
  fsConstants.constants.O_NOFOLLOW |
  fsConstants.constants.O_CLOEXEC;

export function parseStrictProcessId(value) {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,9}\n?$/.test(value)) return null;
  const pid = Number(value.trim());
  return Number.isSafeInteger(pid) && pid <= MAX_PROCESS_ID ? pid : null;
}

export async function readProcessIdFileSnapshot(pidFile) {
  if (typeof pidFile !== 'string' || !path.isAbsolute(pidFile)) {
    throw new Error('Process PID file path must be absolute');
  }

  let handle;
  try {
    handle = await fs.open(pidFile, PID_FILE_OPEN_FLAGS);
    const stat = await handle.stat();
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
    if (
      !stat.isFile() ||
      stat.nlink !== 1 ||
      (stat.mode & 0o022) !== 0 ||
      stat.size < 1 ||
      stat.size > PID_FILE_MAX_BYTES ||
      (currentUid !== null && stat.uid !== currentUid)
    ) {
      throw new Error('Process PID file is not a trusted regular file');
    }
    const contents = await handle.readFile({ encoding: 'utf8' });
    return Object.freeze({
      pid: parseStrictProcessId(contents),
      device: stat.dev,
      inode: stat.ino,
    });
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  } finally {
    await handle?.close().catch(() => {});
  }
}

export async function removeUnchangedProcessIdFile(pidFile, snapshot) {
  if (!snapshot) return false;
  try {
    const current = await fs.lstat(pidFile);
    if (current.dev !== snapshot.device || current.ino !== snapshot.inode) return false;
    await fs.unlink(pidFile);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return true;
    return false;
  }
}

export async function processMatchesExecutable(pid, expectedExecutable) {
  if (
    !Number.isSafeInteger(pid) ||
    pid < 1 ||
    pid > MAX_PROCESS_ID ||
    typeof expectedExecutable !== 'string' ||
    !path.isAbsolute(expectedExecutable)
  ) return false;

  try {
    process.kill(pid, 0);
  } catch {
    return false;
  }

  if (process.platform !== 'linux') return false;
  try {
    const [runningExecutable, expected] = await Promise.all([
      fs.realpath(`/proc/${pid}/exe`),
      fs.realpath(expectedExecutable),
    ]);
    return path.resolve(runningExecutable) === path.resolve(expected);
  } catch {
    return false;
  }
}

export async function processMatchesNodeScript(pid, expectedScript) {
  if (
    typeof expectedScript !== 'string' ||
    !path.isAbsolute(expectedScript) ||
    !await processMatchesExecutable(pid, process.execPath)
  ) return false;

  try {
    const [commandLine, processDirectory, expected] = await Promise.all([
      fs.readFile(`/proc/${pid}/cmdline`),
      fs.realpath(`/proc/${pid}/cwd`),
      fs.realpath(expectedScript),
    ]);
    if (commandLine.length < 1 || commandLine.length > 64 * 1024) return false;
    const arguments_ = commandLine.toString('utf8').split('\0').filter(Boolean).slice(1);
    for (const argument of arguments_) {
      if (!argument || argument.startsWith('-') || argument.includes('\0')) continue;
      const candidate = path.isAbsolute(argument)
        ? argument
        : path.resolve(processDirectory, argument);
      try {
        if (path.resolve(await fs.realpath(candidate)) === path.resolve(expected)) return true;
      } catch { }
    }
    return false;
  } catch {
    return false;
  }
}
