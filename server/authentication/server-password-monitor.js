import fs from 'node:fs';
import path from 'node:path';

const MAX_ENV_FILE_BYTES = 1024 * 1024;
const DEFAULT_POLL_INTERVAL_MS = 1000;

function parseBoolean(value) {
  return /^(?:1|true|yes)$/i.test(typeof value === 'string' ? value.trim() : '');
}

function parseEnvironmentFile(text) {
  const values = new Map();
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator < 1) continue;
    const key = line.slice(0, separator).trim();
    if (key !== 'SERVER_PASSWORD' && key !== 'DISCONNECT_CLIENTS_ON_SERVER_PASSWORD_CHANGE') {
      continue;
    }
    if (values.has(key)) {
      throw new Error(`Duplicate ${key} entry in the environment file`);
    }
    let value = line.slice(separator + 1).trim();
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1);
    }
    values.set(key, value);
  }
  return values;
}

function passwordConfigurationRevision(stat) {
  return [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs].map(String).join(':');
}

function readServerPasswordConfigurationSnapshot(envPath) {
  if (typeof envPath !== 'string' || !path.isAbsolute(envPath)) {
    throw new Error('Server environment file path must be absolute');
  }
  const openFlags = fs.constants.O_RDONLY |
    (fs.constants.O_CLOEXEC ?? 0) |
    fs.constants.O_NOFOLLOW;
  let descriptor;
  let before;
  let text;
  let revision = null;
  try {
    descriptor = fs.openSync(envPath, openFlags);
    before = fs.fstatSync(descriptor, { bigint: true });
    revision = passwordConfigurationRevision(before);
    if (
      !before.isFile() ||
      before.nlink !== 1n ||
      (before.mode & 0o077n) !== 0n ||
      before.size > BigInt(MAX_ENV_FILE_BYTES)
    ) {
      throw new Error('Server environment file is not a private regular file');
    }
    text = fs.readFileSync(descriptor, 'utf8');
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (
      after.dev !== before.dev ||
      after.ino !== before.ino ||
      after.size !== before.size ||
      after.mtimeNs !== before.mtimeNs ||
      after.ctimeNs !== before.ctimeNs
    ) {
      throw new Error('Server environment file changed while it was being read');
    }
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  try {
    const values = parseEnvironmentFile(text);
    const password = (values.get('SERVER_PASSWORD') || '').trim();
    if (password.length < 12 || password.length > 512) {
      throw new Error('SERVER_PASSWORD must contain between 12 and 512 characters');
    }
    return {
      configuration: {
        password,
        disconnectClients: parseBoolean(values.get('DISCONNECT_CLIENTS_ON_SERVER_PASSWORD_CHANGE')),
      },
      revision,
    };
  } catch (error) {
    if (error && typeof error === 'object') error.fileRevision = revision;
    throw error;
  }
}

export function readServerPasswordConfiguration(envPath) {
  return readServerPasswordConfigurationSnapshot(envPath).configuration;
}

export async function startServerPasswordMonitor({
  envPath = path.resolve(process.cwd(), '.env'),
  intervalMs = DEFAULT_POLL_INTERVAL_MS,
  rotatePassword,
  onPasswordRotated,
  logger = console,
} = {}) {
  if (typeof rotatePassword !== 'function') {
    throw new Error('Server password monitor requires a rotation handler');
  }
  if (typeof onPasswordRotated !== 'function') {
    throw new Error('Server password monitor requires a rotation follow-up handler');
  }

  let stopped = false;
  let operationTail = Promise.resolve();
  let reloadScheduled = false;
  let acceptedRevision = null;
  let rejectedRevision = null;
  const applyCurrentConfiguration = async () => {
    if (stopped) return;
    let snapshot;
    try {
      snapshot = readServerPasswordConfigurationSnapshot(envPath);
    } catch (error) {
      if (acceptedRevision === null) throw error;
      if (error?.fileRevision && error.fileRevision === rejectedRevision) return;
      rejectedRevision = error?.fileRevision || null;
      logger.error('[SERVER] Password configuration reload rejected', {
        error: error instanceof Error ? error.message : String(error),
      });
      return;
    }
    if (snapshot.revision === acceptedRevision || snapshot.revision === rejectedRevision) return;

    let changed;
    try {
      changed = await rotatePassword(snapshot.configuration.password);
    } catch (error) {
      logger.error('[SERVER] Password rotation failed; previous credential remains active', {
        error: error instanceof Error ? error.message : String(error),
      });
      return;
    }
    acceptedRevision = snapshot.revision;
    rejectedRevision = null;
    if (!changed || stopped) return;
    logger.info('[SERVER] Server password and entry-token issuer rotated');
    try {
      await onPasswordRotated({
        disconnectClients: snapshot.configuration.disconnectClients,
      });
    } catch (error) {
      logger.error('[SERVER] Password rotation follow-up failed', {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  };

  const scheduleReload = () => {
    if (stopped || reloadScheduled) return operationTail;
    reloadScheduled = true;
    operationTail = operationTail
      .catch(() => { })
      .then(applyCurrentConfiguration)
      .finally(() => {
        reloadScheduled = false;
      });
    return operationTail;
  };

  await scheduleReload();
  const pollTimer = setInterval(
    () => { void scheduleReload(); },
    Math.max(20, Number(intervalMs) || DEFAULT_POLL_INTERVAL_MS),
  );
  pollTimer.unref?.();

  return {
    async stop() {
      if (stopped) return;
      stopped = true;
      clearInterval(pollTimer);
      await operationTail.catch(() => { });
    },
  };
}
