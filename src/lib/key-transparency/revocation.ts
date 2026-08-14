import { signal } from '../tauri-bindings';
import { canonicalAuthUsername } from '../sanitizers';
import { keyTransparencyPeerKey } from './peer-key';

const MAX_REVOCATION_STATES = 2048;

type RevocationState = {
  complete: boolean;
  failed: boolean;
  promise: Promise<void>;
};

const revocations = new Map<string, RevocationState>();

function revocationKey(account: string, peer: string): string {
  return keyTransparencyPeerKey(
    canonicalAuthUsername(account, 'key-transparency revocation account'),
    canonicalAuthUsername(peer, 'key-transparency revocation peer')
  );
}

export function beginPeerIdentityRevocation(account: string, peer: string): Promise<void> {
  const key = revocationKey(account, peer);
  const existing = revocations.get(key);
  if (existing && !existing.failed) return existing.promise;

  let state!: RevocationState;
  const promise = signal.revokeTransparencyPeerIdentity(account, peer)
    .then((revoked) => {
      if (!revoked) throw new Error('Native Signal peer-identity revocation was rejected');
      if (revocations.get(key) === state) state.complete = true;
    })
    .catch((error) => {
      if (revocations.get(key) === state) state.failed = true;
      throw error;
    });
  state = { complete: false, failed: false, promise };
  revocations.delete(key);
  revocations.set(key, state);
  while (revocations.size > MAX_REVOCATION_STATES) {
    const oldest = revocations.keys().next().value as string | undefined;
    if (!oldest) break;
    revocations.delete(oldest);
  }
  void promise.catch(() => undefined);
  return promise;
}

export async function awaitPeerIdentityRevocation(account: string, peer: string): Promise<boolean> {
  let state: RevocationState | undefined;
  try {
    state = revocations.get(revocationKey(account, peer));
  } catch {
    return false;
  }
  if (!state) return false;
  try {
    await state.promise;
  } catch {
    return false;
  }
  return state.complete && !state.failed;
}

export function consumeCompletedPeerIdentityRevocation(account: string, peer: string): boolean {
  let key: string;
  try {
    key = revocationKey(account, peer);
  } catch {
    return false;
  }
  const state = revocations.get(key);
  if (!state?.complete || state.failed) return false;
  revocations.delete(key);
  return true;
}

export function clearPeerIdentityRevocations(): void {
  revocations.clear();
}
