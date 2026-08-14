import type { AnonymousToken } from './privacy-pass-client';
import type { HandshakeMessage } from '../types/noise-types';
import { isPlainObject } from '../sanitizers';

export function wipeAnonymousToken(token: AnonymousToken | null | undefined): void {
  if (!token) return;
  token.tokenSecret?.fill(0);
  token.blindingFactor?.fill(0);
  token.blindedElement?.fill(0);
  token.unblindedToken?.fill(0);
}

export function wipeAnonymousTokens(tokens: readonly AnonymousToken[]): void {
  for (const token of tokens) wipeAnonymousToken(token);
}

export function wipeBinaryValues(root: unknown): void {
  const stack: unknown[] = [root];
  const seen = new WeakSet<object>();
  while (stack.length > 0) {
    const value = stack.pop();
    if (value instanceof Uint8Array) {
      value.fill(0);
      continue;
    }
    if (!value || typeof value !== 'object' || seen.has(value)) continue;
    seen.add(value);
    if (Array.isArray(value)) {
      for (const entry of value) stack.push(entry);
    } else if (isPlainObject(value)) {
      for (const entry of Object.values(value)) stack.push(entry);
    }
  }
}

export function wipeHandshakeBytes(message: HandshakeMessage): void {
  message.ephemeralKyberPublic?.fill(0);
  message.kemCiphertext.fill(0);
  message.ephemeralX25519Public.fill(0);
  message.signature.fill(0);
  message.signerPublicKey.fill(0);
}
