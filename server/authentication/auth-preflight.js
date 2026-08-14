import { verifyPowSolution } from '../security/auth-throttle.js';

const AUTH_PREFLIGHT_TTL_MS = 60_000;
const LOGIN_AUTH_PREFLIGHT_TTL_MS = 5 * 60_000;

export function authPreflightTtlMs(kind) {
  return kind === 'login'
    ? LOGIN_AUTH_PREFLIGHT_TTL_MS
    : AUTH_PREFLIGHT_TTL_MS;
}

export function isAuthPreflightLive(pending, now = Date.now()) {
  const ageMs = now - Number(pending?.createdAt);
  return Number.isSafeInteger(ageMs) &&
    ageMs >= 0 &&
    ageMs <= authPreflightTtlMs(pending?.kind);
}

export function verifyAuthPreflightProof(
  pending,
  { kind, authRequestId, commitment, solution },
  now = Date.now()
) {
  return Boolean(
    pending?.kind === kind &&
    pending.authRequestId === authRequestId &&
    pending.commitment === commitment &&
    isAuthPreflightLive(pending, now) &&
    verifyPowSolution(pending.seed, pending.difficulty, solution)
  );
}
