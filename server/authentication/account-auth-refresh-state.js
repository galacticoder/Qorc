const REFRESH_STATE_PROPERTY = '_accountAuthRefreshState';

export const AccountAuthRefreshDecision = Object.freeze({
  ISSUE: 'issue',
  IN_PROGRESS: 'in-progress',
  REPLAY: 'replay',
  CONFLICT: 'conflict',
});

export function hasLiveAccountAuthRefreshAuthorization(ws) {
  return ws?._accountAuthViaAnonymousToken === true &&
    ws?._authenticated === true;
}

export function reserveAccountAuthRefresh(ws, commitment) {
  if (!ws || typeof commitment !== 'string' || commitment.length === 0) {
    throw new TypeError('Invalid account-auth refresh reservation');
  }

  const existing = ws[REFRESH_STATE_PROPERTY];
  if (!existing) {
    ws[REFRESH_STATE_PROPERTY] = Object.freeze({
      commitment,
      response: null,
    });
    return Object.freeze({ decision: AccountAuthRefreshDecision.ISSUE });
  }
  if (existing.commitment !== commitment) {
    return Object.freeze({ decision: AccountAuthRefreshDecision.CONFLICT });
  }
  if (!existing.response) {
    return Object.freeze({ decision: AccountAuthRefreshDecision.IN_PROGRESS });
  }
  return Object.freeze({
    decision: AccountAuthRefreshDecision.REPLAY,
    response: existing.response,
  });
}

export function completeAccountAuthRefresh(ws, commitment, response) {
  const existing = ws?.[REFRESH_STATE_PROPERTY];
  if (
    !existing ||
    existing.commitment !== commitment ||
    existing.response ||
    !response ||
    typeof response !== 'object'
  ) {
    return false;
  }
  const cachedResponse = {
    ...response,
    ...(Array.isArray(response.signedBlindedTokens)
      ? { signedBlindedTokens: Object.freeze([...response.signedBlindedTokens]) }
      : {}),
  };
  ws[REFRESH_STATE_PROPERTY] = Object.freeze({
    commitment,
    response: Object.freeze(cachedResponse),
  });
  return true;
}

export function releaseFailedAccountAuthRefresh(ws, commitment) {
  const existing = ws?.[REFRESH_STATE_PROPERTY];
  if (!existing || existing.commitment !== commitment || existing.response) {
    return false;
  }
  delete ws[REFRESH_STATE_PROPERTY];
  return true;
}

export function clearAccountAuthRefreshState(ws) {
  if (!ws) return;
  delete ws[REFRESH_STATE_PROPERTY];
}
