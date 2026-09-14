import { WS_CONTROL_SEND_TIMEOUT_MS } from '../constants';

export interface PreparedDiscoveryPublication {
  requestId: string;
  publication: { epochId: string; publishId: string; bucketIds: number[] };
  encryptedBlob: string;
  powNonce: string;
  powSolution: string;
  inputFingerprint: string;
  contextFingerprint: string;
  fingerprint: string;
  publicKey: string;
  connectionEpoch: number;
  avatarStateVersion: number;
  expiresAt: number;
}

export function canReuseDiscoveryPublication(
  prepared: PreparedDiscoveryPublication | null,
  current: {
    inputFingerprint: string | null;
    epochId: string;
    publicKey: string;
    connectionEpoch: number | null;
    avatarStateVersion: number;
  },
  now = Date.now(),
): prepared is PreparedDiscoveryPublication {
  return prepared !== null &&
    current.connectionEpoch !== null &&
    prepared.connectionEpoch === current.connectionEpoch &&
    prepared.publication.epochId === current.epochId &&
    prepared.publicKey === current.publicKey &&
    prepared.inputFingerprint === current.inputFingerprint &&
    prepared.avatarStateVersion === current.avatarStateVersion &&
    prepared.expiresAt > now + WS_CONTROL_SEND_TIMEOUT_MS;
}

export function canRetryPreparedPublication(error: string): boolean {
  return error === 'publish-send-timeout' ||
    error === 'publish-response-timeout' ||
    error === 'publish-send-failed';
}
