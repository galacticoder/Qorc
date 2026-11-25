import { PROTOCOL_KEYS } from '../config/protocol-keys';

import { KEY_TRANSPARENCY_MAX_LOG_SIZE } from '../../../shared/key-transparency-protocol.js';

export const KEY_TRANSPARENCY_MAX_PREFIX_CACHE_CONTACTS = 16;
export const MAX_CACHED_TRANSITIONS = 4096;
export const KEY_TRANSPARENCY_CHUNK_EPOCHS = 720;
export const KEY_TRANSPARENCY_MAX_RECORDS_PER_CHUNK = 65_536;
export const KEY_TRANSPARENCY_MAX_RECORD_CHUNKS = Math.ceil(KEY_TRANSPARENCY_MAX_LOG_SIZE / 1024);
export const KEY_TRANSPARENCY_MAX_TRANSITION_CHARS = 64 * 1024;
export const KEY_TRANSPARENCY_MAX_WARNINGS = 2048;
export const MAX_MONITORED_CONTACTS = 2048;
export const MAX_REVOCATION_STATES = 2048;
export const MAX_AUTHORIZED_PEERS = 2048;
export const MAX_STORED_AUTHORIZATIONS = 2048;

export const MAX_SYNC_ROUNDS = 64;
export const GOSSIP_AUDIT_ATTEMPTS = 3;
export const GOSSIP_AUDIT_RETRY_MS = 15_000;
export const GOSSIP_DEFERRED_RETRY_MS = 60_000;
export const MAX_PENDING_GOSSIP_HEADS = 64;
export const MAX_AUDITED_GOSSIP_HEADS = 256;

export const CONTACT_MONITOR_SWEEP_MS = 24 * 60 * 60 * 1000;
export const CONTACT_MONITOR_MIN_INTERVAL_MS = 60_000;
export const CONTACT_MONITOR_MAX_INTERVAL_MS = 30 * 60 * 1000;
export const CONTACT_MONITOR_RETRY_MS = 5 * 60 * 1000;
export const COVER_MONITOR_MIN_INTERVAL_MS = 10 * 60 * 1000;
export const COVER_MONITOR_JITTER_MS = 20 * 60 * 1000;

export const LABEL_DOMAIN = new TextEncoder().encode(PROTOCOL_KEYS.KEY_TRANSPARENCY_LABEL);
export const EPOCH_LABEL_DOMAIN = new TextEncoder().encode(PROTOCOL_KEYS.KEY_TRANSPARENCY_EPOCH_LABEL);
export const KEY_COMMITMENT_DOMAIN = new TextEncoder().encode(PROTOCOL_KEYS.KEY_TRANSPARENCY_KEY_COMMITMENT);
export const SIGNER_KEY_ID_DOMAIN = new TextEncoder().encode(PROTOCOL_KEYS.KEY_TRANSPARENCY_SIGNER_KEY);
export const SIGNED_UPDATE_KEYS = [
  'kind',
  'label',
  'pendingRootCommitment',
  'previousRootCommitment',
  'protocol',
  'recoveryActivatesAt',
  'recoveryCommitment',
  'recoveryRequestEpoch',
  'rootCommitment',
  'version',
];
export const KEY_TRANSPARENCY_UPDATE_AUTHORIZATION_KEYS = [
  'previousRootPublicKey',
  'previousRootSignature',
  'recoveryPublicKey',
  'recoverySignature',
  'rootPublicKey',
  'rootSignature',
];
export const KEY_TRANSPARENCY_HEAD_KEYS = ['entryCount', 'epoch', 'genesisEpoch', 'protocol', 'rootHash', 'signature', 'signerKeyId'];
export const KEY_TRANSPARENCY_SYNC_KEYS = [
  'currentEpoch',
  'firstLogIndex',
  'fromEpoch',
  'head',
  'protocol',
  'records',
  'toEpoch',
];
export const KEY_TRANSPARENCY_RECORD_ENTRY_KEYS = ['epoch', 'epochLabel', 'recordHash', 'version'];
export const VERIFIED_LOG_SCOPE = 'verified-log-v2';
export const KEY_TRANSPARENCY_WARNING_KEYS = [
  'activatesAtEpoch',
  'label',
  'peer',
  'pendingRootCommitment',
  'version',
];
export const KEY_TRANSPARENCY_MONITOR_ENTRY_KEYS = ['discoveryKey', 'label', 'lastCheckedAt', 'peer', 'rootCommitment', 'version'];
export const VERIFIED_AUTHORIZATION_PROTOCOL = `${PROTOCOL_KEYS.KEY_TRANSPARENCY_AUTHORIZATION_STORE}-v2`;
export const AUTHORIZED_KEYS = [
  'dilithiumPublicBase64',
  'identityBundleFingerprint',
  'identityRootFingerprint',
  'kyberPublicBase64',
  'peer',
  'peerCertificateFingerprint',
  'rootCommitment',
  'verifiedAt',
  'version',
  'x25519PublicBase64',
];
export const REVOKED_KEYS = ['peer', 'rootCommitment', 'version'];
export const KEY_TRANSPARENCY_GOSSIP_HEAD_KEYS = ['entryCount', 'epoch', 'genesisEpoch', 'protocol', 'rootHash', 'signature', 'signerKeyId'];
export const CRYPTO_DISCOVERY_ENCRYPTION_KEY_LENGTH_EXPECTED = 32;
export const RECORD_STORE_DISCOVERY_ENCRYPTION_KEY_LENGTH_EXPECTED = 32;
export const MONITOR_STORE_KEY_LENGTH_EXPECTED = 32;
export const MONITOR_STORE_DISCOVERY_ENCRYPTION_KEY_LENGTH_EXPECTED = 32;
