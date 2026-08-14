import type {
  KeyTransparencyAuthorization,
  KeyTransparencyEventKind,
  KeyTransparencySignedUpdate,
} from './crypto';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

// The signed head of the append only log.
export interface KeyTransparencyLogHead {
  protocol: typeof PROTOCOL_KEYS.KEY_TRANSPARENCY_PROTOCOL;
  epoch: number;
  genesisEpoch: number;
  entryCount: number;
  rootHash: string;
  signerKeyId: string;
  signature: string;
}

// entire on-server footprint of an account update
export interface KeyTransparencyRecord {
  epoch: number;
  epochLabel: string;
  version: number;
  recordHash: string;
}

export interface KeyTransparencySyncResult {
  protocol: typeof PROTOCOL_KEYS.KEY_TRANSPARENCY_PROTOCOL;
  currentEpoch: number;
  fromEpoch: number;
  toEpoch: number;
  firstLogIndex: number;
  records: KeyTransparencyRecord[];
  head: KeyTransparencyLogHead;
}

export interface KeyTransparencyTransition {
  signedUpdate: KeyTransparencySignedUpdate;
  authorization: KeyTransparencyAuthorization;
}

export interface KeyTransparencyCheckpoint {
  protocol: typeof PROTOCOL_KEYS.KEY_TRANSPARENCY_PROTOCOL;
  epoch: number;
  entryCount: number;
  rootHash: string;
}

export interface VerifiedKeyTransparencyContactState {
  protocol: typeof PROTOCOL_KEYS.KEY_TRANSPARENCY_CONTACT;
  label: string;
  version: number;
  state: 'active' | 'recovery-pending';
  kind: KeyTransparencyEventKind;
  rootCommitment: string;
  recoveryCommitment: string;
  pendingRootCommitment: string | null;
  recoveryActivatesAtEpoch: number | null;
  recordHash: string;
  epoch: number;
  lastVerifiedEpoch: number;
}
