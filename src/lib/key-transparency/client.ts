import { sha3_512 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '../utils/byte-utils';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { STORAGE_KEY_DOMAINS, STORAGE_PREFIXES } from '../database/storage-keys';
import {
  ACCOUNT_AUTH_PURPOSE,
  KEY_TRANSPARENCY_APPEND_AUDIENCE,
  KEY_TRANSPARENCY_SYNC_AUDIENCE,
} from '../config/audiences';

import {
  KEY_TRANSPARENCY_ML_DSA_PUBLIC_KEY_BYTES,
  KEY_TRANSPARENCY_ML_DSA_SIGNATURE_BYTES,
  KEY_TRANSPARENCY_APPEND_POW_DIFFICULTY,
  KEY_TRANSPARENCY_APPEND_POW_DOMAIN,
  KEY_TRANSPARENCY_DELTA_MAX_EPOCHS,
  KEY_TRANSPARENCY_MAX_LOG_SIZE,
  KEY_TRANSPARENCY_PROTOCOL,
  KEY_TRANSPARENCY_SYNC_POW_DIFFICULTY,
  KEY_TRANSPARENCY_SYNC_POW_DOMAIN,
  exactPlainObject,
  isKeyTransparencyHash,
  keyTransparencyPowEpoch,
  keyTransparencyRecoveryActivationEpoch,
} from '../../../shared/key-transparency-protocol.js';
import { createAnonymousHttpPow } from '../cryptography/anonymous-http-pow';
import { Base64 } from '../cryptography/base64';
import {
  PrivacyPassClient,
  PrivacyPassHelpers,
  type AnonymousToken,
} from '../cryptography/privacy-pass-client';
import { tokenVault } from '../database/token-vault';
import { AUTH_USERNAME_REGEX } from '../constants';
import {
  assertCurrentServerContext,
  captureCurrentServerContext,
  deriveLocalAccountScope,
  type CurrentServerContext,
} from '../security/local-account-scope';
import { storage } from '../tauri-bindings';
import { EventType } from '../types/event-types';
import { anonymousHttpFetch } from '../transport/pq-anonymous-http';
import { wipeAnonymousToken } from '../cryptography/wipe';
import { isCanonicalAuthUsername } from '../sanitizers';
import { createStoreLock } from './store-lock';
import websocketClient from '../websocket/websocket';
import {
  computeKeyTransparencyRecordHash,
  createKeyTransparencyAuthorizationWithSigners,
  deriveKeyTransparencyEpochLabel,
  deriveKeyTransparencyLabel,
  keyTransparencyCurrentEpoch,
  keyTransparencyPublicKeyCommitment,
  type KeyTransparencyAuthorization,
  type KeyTransparencySignedUpdate,
} from './crypto';
import type {
  KeyTransparencyCheckpoint,
  KeyTransparencyLogHead,
  KeyTransparencyTransition,
  VerifiedKeyTransparencyContactState,
} from './types';
import {
  commitKeyTransparencyDelta,
  findKeyTransparencyRecordsForContact,
  loadKeyTransparencyCheckpoint,
  loadKeyTransparencyTransition,
  loadOwnKeyTransparencyTransition,
  saveKeyTransparencyTransition,
  saveOwnKeyTransparencyTransition,
  type StoredKeyTransparencyRecord,
} from './record-store';
import {
  KeyTransparencyWarningStoreCorruptionError,
  keyTransparencyWarningStore,
} from './warning-store';
import {
  KeyTransparencyMonitorStoreCorruptionError,
  listKeyTransparencyMonitorTargets,
  markKeyTransparencyMonitorTargetChecked,
  readKeyTransparencyMonitorTarget,
  removeKeyTransparencyMonitorPeer,
  upsertKeyTransparencyMonitorTarget,
} from './monitor-store';
import {
  clearKeyTransparencyVerifiedMaterials,
  exportKeyTransparencyAuthorizations,
  getKeyTransparencyAuthorizedPeerState,
  importKeyTransparencyAuthorizations,
  revokeKeyTransparencyPeerAuthorization,
} from './verified-material';
import {
  clearKeyTransparencyAuthorizations,
  readKeyTransparencyAuthorizations,
  writeKeyTransparencyAuthorizations,
} from './authorization-store';
import { beginPeerIdentityRevocation } from './revocation';
import {
  KeyTransparencyGlobalVerificationError,
  keyTransparencyGenesisCheckpoint,
  verifyKeyTransparencyHead,
  keyTransparencyRootMatches,
  verifyKeyTransparencyDelta,
  verifyKeyTransparencyGossipHead,
  verifyKeyTransparencyTransitions,
} from './verifier';


const MAX_SYNC_ROUNDS = 64;
const GOSSIP_AUDIT_ATTEMPTS = 3;
const GOSSIP_AUDIT_RETRY_MS = 15_000;
const GOSSIP_DEFERRED_RETRY_MS = 60_000;
const MAX_PENDING_GOSSIP_HEADS = 64;
const MAX_AUDITED_GOSSIP_HEADS = 256;
const CONTACT_MONITOR_SWEEP_MS = 24 * 60 * 60 * 1000;
const CONTACT_MONITOR_MIN_INTERVAL_MS = 60_000;
const CONTACT_MONITOR_MAX_INTERVAL_MS = 30 * 60 * 1000;
const CONTACT_MONITOR_RETRY_MS = 5 * 60 * 1000;
const COVER_MONITOR_MIN_INTERVAL_MS = 10 * 60 * 1000;
const COVER_MONITOR_JITTER_MS = 20 * 60 * 1000;
const TREE_HEAD_KEYS = ['protocol', 'rootHash', 'signature', 'signerKeyId', 'timestamp', 'treeSize'];

export type OwnKeyTransparencyStatus =
  | { status: 'ready'; contact: VerifiedKeyTransparencyContactState }
  | { status: 'recovery-pending'; contact: VerifiedKeyTransparencyContactState; activatesAtEpoch: number };

interface RootKeyPairInput {
  publicKeyBase64: string;
  sign: (payload: Uint8Array) => Promise<string>;
}

interface VerifiedQueryState {
  context: CurrentServerContext;
  head: KeyTransparencyLogHead;
  contact: VerifiedKeyTransparencyContactState | null;
}

function storageDigest(domain: string, parts: readonly string[]): string {
  const input = new TextEncoder().encode([domain, ...parts].join('\0'));
  const digest = sha3_512(input);
  try {
    return bytesToHex(digest.subarray(0, 32));
  } finally {
    input.fill(0);
    digest.fill(0);
  }
}

function headStorageKey(serverScope: string): string {
  return `${STORAGE_PREFIXES.KEY_TRANSPARENCY_HEAD}${storageDigest(STORAGE_KEY_DOMAINS.KEY_TRANSPARENCY_HEAD, [serverScope])}`;
}

function incidentStorageKey(serverScope: string): string {
  return `${STORAGE_PREFIXES.KEY_TRANSPARENCY_INCIDENT}${storageDigest(STORAGE_KEY_DOMAINS.KEY_TRANSPARENCY_INCIDENT, [serverScope])}`;
}

function contactStorageKey(accountScope: string, label: string): string {
  return `${STORAGE_PREFIXES.KEY_TRANSPARENCY_CONTACT}${storageDigest(STORAGE_KEY_DOMAINS.KEY_TRANSPARENCY_CONTACT, [accountScope, label])}`;
}

function decodeCanonicalPublicKey(value: string): Uint8Array {
  if (
    typeof value !== 'string' ||
    value.length !== 4 * Math.ceil(KEY_TRANSPARENCY_ML_DSA_PUBLIC_KEY_BYTES / 3) ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) throw new Error('Invalid account-root public key');
  const publicKey = Base64.base64ToUint8Array(value);
  if (
    publicKey.length !== KEY_TRANSPARENCY_ML_DSA_PUBLIC_KEY_BYTES ||
    Base64.arrayBufferToBase64(publicKey) !== value
  ) {
    publicKey.fill(0);
    throw new Error('Invalid account-root public key');
  }
  return publicKey;
}

function parseStoredHead(raw: string | null): KeyTransparencyLogHead | null {
  if (raw === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('Stored key-transparency head is corrupt');
  }
  const head = parsed as KeyTransparencyLogHead;
  if (
    !exactPlainObject(head, TREE_HEAD_KEYS) ||
    head.protocol !== KEY_TRANSPARENCY_PROTOCOL ||
    !isKeyTransparencyHash(head.rootHash) ||
    !isKeyTransparencyHash(head.signerKeyId) ||
    !Number.isSafeInteger(head.epoch) ||
    head.epoch < 0 ||
    !Number.isSafeInteger(head.entryCount) ||
    head.entryCount < 0 ||
    head.entryCount > KEY_TRANSPARENCY_MAX_LOG_SIZE ||
    typeof head.signature !== 'string'
  ) throw new Error('Stored key-transparency head is corrupt');
  return head;
}

function exactSuccessWrapper(value: unknown): value is { ok: true } {
  return exactPlainObject(value, ['ok']) && (value as { ok?: unknown }).ok === true;
}

function exactQueryWrapper(value: unknown): value is { ok: true; result: unknown } {
  return exactPlainObject(value, ['ok', 'result']) && (value as { ok?: unknown }).ok === true;
}

function parseGossipCandidate(value: unknown): KeyTransparencyLogHead | null {
  const head = value as KeyTransparencyLogHead;
  if (
    !exactPlainObject(head, TREE_HEAD_KEYS) ||
    head.protocol !== KEY_TRANSPARENCY_PROTOCOL ||
    !isKeyTransparencyHash(head.rootHash) ||
    !isKeyTransparencyHash(head.signerKeyId) ||
    !Number.isSafeInteger(head.epoch) ||
    head.epoch < 0 ||
    !Number.isSafeInteger(head.entryCount) ||
    head.entryCount < 0 ||
    head.entryCount > KEY_TRANSPARENCY_MAX_LOG_SIZE ||
    typeof head.signature !== 'string' ||
    head.signature.length !== 4 * Math.ceil(KEY_TRANSPARENCY_ML_DSA_SIGNATURE_BYTES / 3) ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(head.signature)
  ) return null;
  return { ...head };
}

function randomUnit(): number {
  const value = new Uint32Array(1);
  crypto.getRandomValues(value);
  return value[0] / 0x1_0000_0000;
}

class KeyTransparencyClient {
  private latestHead: KeyTransparencyLogHead | null = null;
  private generation = 0;
  private readonly enqueue = createStoreLock();
  private pendingGossip = new Map<string, KeyTransparencyLogHead>();
  private deferredGossip = new Map<string, KeyTransparencyLogHead>();
  private pendingGossipSources = new Map<string, string>();
  private auditedGossip = new Set<string>();
  private deferredGossipTimer: ReturnType<typeof setTimeout> | null = null;
  private contactMonitorTimer: ReturnType<typeof setTimeout> | null = null;
  private coverMonitorTimer: ReturnType<typeof setTimeout> | null = null;
  private monitorOwner: string | null = null;
  private securityIncidentActive = false;
  private authorizationRestore: {
    ownerUsername: string;
    generation: number;
    promise: Promise<number>;
  } | null = null;

  destroy(): void {
    this.generation += 1;
    this.latestHead = null;
    this.pendingGossip.clear();
    this.deferredGossip.clear();
    this.pendingGossipSources.clear();
    this.auditedGossip.clear();
    if (this.deferredGossipTimer !== null) clearTimeout(this.deferredGossipTimer);
    this.deferredGossipTimer = null;
    this.securityIncidentActive = false;
    this.authorizationRestore = null;
    clearKeyTransparencyVerifiedMaterials();
    this.stopContactMonitoring();
  }

  isSecurityIncidentActive(): boolean {
    return this.securityIncidentActive;
  }

  async assertSecurityReady(): Promise<void> {
    const context = await captureCurrentServerContext();
    await this.assertNoIncident(context);
    await assertCurrentServerContext(context);
  }

  getGossipHead(): KeyTransparencyLogHead | null {
    return this.latestHead ? { ...this.latestHead } : null;
  }

  private assertGeneration(expectedGeneration: number): void {
    if (expectedGeneration !== this.generation) {
      throw new Error('Key-transparency account changed');
    }
  }

  private markGossipAudited(id: string): void {
    this.pendingGossipSources.delete(id);
    this.auditedGossip.delete(id);
    this.auditedGossip.add(id);
    while (this.auditedGossip.size > MAX_AUDITED_GOSSIP_HEADS) {
      const oldest = this.auditedGossip.values().next().value as string | undefined;
      if (!oldest) break;
      this.auditedGossip.delete(oldest);
    }
  }

  private activateSecurityIncident(): void {
    if (this.securityIncidentActive) return;
    this.securityIncidentActive = true;
    this.generation += 1;
    const incidentOwner = this.monitorOwner;
    clearKeyTransparencyVerifiedMaterials();
    
    if (incidentOwner) {
      void this.discardPersistedAuthorizations(incidentOwner).catch(() => { });
    }
    this.stopContactMonitoring();
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new Event(EventType.KEY_TRANSPARENCY_SECURITY_INCIDENT));
    }
  }

  private async hasIncident(context: CurrentServerContext): Promise<boolean> {
    const detected = await storage.get(incidentStorageKey(context.serverScope)) !== null;
    if (detected) this.activateSecurityIncident();
    return detected;
  }

  private async recordIncident(context: CurrentServerContext): Promise<void> {
    this.activateSecurityIncident();
    const marker = JSON.stringify({
      protocol: PROTOCOL_KEYS.KEY_TRANSPARENCY_CLIENT_STATE,
      detected: true,
    });
    const key = incidentStorageKey(context.serverScope);
    if (!await storage.set(key, marker) || await storage.get(key) !== marker) {
      throw new Error('Key-transparency security incident could not be persisted');
    }
  }

  private async assertNoIncident(context: CurrentServerContext): Promise<void> {
    if (await this.hasIncident(context)) {
      throw new Error('Key-transparency security incident requires user review');
    }
  }

  private async loadHead(
    context: CurrentServerContext,
    signerPublicKey: Uint8Array,
  ): Promise<KeyTransparencyLogHead | null> {
    try {
      const head = parseStoredHead(await storage.get(headStorageKey(context.serverScope)));
      if (!head) return null;
      return verifyKeyTransparencyGossipHead(head, signerPublicKey);
    } catch {
      await this.recordIncident(context);
      throw new Error('Stored key-transparency head failed validation');
    }
  }

  private async persistHead(context: CurrentServerContext, head: KeyTransparencyLogHead): Promise<void> {
    const key = headStorageKey(context.serverScope);
    const serialized = JSON.stringify(head);
    if (!await storage.set(key, serialized) || await storage.get(key) !== serialized) {
      throw new Error('Key-transparency head could not be persisted');
    }
    this.latestHead = { ...head };
  }

  private async persistContact(
    context: CurrentServerContext,
    ownerUsername: string,
    contact: VerifiedKeyTransparencyContactState,
  ): Promise<void> {
    const accountScope = deriveLocalAccountScope(context, ownerUsername);
    const key = contactStorageKey(accountScope, contact.label);
    const serialized = JSON.stringify(contact);
    if (!await storage.set(key, serialized) || await storage.get(key) !== serialized) {
      throw new Error('Key-transparency contact state could not be persisted');
    }
  }

  // Fetch one delta and fold it onto the stored checkpoint
  private async requestDelta(input: {
    context: CurrentServerContext;
    checkpoint: KeyTransparencyCheckpoint;
    generation: number;
    toEpoch: number;
  }): Promise<ReturnType<typeof verifyKeyTransparencyDelta>> {
    this.assertGeneration(input.generation);
    const trustedNow = websocketClient.getAuthenticatedServerNow();
    if (trustedNow === null) throw new Error('Authenticated key-transparency time is unavailable');
    const powEpoch = keyTransparencyPowEpoch(trustedNow);
    const fromEpoch = input.checkpoint.epoch;
    const work = await createAnonymousHttpPow(
      KEY_TRANSPARENCY_SYNC_POW_DOMAIN,
      powEpoch,
      [String(fromEpoch), String(input.toEpoch)],
      KEY_TRANSPARENCY_SYNC_POW_DIFFICULTY,
    );
    const currentTrustedNow = websocketClient.getAuthenticatedServerNow();
    if (currentTrustedNow === null || powEpoch !== keyTransparencyPowEpoch(currentTrustedNow)) {
      throw new Error('Key-transparency proof-of-work epoch changed');
    }
    this.assertGeneration(input.generation);
    const material = websocketClient.getAnonymousHttpServerKeyMaterial();
    if (!material?.dilithiumPublicKey) {
      material?.kyberPublicKey.fill(0);
      material?.dilithiumPublicKey?.fill(0);
      material?.x25519PublicKey?.fill(0);
      throw new Error('Authenticated key-transparency signer is unavailable');
    }
    try {
      const response = await anonymousHttpFetch(
        KEY_TRANSPARENCY_SYNC_AUDIENCE,
        { fromEpoch, powEpoch, ...work, toEpoch: input.toEpoch },
        input.context.serverUrl,
      );
      await assertCurrentServerContext(input.context);
      this.assertGeneration(input.generation);
      if (!exactQueryWrapper(response)) {
        throw new Error('Invalid authenticated key-transparency response');
      }
      try {
        return verifyKeyTransparencyDelta(
          input.checkpoint,
          response.result,
          material.dilithiumPublicKey,
        );
      } catch {
        await this.recordIncident(input.context);
        throw new Error('Key-transparency delta verification failed');
      }
    } finally {
      material.kyberPublicKey.fill(0);
      material.dilithiumPublicKey.fill(0);
      material.x25519PublicKey?.fill(0);
    }
  }

  private async requestHead(
    context: CurrentServerContext,
    generation: number,
  ): Promise<KeyTransparencyLogHead> {
    this.assertGeneration(generation);
    const trustedNow = websocketClient.getAuthenticatedServerNow();
    if (trustedNow === null) throw new Error('Authenticated key-transparency time is unavailable');
    const powEpoch = keyTransparencyPowEpoch(trustedNow);
    const epoch = keyTransparencyCurrentEpoch(trustedNow);
    const work = await createAnonymousHttpPow(
      KEY_TRANSPARENCY_SYNC_POW_DOMAIN,
      powEpoch,
      [String(epoch), String(epoch)],
      KEY_TRANSPARENCY_SYNC_POW_DIFFICULTY,
    );
    this.assertGeneration(generation);
    const material = websocketClient.getAnonymousHttpServerKeyMaterial();
    if (!material?.dilithiumPublicKey) {
      material?.kyberPublicKey.fill(0);
      material?.dilithiumPublicKey?.fill(0);
      material?.x25519PublicKey?.fill(0);
      throw new Error('Authenticated key-transparency signer is unavailable');
    }
    try {
      const response = await anonymousHttpFetch(
        KEY_TRANSPARENCY_SYNC_AUDIENCE,
        { fromEpoch: epoch, powEpoch, ...work, toEpoch: epoch },
        context.serverUrl,
      );
      await assertCurrentServerContext(context);
      this.assertGeneration(generation);
      if (!exactQueryWrapper(response)) {
        throw new Error('Invalid authenticated key-transparency response');
      }
      const result = response.result as { head?: unknown };
      return verifyKeyTransparencyHead(result?.head, material.dilithiumPublicKey);
    } finally {
      material.kyberPublicKey.fill(0);
      material.dilithiumPublicKey.fill(0);
      material.x25519PublicKey?.fill(0);
    }
  }

  // Bring the local log up to the current epoch
  private async syncLogUnlocked(
    ownerUsername: string,
    generation: number,
  ): Promise<{ context: CurrentServerContext; checkpoint: KeyTransparencyCheckpoint }> {
    this.assertGeneration(generation);
    const context = await captureCurrentServerContext();
    await this.assertNoIncident(context);

    const nowEpoch = keyTransparencyCurrentEpoch(
      websocketClient.getAuthenticatedServerNow() ?? Date.now(),
    );
    let checkpoint = await loadKeyTransparencyCheckpoint(context, ownerUsername);
    if (checkpoint && checkpoint.epoch > nowEpoch) {
      checkpoint = null;
    }
    if (!checkpoint) {
      const probe = await this.requestHead(context, generation);
      checkpoint = keyTransparencyGenesisCheckpoint(probe.genesisEpoch);
    }
    const currentEpoch = keyTransparencyCurrentEpoch(
      websocketClient.getAuthenticatedServerNow() ?? Date.now(),
    );

    for (let round = 0; round < MAX_SYNC_ROUNDS && checkpoint.epoch <= currentEpoch; round += 1) {
      if (generation !== this.generation) throw new Error('Key-transparency account changed');
      const toEpoch = Math.min(
        currentEpoch,
        checkpoint.epoch + KEY_TRANSPARENCY_DELTA_MAX_EPOCHS - 1,
      );
      const openEpoch = toEpoch >= currentEpoch;
      const beforeRound = checkpoint;
      const verified = await this.requestDelta({ context, checkpoint, generation, toEpoch });
      await commitKeyTransparencyDelta(
        context,
        ownerUsername,
        verified.records,
        openEpoch ? beforeRound : verified.checkpoint,
      );
      await this.persistHead(context, verified.head);
      await assertCurrentServerContext(context);
      this.assertGeneration(generation);
      checkpoint = verified.checkpoint;
      if (openEpoch) break;
    }

    if (!this.latestHead) {
      const head = await this.requestHead(context, generation);
      this.assertGeneration(generation);
      await this.persistHead(context, head);
    }

    return { context, checkpoint };
  }

  // Sync the log then resolve a contact entirely from local state
  private async queryStateUnlocked(
    ownerUsername: string,
    discoveryEncryptionKey: Uint8Array,
    generation: number,
  ): Promise<VerifiedQueryState> {
    let { context, checkpoint } = await this.syncLogUnlocked(ownerUsername, generation);
    let records = await findKeyTransparencyRecordsForContact(
      context,
      ownerUsername,
      discoveryEncryptionKey,
      Math.max(0, checkpoint.epoch - 1),
    );
    this.assertGeneration(generation);

    if (records.length === 0) {
      const resynced = await this.syncLogUnlocked(ownerUsername, generation);
      context = resynced.context;
      checkpoint = resynced.checkpoint;
      records = await findKeyTransparencyRecordsForContact(
        context,
        ownerUsername,
        discoveryEncryptionKey,
        Math.max(0, checkpoint.epoch - 1),
      );
      this.assertGeneration(generation);
    }

    const published: Array<{
      transition: KeyTransparencyTransition;
      record: StoredKeyTransparencyRecord;
      epoch: number;
    }> = [];
    let missingTransitions = 0;
    for (const record of records) {
      const cached = await loadKeyTransparencyTransition(context, ownerUsername, record.recordHash);
      
      if (!cached) {
        missingTransitions = records.length - published.length;
        break;
      }
      published.push({
        transition: cached as KeyTransparencyTransition,
        record,
        epoch: record.epoch,
      });
    }
    
    if (records.length === 0 || missingTransitions > 0) {
      console.warn('[KT] contact chain incomplete', {
        records: records.length,
        verified: published.length,
        missingTransitions,
        throughEpoch: Math.max(0, checkpoint.epoch - 1),
      });
    }

    let contact: VerifiedKeyTransparencyContactState | null = null;
    try {
      contact = verifyKeyTransparencyTransitions(null, published, discoveryEncryptionKey);
    } catch {
      await this.recordIncident(context);
      throw new Error('Key-transparency contact chain verification failed');
    }
    if (contact) {
      contact = { ...contact, lastVerifiedEpoch: Math.max(0, checkpoint.epoch - 1) };
      await this.persistContact(context, ownerUsername, contact);
    }
    const head = this.latestHead;
    if (!head) throw new Error('Key-transparency head is unavailable');
    return { context, head, contact };
  }

  // This accounts latest signed transition for the discovery publisher to attach
  async getPublishedTransition(ownerUsername: string): Promise<unknown | null> {
    const context = await captureCurrentServerContext();
    return loadOwnKeyTransparencyTransition(context, ownerUsername);
  }

  // Cache a transition found in a peers discovery publication
  async ingestPublishedTransition(ownerUsername: string, value: unknown): Promise<void> {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return;
    const candidate = value as KeyTransparencyTransition;
    let recordHash: string;
    try {
      recordHash = computeKeyTransparencyRecordHash(
        candidate.signedUpdate,
        candidate.authorization,
      );
    } catch {
      return;
    }
    const context = await captureCurrentServerContext();
    await saveKeyTransparencyTransition(context, ownerUsername, recordHash, candidate);
  }

  async queryContactState(
    ownerUsername: string,
    discoveryEncryptionKey: Uint8Array,
  ): Promise<VerifiedQueryState> {
    const generation = this.generation;
    return this.enqueue(() => this.queryStateUnlocked(ownerUsername, discoveryEncryptionKey, generation));
  }

  async verifyDiscoveredIdentity(input: {
    ownerUsername: string;
    peerUsername: string;
    monitorContact?: boolean;
    discoveryEncryptionKey: Uint8Array;
    accountRootPublicKeyBase64: string;
  }): Promise<VerifiedKeyTransparencyContactState> {
    const generation = this.generation;
    return this.enqueue(async () => {
      this.assertGeneration(generation);
      const result = await this.queryStateUnlocked(
        input.ownerUsername,
        input.discoveryEncryptionKey,
        generation,
      );
      const contact = result.contact;
      if (!contact || !keyTransparencyRootMatches(contact, input.accountRootPublicKeyBase64)) {
        throw new Error('Discovery identity does not match the verified transparency log');
      }

      const liveAuthorization = getKeyTransparencyAuthorizedPeerState(
        input.ownerUsername,
        input.peerUsername,
      );
      const monitored = await this.runMonitorStoreOperation(
        result.context,
        () => readKeyTransparencyMonitorTarget(
          result.context,
          input.ownerUsername,
          input.peerUsername,
        ),
      );
      try {
        if (monitored && monitored.label !== contact.label) {
          await this.recordIncident(result.context);
          throw new Error('Monitored contact transparency label changed');
        }
        if (
          liveAuthorization && monitored &&
          liveAuthorization.rootCommitment !== monitored.rootCommitment
        ) {
          await this.recordIncident(result.context);
          throw new Error('Live and durable key-transparency trust state disagree');
        }
        if (
          (liveAuthorization && liveAuthorization.version > contact.version) ||
          (monitored && monitored.version > contact.version)
        ) {
          await this.recordIncident(result.context);
          throw new Error('Key-transparency trust checkpoint is ahead of verified history');
        }

        const previous = monitored ?? (liveAuthorization ? {
          peer: input.peerUsername,
          rootCommitment: liveAuthorization.rootCommitment,
        } : null);
        if (previous) {
          await this.revokeChangedMonitoredRoot(input.ownerUsername, previous, contact);
          this.assertGeneration(generation);
        }

        await this.runWarningStoreOperation(
          result.context,
          () => keyTransparencyWarningStore.update(
            result.context,
            input.ownerUsername,
            input.peerUsername,
            contact,
          ),
        );
        if (monitored || input.monitorContact !== false) {
          await this.runMonitorStoreOperation(
            result.context,
            () => upsertKeyTransparencyMonitorTarget(
              result.context,
              input.ownerUsername,
              input.peerUsername,
              input.discoveryEncryptionKey,
              contact,
              monitored ? {
                rootCommitment: monitored.rootCommitment,
                version: monitored.version,
              } : null,
            ),
          );
        }
        await assertCurrentServerContext(result.context);
        this.assertGeneration(generation);
        return contact;
      } finally {
        monitored?.discoveryEncryptionKey.fill(0);
      }
    });
  }

  private async runMonitorStoreOperation<T>(
    context: CurrentServerContext,
    operation: () => Promise<T>,
  ): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (error instanceof KeyTransparencyMonitorStoreCorruptionError) {
        await this.recordIncident(context);
        throw new Error('Stored key-transparency monitor state failed validation');
      }
      throw error;
    }
  }

  private async runWarningStoreOperation<T>(
    context: CurrentServerContext,
    operation: () => Promise<T>,
  ): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (error instanceof KeyTransparencyWarningStoreCorruptionError) {
        await this.recordIncident(context);
        throw new Error('Stored key-transparency warning state failed validation');
      }
      throw error;
    }
  }

  // Load this accounts persisted peer authorizations
  async restorePersistedAuthorizations(ownerUsername: string): Promise<number> {
    const generation = this.generation;
    const existing = this.authorizationRestore;
    if (
      existing &&
      existing.ownerUsername === ownerUsername &&
      existing.generation === generation
    ) return existing.promise;

    const promise = (async (): Promise<number> => {
      const context = await captureCurrentServerContext();
      if (await this.hasIncident(context)) return 0;
      const snapshot = await readKeyTransparencyAuthorizations(context, ownerUsername)
        .catch(() => null);
      if (!snapshot) return 0;
      await assertCurrentServerContext(context);
      if (generation !== this.generation || this.securityIncidentActive) return 0;
      return importKeyTransparencyAuthorizations(ownerUsername, snapshot);
    })();
    this.authorizationRestore = { ownerUsername, generation, promise };
    try {
      const restored = await promise;
      if (restored === 0 && this.authorizationRestore?.promise === promise) {
        this.authorizationRestore = null;
      }
      return restored;
    } catch (error) {
      if (this.authorizationRestore?.promise === promise) {
        this.authorizationRestore = null;
      }
      throw error;
    }
  }

  // Persist the current authorizations/revocations for this account
  async persistAuthorizations(ownerUsername: string): Promise<void> {
    if (this.securityIncidentActive) {
      return;
    }
    const generation = this.generation;
    const context = await captureCurrentServerContext();
    if (generation !== this.generation || this.securityIncidentActive) {
      return;
    }
    const snapshot = exportKeyTransparencyAuthorizations(ownerUsername);
    await writeKeyTransparencyAuthorizations(context, ownerUsername, snapshot);
  }

  // Drop the persisted authorizations for this account
  async discardPersistedAuthorizations(ownerUsername: string): Promise<void> {
    const context = await captureCurrentServerContext().catch(() => null);
    if (!context) return;
    await clearKeyTransparencyAuthorizations(context, ownerUsername).catch(() => { });
  }

  async activateWarningStore(ownerUsername: string): Promise<void> {
    const context = await captureCurrentServerContext();
    await this.assertNoIncident(context);
    await this.runWarningStoreOperation(
      context,
      () => keyTransparencyWarningStore.activate(ownerUsername),
    );
    await assertCurrentServerContext(context);
  }

  // Publish a transition append its record to the log, and cache the transition itself locally so it can be served to contacts.
  private async submitTransition(
    context: CurrentServerContext,
    generation: number,
    ownerUsername: string,
    signedUpdate: KeyTransparencySignedUpdate,
    updateAuthorization: KeyTransparencyAuthorization,
    discoveryEncryptionKey: Uint8Array,
  ): Promise<{ recordHash: string; epoch: number }> {
    let token: AnonymousToken | null = null;
    let redemption: Awaited<ReturnType<PrivacyPassClient['prepareRedemption']>> | null = null;
    try {
      this.assertGeneration(generation);
      const trustedNow = websocketClient.getAuthenticatedServerNow();
      if (trustedNow === null) throw new Error('Authenticated key-transparency time is unavailable');
      const powEpoch = keyTransparencyPowEpoch(trustedNow);
      const epoch = keyTransparencyCurrentEpoch(trustedNow);
      const epochLabel = deriveKeyTransparencyEpochLabel(discoveryEncryptionKey, epoch);
      const recordHash = computeKeyTransparencyRecordHash(signedUpdate, updateAuthorization);
      const work = await createAnonymousHttpPow(
        KEY_TRANSPARENCY_APPEND_POW_DOMAIN,
        powEpoch,
        [epochLabel, String(signedUpdate.version), recordHash],
        KEY_TRANSPARENCY_APPEND_POW_DIFFICULTY,
      );
      const currentTrustedNow = websocketClient.getAuthenticatedServerNow();
      if (currentTrustedNow === null || powEpoch !== keyTransparencyPowEpoch(currentTrustedNow)) {
        throw new Error('Key-transparency proof-of-work epoch changed');
      }
      this.assertGeneration(generation);
      const serverEntryAuthorization = await websocketClient.reserveServerEntryAuthorization();
      this.assertGeneration(generation);
      if (!serverEntryAuthorization) throw new Error('Anonymous server-entry authorization is unavailable');
      [token] = await tokenVault.reserveResumeTokens(1);
      this.assertGeneration(generation);
      if (!token) throw new Error('Anonymous account authorization is unavailable');
      redemption = await new PrivacyPassClient(ACCOUNT_AUTH_PURPOSE).prepareRedemption(token);
      this.assertGeneration(generation);
      const authorization = PrivacyPassHelpers.formatResponse(redemption);
      await assertCurrentServerContext(context);
      this.assertGeneration(generation);
      const response = await anonymousHttpFetch(
        KEY_TRANSPARENCY_APPEND_AUDIENCE,
        {
          authorization,
          epochLabel,
          powEpoch,
          ...work,
          recordHash,
          serverEntryAuthorization,
          version: signedUpdate.version,
        },
        context.serverUrl,
      );
      await assertCurrentServerContext(context);
      this.assertGeneration(generation);
      if (!exactSuccessWrapper(response)) {
        throw new Error('Key-transparency append was not accepted');
      }
      
      const published = { signedUpdate, authorization: updateAuthorization };
      await saveKeyTransparencyTransition(context, ownerUsername, recordHash, published);
      await saveOwnKeyTransparencyTransition(context, ownerUsername, published);
      return { recordHash, epoch };
    } finally {
      redemption?.nullifier.fill(0);
      redemption?.mac.fill(0);
      wipeAnonymousToken(token);
    }
  }


  private async registerOwnIdentity(
    context: CurrentServerContext,
    generation: number,
    ownerUsername: string,
    discoveryEncryptionKey: Uint8Array,
    rootPublicKey: Uint8Array,
    rootSigner: RootKeyPairInput['sign'],
    recovery: { publicKey: Uint8Array; sign: RootKeyPairInput['sign'] },
  ): Promise<void> {
    const signedUpdate: KeyTransparencySignedUpdate = {
      protocol: KEY_TRANSPARENCY_PROTOCOL,
      kind: 'register',
      label: deriveKeyTransparencyLabel(discoveryEncryptionKey),
      version: 1,
      rootCommitment: keyTransparencyPublicKeyCommitment(rootPublicKey),
      recoveryCommitment: keyTransparencyPublicKeyCommitment(recovery.publicKey),
      previousRootCommitment: null,
      pendingRootCommitment: null,
      recoveryRequestEpoch: null,
      recoveryActivatesAt: null,
    };
    const updateAuthorization = await createKeyTransparencyAuthorizationWithSigners(signedUpdate, {
      root: { publicKey: rootPublicKey, sign: rootSigner },
      recovery,
    });
    await this.submitTransition(
      context,
      generation,
      ownerUsername,
      signedUpdate,
      updateAuthorization,
      discoveryEncryptionKey,
    );
  }

  private async requestRecovery(
    context: CurrentServerContext,
    generation: number,
    ownerUsername: string,
    current: VerifiedKeyTransparencyContactState,
    discoveryEncryptionKey: Uint8Array,
    rootPublicKey: Uint8Array,
    rootSigner: RootKeyPairInput['sign'],
    recovery: { publicKey: Uint8Array; sign: RootKeyPairInput['sign'] },
  ): Promise<void> {
    if (keyTransparencyPublicKeyCommitment(recovery.publicKey) !== current.recoveryCommitment) {
      throw new Error('Password-derived recovery key does not match the transparency log');
    }
    const trustedNow = websocketClient.getAuthenticatedServerNow();
    if (trustedNow === null) throw new Error('Authenticated key-transparency time is unavailable');
    const recoveryRequestEpoch = keyTransparencyCurrentEpoch(trustedNow);
    const signedUpdate: KeyTransparencySignedUpdate = {
      protocol: KEY_TRANSPARENCY_PROTOCOL,
      kind: 'recovery-request',
      label: current.label,
      version: current.version + 1,
      rootCommitment: current.rootCommitment,
      recoveryCommitment: current.recoveryCommitment,
      previousRootCommitment: current.rootCommitment,
      pendingRootCommitment: keyTransparencyPublicKeyCommitment(rootPublicKey),
      recoveryRequestEpoch,
      recoveryActivatesAt: keyTransparencyRecoveryActivationEpoch(recoveryRequestEpoch),
    };
    const updateAuthorization = await createKeyTransparencyAuthorizationWithSigners(signedUpdate, {
      root: { publicKey: rootPublicKey, sign: rootSigner },
      recovery,
    });
    await this.submitTransition(
      context,
      generation,
      ownerUsername,
      signedUpdate,
      updateAuthorization,
      discoveryEncryptionKey,
    );
  }

  private async cancelRecovery(
    context: CurrentServerContext,
    generation: number,
    ownerUsername: string,
    current: VerifiedKeyTransparencyContactState,
    discoveryEncryptionKey: Uint8Array,
    rootPublicKey: Uint8Array,
    rootSigner: RootKeyPairInput['sign'],
  ): Promise<void> {
    const signedUpdate: KeyTransparencySignedUpdate = {
      protocol: KEY_TRANSPARENCY_PROTOCOL,
      kind: 'recovery-cancel',
      label: current.label,
      version: current.version + 1,
      rootCommitment: current.rootCommitment,
      recoveryCommitment: current.recoveryCommitment,
      previousRootCommitment: current.rootCommitment,
      pendingRootCommitment: null,
      recoveryRequestEpoch: null,
      recoveryActivatesAt: null,
    };
    const updateAuthorization = await createKeyTransparencyAuthorizationWithSigners(signedUpdate, {
      previousRoot: { publicKey: rootPublicKey, sign: rootSigner },
    });
    await this.submitTransition(
      context,
      generation,
      ownerUsername,
      signedUpdate,
      updateAuthorization,
      discoveryEncryptionKey,
    );
  }

  async validateOwnIdentity(input: {
    ownerUsername: string;
    discoveryEncryptionKey: Uint8Array;
    accountRoot: RootKeyPairInput;
    recovery: RootKeyPairInput;
  }): Promise<OwnKeyTransparencyStatus> {
    const generation = this.generation;
    return this.enqueue(async () => {
      this.assertGeneration(generation);
      if (typeof input.accountRoot.sign !== 'function' || typeof input.recovery.sign !== 'function') {
        throw new Error('Native key-transparency signer is unavailable');
      }
      let rootPublicKey: Uint8Array | null = null;
      let recoveryPublicKey: Uint8Array | null = null;
      try {
        rootPublicKey = decodeCanonicalPublicKey(input.accountRoot.publicKeyBase64);
        recoveryPublicKey = decodeCanonicalPublicKey(input.recovery.publicKeyBase64);
        let verified = await this.queryStateUnlocked(
          input.ownerUsername,
          input.discoveryEncryptionKey,
          generation,
        );
        const localRootCommitment = keyTransparencyPublicKeyCommitment(rootPublicKey);
        const recovery = { publicKey: recoveryPublicKey, sign: input.recovery.sign };
        const localRecoveryCommitment = keyTransparencyPublicKeyCommitment(recovery.publicKey);

        if (!verified.contact) {
          try {
            await this.registerOwnIdentity(
              verified.context,
              generation,
              input.ownerUsername,
              input.discoveryEncryptionKey,
              rootPublicKey,
              input.accountRoot.sign,
              recovery,
            );
          } catch (e) {
            console.log(`[KT-DIAG ${new Date().toISOString()}] registerOwnIdentity THREW`, { owner: input.ownerUsername, error: e instanceof Error ? e.message : String(e) });
          }
          verified = await this.queryStateUnlocked(input.ownerUsername, input.discoveryEncryptionKey, generation);
          if (!verified.contact) {
            throw new Error('Key-transparency registration did not commit');
          }
        }

        let current = verified.contact;
        if (current.recoveryCommitment !== localRecoveryCommitment) {
          throw new Error('Transparency recovery commitment does not match this account password');
        }

        if (current.state === 'recovery-pending') {
          if (current.rootCommitment === localRootCommitment) {
            try {
              await this.cancelRecovery(
                verified.context,
                generation,
                input.ownerUsername,
                current,
                input.discoveryEncryptionKey,
                rootPublicKey,
                input.accountRoot.sign,
              );
            } catch {
            }
            verified = await this.queryStateUnlocked(input.ownerUsername, input.discoveryEncryptionKey, generation);
            if (!verified.contact) throw new Error('Key-transparency identity disappeared');
            current = verified.contact;
          } else if (current.pendingRootCommitment === localRootCommitment) {
            return {
              status: 'recovery-pending',
              contact: current,
              activatesAtEpoch: current.recoveryActivatesAtEpoch!,
            };
          } else {
            throw new Error('A different key recovery is already pending');
          }
        }

        if (current.rootCommitment !== localRootCommitment) {
          try {
            await this.requestRecovery(
              verified.context,
              generation,
              input.ownerUsername,
              current,
              input.discoveryEncryptionKey,
              rootPublicKey,
              input.accountRoot.sign,
              recovery,
            );
          } catch {
          }
          verified = await this.queryStateUnlocked(input.ownerUsername, input.discoveryEncryptionKey, generation);
          if (!verified.contact) throw new Error('Key-transparency identity disappeared');
          current = verified.contact;
          if (
            current.state !== 'recovery-pending' ||
            current.pendingRootCommitment !== localRootCommitment ||
            current.recoveryActivatesAtEpoch === null
          ) throw new Error('Key-transparency recovery request did not commit');
          return {
            status: 'recovery-pending',
            contact: current,
            activatesAtEpoch: current.recoveryActivatesAtEpoch,
          };
        }

        return { status: 'ready', contact: current };
      } finally {
        rootPublicKey?.fill(0);
        recoveryPublicKey?.fill(0);
      }
    });
  }

  async rotateOwnIdentity(input: {
    ownerUsername: string;
    discoveryEncryptionKey: Uint8Array;
    previousRoot: RootKeyPairInput;
    newRoot: RootKeyPairInput;
  }): Promise<VerifiedKeyTransparencyContactState> {
    const generation = this.generation;
    return this.enqueue(async () => {
      this.assertGeneration(generation);
      let previousPublicKey: Uint8Array | null = null;
      let newPublicKey: Uint8Array | null = null;
      try {
        previousPublicKey = decodeCanonicalPublicKey(input.previousRoot.publicKeyBase64);
        newPublicKey = decodeCanonicalPublicKey(input.newRoot.publicKeyBase64);
        const verified = await this.queryStateUnlocked(input.ownerUsername, input.discoveryEncryptionKey, generation);
        const current = verified.contact;
        if (
          !current ||
          current.state !== 'active' ||
          current.rootCommitment !== keyTransparencyPublicKeyCommitment(previousPublicKey)
        ) throw new Error('Verified previous account root is unavailable for rotation');
        const signedUpdate: KeyTransparencySignedUpdate = {
          protocol: KEY_TRANSPARENCY_PROTOCOL,
          kind: 'rotate',
          label: current.label,
          version: current.version + 1,
          rootCommitment: keyTransparencyPublicKeyCommitment(newPublicKey),
          recoveryCommitment: current.recoveryCommitment,
          previousRootCommitment: current.rootCommitment,
          pendingRootCommitment: null,
          recoveryRequestEpoch: null,
          recoveryActivatesAt: null,
        };
        const updateAuthorization = await createKeyTransparencyAuthorizationWithSigners(signedUpdate, {
          previousRoot: {
            publicKey: previousPublicKey,
            sign: input.previousRoot.sign,
          },
          root: { publicKey: newPublicKey, sign: input.newRoot.sign },
        });
        await this.submitTransition(
          verified.context,
          generation,
          input.ownerUsername,
          signedUpdate,
          updateAuthorization,
          input.discoveryEncryptionKey,
        );
        const after = await this.queryStateUnlocked(input.ownerUsername, input.discoveryEncryptionKey, generation);
        if (!after.contact || after.contact.rootCommitment !== signedUpdate.rootCommitment) {
          throw new Error('Key-transparency rotation did not commit');
        }
        return after.contact;
      } finally {
        previousPublicKey?.fill(0);
        newPublicKey?.fill(0);
      }
    });
  }

  private scheduleContactMonitor(ownerUsername: string, generation: number, delayMs: number): void {
    if (this.contactMonitorTimer !== null) clearTimeout(this.contactMonitorTimer);
    this.contactMonitorTimer = setTimeout(() => {
      this.contactMonitorTimer = null;
      if (generation !== this.generation || this.monitorOwner !== ownerUsername) return;
      void this.enqueue(() => this.runContactMonitorCycle(ownerUsername, generation))
        .then((targetCount) => {
          if (generation !== this.generation || this.monitorOwner !== ownerUsername) return;
          const baseInterval = targetCount === 0
            ? CONTACT_MONITOR_MAX_INTERVAL_MS
            : Math.min(
                CONTACT_MONITOR_MAX_INTERVAL_MS,
                Math.max(CONTACT_MONITOR_MIN_INTERVAL_MS, CONTACT_MONITOR_SWEEP_MS / targetCount),
              );
          this.scheduleContactMonitor(
            ownerUsername,
            generation,
            Math.floor(baseInterval * (0.75 + randomUnit() * 0.5)),
          );
        })
        .catch(() => {
          if (generation === this.generation && this.monitorOwner === ownerUsername) {
            this.scheduleContactMonitor(ownerUsername, generation, CONTACT_MONITOR_RETRY_MS);
          }
        });
    }, Math.max(1, Math.floor(delayMs)));
  }

  private scheduleCoverMonitor(ownerUsername: string, generation: number, delayMs: number): void {
    if (this.coverMonitorTimer !== null) clearTimeout(this.coverMonitorTimer);
    this.coverMonitorTimer = setTimeout(() => {
      this.coverMonitorTimer = null;
      if (generation !== this.generation || this.monitorOwner !== ownerUsername) return;
      void this.enqueue(() => this.runCoverMonitorCycle(ownerUsername, generation))
        .catch(() => undefined)
        .finally(() => {
          if (generation === this.generation && this.monitorOwner === ownerUsername) {
            this.scheduleCoverMonitor(
              ownerUsername,
              generation,
              COVER_MONITOR_MIN_INTERVAL_MS + randomUnit() * COVER_MONITOR_JITTER_MS,
            );
          }
        });
    }, Math.max(1, Math.floor(delayMs)));
  }

  private async runContactMonitorCycle(
    ownerUsername: string,
    generation: number,
  ): Promise<number> {
    this.assertGeneration(generation);
    const context = await captureCurrentServerContext();
    await this.assertNoIncident(context);
    const targets = await this.runMonitorStoreOperation(
      context,
      () => listKeyTransparencyMonitorTargets(context, ownerUsername),
    );
    try {
      this.assertGeneration(generation);
      await assertCurrentServerContext(context);
      if (targets.length === 0) return 0;
      let oldest = Number.MAX_SAFE_INTEGER;
      for (const target of targets) oldest = Math.min(oldest, target.lastCheckedAt);
      const authenticatedNow = websocketClient.getAuthenticatedServerNow();
      if (authenticatedNow === null) {
        throw new Error('Authenticated key-transparency time is unavailable');
      }
      if (
        oldest > 0 &&
        oldest <= authenticatedNow &&
        authenticatedNow - oldest < CONTACT_MONITOR_SWEEP_MS
      ) return targets.length;
      const candidates = targets.filter((target) => target.lastCheckedAt === oldest);
      const target = candidates[Math.floor(randomUnit() * candidates.length)];
      const verified = await this.queryStateUnlocked(
        ownerUsername,
        target.discoveryEncryptionKey,
        generation,
      );
      if (!verified.contact || verified.contact.label !== target.label) {
        await this.recordIncident(verified.context);
        throw new Error('Monitored key-transparency contact disappeared');
      }
      await this.revokeChangedMonitoredRoot(ownerUsername, target, verified.contact);
      const contact = verified.contact;
      await this.runWarningStoreOperation(
        verified.context,
        () => keyTransparencyWarningStore.update(
          verified.context,
          ownerUsername,
          target.peer,
          contact,
        ),
      );
      const checkedAt = websocketClient.getAuthenticatedServerNow();
      if (checkedAt === null) throw new Error('Authenticated key-transparency time is unavailable');
      await this.runMonitorStoreOperation(
        verified.context,
        () => markKeyTransparencyMonitorTargetChecked(
          verified.context,
          ownerUsername,
          target.label,
          checkedAt,
          contact,
        ),
      );
      return targets.length;
    } finally {
      for (const target of targets) target.discoveryEncryptionKey.fill(0);
    }
  }

  private async runCoverMonitorCycle(ownerUsername: string, generation: number): Promise<void> {
    this.assertGeneration(generation);
    const context = await captureCurrentServerContext();
    await this.assertNoIncident(context);
    const targets = await this.runMonitorStoreOperation(
      context,
      () => listKeyTransparencyMonitorTargets(context, ownerUsername),
    );
    const selected = targets.length > 0
      ? targets[Math.floor(randomUnit() * targets.length)]
      : null;
    const discoveryKey = selected?.discoveryEncryptionKey.slice() ?? new Uint8Array(32);
    if (!selected) crypto.getRandomValues(discoveryKey);
    try {
      const verified = await this.queryStateUnlocked(ownerUsername, discoveryKey, generation);
      if (selected) {
        if (!verified.contact || verified.contact.label !== selected.label) {
          await this.recordIncident(verified.context);
          throw new Error('Covered key-transparency contact disappeared');
        }
        await this.revokeChangedMonitoredRoot(ownerUsername, selected, verified.contact);
        const contact = verified.contact;
        await this.runWarningStoreOperation(
          verified.context,
          () => keyTransparencyWarningStore.update(
            verified.context,
            ownerUsername,
            selected.peer,
            contact,
          ),
        );
        const checkedAt = websocketClient.getAuthenticatedServerNow();
        if (checkedAt === null) throw new Error('Authenticated key-transparency time is unavailable');
        await this.runMonitorStoreOperation(
          verified.context,
          () => markKeyTransparencyMonitorTargetChecked(
            verified.context,
            ownerUsername,
            selected.label,
            checkedAt,
            contact,
          ),
        );
      }
    } finally {
      discoveryKey.fill(0);
      for (const target of targets) target.discoveryEncryptionKey.fill(0);
    }
  }

  private async revokeChangedMonitoredRoot(
    ownerUsername: string,
    target: { peer: string; rootCommitment: string },
    contact: VerifiedKeyTransparencyContactState,
  ): Promise<void> {
    if (target.rootCommitment === contact.rootCommitment) return;
    revokeKeyTransparencyPeerAuthorization(ownerUsername, target.peer, contact);
    
    void this.persistAuthorizations(ownerUsername).catch(() => { });
    const nativeRevocation = beginPeerIdentityRevocation(ownerUsername, target.peer);
    try {
      window.dispatchEvent(new CustomEvent(EventType.KEY_TRANSPARENCY_ROOT_CHANGED, {
        detail: {
          account: ownerUsername,
          peer: target.peer,
          rootCommitment: contact.rootCommitment,
          version: contact.version,
        },
      }));
    } catch {
    }
    await nativeRevocation;
  }

  startContactMonitoring(ownerUsername: string): void {
    if (!isCanonicalAuthUsername(ownerUsername)) return;
    const normalized = ownerUsername;
    if (
      this.monitorOwner === normalized &&
      (this.contactMonitorTimer !== null || this.coverMonitorTimer !== null)
    ) return;
    this.stopContactMonitoring();
    this.monitorOwner = normalized;
    const generation = this.generation;
    this.scheduleContactMonitor(normalized, generation, 30_000 + randomUnit() * 90_000);
    this.scheduleCoverMonitor(
      normalized,
      generation,
      COVER_MONITOR_MIN_INTERVAL_MS + randomUnit() * COVER_MONITOR_JITTER_MS,
    );
  }

  stopContactMonitoring(ownerUsername?: string): void {
    if (ownerUsername && this.monitorOwner !== ownerUsername.trim().toLowerCase()) return;
    if (this.contactMonitorTimer !== null) clearTimeout(this.contactMonitorTimer);
    if (this.coverMonitorTimer !== null) clearTimeout(this.coverMonitorTimer);
    this.contactMonitorTimer = null;
    this.coverMonitorTimer = null;
    this.monitorOwner = null;
  }

  async removeMonitoredPeer(ownerUsername: string, peer: string): Promise<void> {
    const generation = this.generation;
    await this.enqueue(async () => {
      this.assertGeneration(generation);
      const context = await captureCurrentServerContext();
      await this.runMonitorStoreOperation(
        context,
        () => removeKeyTransparencyMonitorPeer(context, ownerUsername, peer),
      );
      await assertCurrentServerContext(context);
      this.assertGeneration(generation);
    });
  }

  private async auditGossipAttempt(
    gossip: KeyTransparencyLogHead,
    generation: number,
    ownerUsername: string,
  ): Promise<'complete' | 'invalid' | 'retry'> {
    this.assertGeneration(generation);
    const context = await captureCurrentServerContext();
    await this.assertNoIncident(context);
    const material = websocketClient.getAnonymousHttpServerKeyMaterial();
    if (!material?.dilithiumPublicKey) {
      material?.kyberPublicKey.fill(0);
      material?.x25519PublicKey?.fill(0);
      return 'retry';
    }
    try {
      try {
        verifyKeyTransparencyGossipHead(gossip, material.dilithiumPublicKey);
      } catch {
        return 'invalid';
      }
    } finally {
      material.kyberPublicKey.fill(0);
      material.dilithiumPublicKey.fill(0);
      material.x25519PublicKey?.fill(0);
    }
    this.assertGeneration(generation);

    const signer = websocketClient.getAnonymousHttpServerKeyMaterial();
    if (!signer?.dilithiumPublicKey) {
      signer?.kyberPublicKey.fill(0);
      signer?.x25519PublicKey?.fill(0);
      return 'retry';
    }
    let knownHead: KeyTransparencyLogHead | null;
    try {
      knownHead = await this.loadHead(context, signer.dilithiumPublicKey);
    } finally {
      signer.kyberPublicKey.fill(0);
      signer.dilithiumPublicKey.fill(0);
      signer.x25519PublicKey?.fill(0);
    }
    if (knownHead?.entryCount === gossip.entryCount && knownHead.rootHash !== gossip.rootHash) {
      await this.recordIncident(context);
      throw new Error('Conflicting signed key-transparency heads detected');
    }
    if (knownHead?.entryCount === gossip.entryCount && knownHead.rootHash === gossip.rootHash) {
      return 'complete';
    }

    try {
      const { context: syncedContext } = await this.syncLogUnlocked(ownerUsername, generation);
      this.assertGeneration(generation);
      const fresh = this.latestHead;
      if (!fresh) return 'retry';

      if (fresh.entryCount < gossip.entryCount) {
        if (fresh.epoch > gossip.epoch) {
          await this.recordIncident(syncedContext);
          throw new Error('Key-transparency signer served a later smaller log');
        }
        return 'retry';
      }
      if (fresh.entryCount === gossip.entryCount && fresh.rootHash !== gossip.rootHash) {
        await this.recordIncident(syncedContext);
        throw new Error('Conflicting signed key-transparency heads detected');
      }
      return 'complete';
    } catch (error) {
      if (error instanceof KeyTransparencyGlobalVerificationError) throw error;
      return 'retry';
    }
  }

  private async runGossipAudit(
    id: string,
    gossip: KeyTransparencyLogHead,
    generation: number,
  ): Promise<void> {
    try {
      for (let attempt = 0; attempt < GOSSIP_AUDIT_ATTEMPTS; attempt += 1) {
        try {
          const owner = this.monitorOwner;
          if (!owner) return;
          const status = await this.enqueue(
            () => this.auditGossipAttempt(gossip, generation, owner),
          );
          if (status === 'complete') {
            this.markGossipAudited(id);
            return;
          }
          if (status === 'invalid') return;
        } catch {
          if (generation !== this.generation) return;
          try {
            const context = await captureCurrentServerContext();
            if (await this.hasIncident(context)) {
              this.markGossipAudited(id);
              return;
            }
          } catch {
          }
        }
        if (attempt + 1 < GOSSIP_AUDIT_ATTEMPTS) {
          await new Promise((resolve) => setTimeout(resolve, GOSSIP_AUDIT_RETRY_MS));
        }
      }
      if (generation === this.generation) {
        this.pendingGossip.delete(id);
        this.deferredGossip.delete(id);
        this.deferredGossip.set(id, { ...gossip });
        while (this.pendingGossip.size + this.deferredGossip.size > MAX_PENDING_GOSSIP_HEADS) {
          const oldest = this.deferredGossip.keys().next().value as string | undefined;
          if (!oldest) break;
          this.deferredGossip.delete(oldest);
        }
        this.scheduleDeferredGossip(generation);
      }
    } finally {
      this.pendingGossip.delete(id);
      if (!this.deferredGossip.has(id)) this.pendingGossipSources.delete(id);
    }
  }

  private scheduleDeferredGossip(generation: number): void {
    if (
      this.deferredGossipTimer !== null ||
      this.deferredGossip.size === 0 ||
      generation !== this.generation
    ) return;
    this.deferredGossipTimer = setTimeout(() => {
      this.deferredGossipTimer = null;
      if (generation !== this.generation) return;
      const next = this.deferredGossip.entries().next().value as
        | [string, KeyTransparencyLogHead]
        | undefined;
      if (!next) return;
      const [id, gossip] = next;
      this.deferredGossip.delete(id);
      if (!this.auditedGossip.has(id)) {
        this.pendingGossip.set(id, gossip);
        void this.runGossipAudit(id, gossip, generation).catch(() => undefined);
      }
      this.scheduleDeferredGossip(generation);
    }, GOSSIP_DEFERRED_RETRY_MS);
  }

  observeGossipHead(value: unknown, sourcePeer: string): void {
    const gossip = parseGossipCandidate(value);
    if (!gossip) return;
    const source = typeof sourcePeer === 'string' ? sourcePeer.trim().toLowerCase() : '';
    if (source !== sourcePeer || !AUTH_USERNAME_REGEX.test(source)) return;
    const id = `${gossip.entryCount}:${gossip.rootHash}`;
    if (
      this.pendingGossip.has(id) ||
      this.deferredGossip.has(id) ||
      this.auditedGossip.has(id) ||
      Array.from(this.pendingGossipSources.values()).includes(source) ||
      this.pendingGossip.size + this.deferredGossip.size >= MAX_PENDING_GOSSIP_HEADS
    ) return;
    const generation = this.generation;
    this.pendingGossip.set(id, gossip);
    this.pendingGossipSources.set(id, source);
    void this.runGossipAudit(id, gossip, generation).catch(() => undefined);
  }
}

export const keyTransparencyClient = new KeyTransparencyClient();
