/**
 * Blind Routing Client
 */

import { blake3 } from '@noble/hashes/blake3.js';
import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';
import { PostQuantumRandom } from '../cryptography/random';
import { PostQuantumUtils } from '../utils/pq-utils';
import { PostQuantumKEM } from '../cryptography/kem';
import { MessageFraming, FrameSize } from './message-framing';
import { MIN_ENVELOPE_SIZE } from '../constants';
import { storage } from '../tauri-bindings';
import {
  deriveBlockListLookupId,
  deriveBundleLookupId,
  deriveMailboxMetadataId,
  deriveRendezvousRouteId,
  isRendezvousRouteId
} from './rendezvous-routing';

// Sealed envelope version
const SEALED_ENVELOPE_VERSION = 'ss-v1';
const ROUTE_ROTATION_INTERVAL_MS = 5 * 60 * 1000;
const ROUTE_ROTATION_JITTER_MS = 45 * 1000;
const COVER_CIPHERTEXT_BYTES = FrameSize.SMALL + 16;
const COVER_EPHEMERAL_BYTES = 1568;
const COVER_NONCE_BYTES = 24;

export interface BlindRoutingCredentials {
  capabilityToken: string;
  primaryInboxId?: string;
  secondaryInboxId?: string;
  primaryRouteId?: string;
  secondaryRouteId?: string;
  primaryMailboxLookupId?: string;
  primaryBundleLookupId?: string;
  primaryBlockListLookupId?: string;
  blindSignature?: string;
  blindSignatureKid?: string;
  blindSignatureSubject?: 'route-v1';
  expiresAt: number;
}

export interface SealedEnvelope {
  version: string;
  ciphertext: string;
  ephemeralKey: string;
  nonce: string;
}

export interface BlindRouteMessage {
  type: typeof SignalType.BLIND_ROUTE;
  sealedEnvelope: SealedEnvelope;
}

export interface PeerInboxInfo {
  inboxId: string;
  routeId?: string;
  mailboxLookupId?: string;
  kyberPublicKey: Uint8Array;
  dilithiumPublicKey: Uint8Array;
}

export interface RouteCommitmentRotationResult {
  primaryInboxId: string;
  secondaryInboxId: string;
  routeId: string;
  mailboxLookupId: string;
  bundleLookupId: string;
  blockListLookupId: string;
}

/**
 * Blind Routing Client
 * Handles sealed sender envelope creation and routing
 */
export class BlindRoutingClient {
  private credentials: BlindRoutingCredentials | null = null;
  private localUsername: string;
  private localKyberKeys: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
  private routeRotationTimer: ReturnType<typeof setTimeout> | null = null;
  private routeRotationInFlight = false;

  private peerInboxes: Map<string, PeerInboxInfo> = new Map();

  private sendFn: ((message: any) => Promise<void>) | null = null;

  constructor(username: string) {
    this.localUsername = username;
  }

  /**
   * Check if credentials are loaded in memory
   */
  hasCredentials(): boolean {
    return this.credentials !== null && !!this.credentials.capabilityToken;
  }

  /**
   * Set blind routing credentials received from server after auth
   */
  async setCredentials(credentials: BlindRoutingCredentials): Promise<void> {
    const normalized = this.normalizeCredentials(credentials);
    this.credentials = normalized;
    await this.saveCredentials(normalized);
  }

  /**
   * Persist credentials to local storage
   */
  async saveCredentials(credentials: BlindRoutingCredentials): Promise<void> {
    try {
      await storage.init();
      const key = `rtc:${this.localUsername}`;
      await storage.set(key, JSON.stringify(credentials));
    } catch (e) {
      console.error('[BlindRouting] Failed to save credentials');
    }
  }

  /**
   * Load credentials from local storage
   */
  async loadPersistentCredentials(): Promise<BlindRoutingCredentials | null> {
    try {
      await storage.init();
      const key = `rtc:${this.localUsername}`;
      const raw = await storage.get(key);
      if (raw && typeof raw === 'string') {
        this.credentials = this.normalizeCredentials(JSON.parse(raw));
        return this.credentials;
      }
    } catch (e) {
      console.error('[BlindRouting] Failed to load credentials');
    }
    return null;
  }

  /**
   * Set local Kyber keys for key encapsulation
   */
  setKyberKeys(keys: { publicKey: Uint8Array; secretKey: Uint8Array }): void {
    this.localKyberKeys = keys;
  }

  /**
   * Get local Kyber public key
   */
  getLocalKyberPublicKey(): Uint8Array | null {
    return this.localKyberKeys?.publicKey || null;
  }

  /**
   * Set WebSocket send function
   */
  setSendFunction(fn: (message: any) => Promise<void>): void {
    this.sendFn = fn;
  }

  /**
   * Register a peer inbox information
   */
  registerPeerInbox(username: string, inboxInfo: PeerInboxInfo): void {
    const routeId = inboxInfo.routeId || deriveRendezvousRouteId(inboxInfo.inboxId);
    const mailboxLookupId = inboxInfo.mailboxLookupId || deriveMailboxMetadataId(inboxInfo.inboxId);
    this.peerInboxes.set(username, { ...inboxInfo, routeId, mailboxLookupId });
  }

  /**
   * Get current inbox ID for receiving messages
   */
  getMyInboxId(): string | null {
    return this.credentials?.primaryInboxId ?? null;
  }

  /**
   * Get committed route ID used for server visible rendezvous
   */
  getMyRouteId(): string | null {
    const routeId = this.credentials?.primaryRouteId;
    if (isRendezvousRouteId(routeId)) return routeId;
    const inboxId = this.credentials?.primaryInboxId;
    return inboxId ? deriveRendezvousRouteId(inboxId) : null;
  }

  getMyMailboxLookupId(): string | null {
    return this.credentials?.primaryMailboxLookupId || (
      this.credentials?.primaryInboxId ? deriveMailboxMetadataId(this.credentials.primaryInboxId) : null
    );
  }

  getMyBundleLookupId(): string | null {
    return this.credentials?.primaryBundleLookupId || (
      this.credentials?.primaryInboxId ? deriveBundleLookupId(this.credentials.primaryInboxId) : null
    );
  }

  getMyBlockListLookupId(): string | null {
    return this.credentials?.primaryBlockListLookupId || (
      this.credentials?.primaryInboxId ? deriveBlockListLookupId(this.credentials.primaryInboxId) : null
    );
  }

  /**
   * Get the local username
   */
  getLocalUsername(): string {
    return this.localUsername;
  }

  /**
   * Create a sealed sender envelope
   */
  async createSealedEnvelope(
    recipientInboxId: string,
    recipientKyberPublicKey: Uint8Array,
    innerPayload: any
  ): Promise<SealedEnvelope> {
    // Prepare inner payload with sender identity
    const innerMessage = {
      from: this.localUsername,
      fromInbox: this.credentials?.primaryInboxId,
      payload: innerPayload,
      timestamp: Date.now(),
      nonce: PostQuantumUtils.uint8ArrayToBase64(PostQuantumRandom.randomBytes(16))
    };

    const rawJson = JSON.stringify(innerMessage);
    const rawBytes = new TextEncoder().encode(rawJson);
    const frameSize = MessageFraming.selectFrameSize(rawBytes.length);
    
    const maxContentSize = MessageFraming.getMaxContentSize(frameSize);
    const paddedPayload = MessageFraming.padJsonPayload(
      innerMessage,
      maxContentSize
    );
    const paddedJson = JSON.stringify(paddedPayload);
    const paddedBytes = new TextEncoder().encode(paddedJson);

    // Create padded frame
    const frame = MessageFraming.createPaddedFrame(paddedBytes, {
      forceFrameSize: frameSize
    });

    // Encrypt with Kyber key encapsulation
    const { ciphertext, sharedSecret } = await PostQuantumKEM.encapsulate(recipientKyberPublicKey);

    const encryptionKey = blake3(sharedSecret, { dkLen: 32 });
    const nonce = PostQuantumRandom.randomBytes(24);
    const encryptedData = await this.encryptWithKey(frame.data, encryptionKey, nonce);
    const finalCiphertext = this.ensureMinSize(encryptedData, MIN_ENVELOPE_SIZE);

    return {
      version: SEALED_ENVELOPE_VERSION,
      ciphertext: PostQuantumUtils.uint8ArrayToBase64(finalCiphertext),
      ephemeralKey: PostQuantumUtils.uint8ArrayToBase64(ciphertext),
      nonce: PostQuantumUtils.uint8ArrayToBase64(nonce)
    };
  }

  createCoverSealedEnvelope(): SealedEnvelope {
    return {
      version: SEALED_ENVELOPE_VERSION,
      ciphertext: PostQuantumUtils.uint8ArrayToBase64(PostQuantumRandom.randomBytes(COVER_CIPHERTEXT_BYTES)),
      ephemeralKey: PostQuantumUtils.uint8ArrayToBase64(PostQuantumRandom.randomBytes(COVER_EPHEMERAL_BYTES)),
      nonce: PostQuantumUtils.uint8ArrayToBase64(PostQuantumRandom.randomBytes(COVER_NONCE_BYTES))
    };
  }

  /**
   * Decrypt a sealed envelope addressed to us
   */
  async openSealedEnvelope(envelope: SealedEnvelope): Promise<{
    from: string;
    fromInbox: string;
    payload: any;
    timestamp: number;
  } | null> {
    if (!this.localKyberKeys) {
      console.error('[BlindRouting] No Kyber keys available for decryption');
      return null;
    }

    if (envelope.version !== SEALED_ENVELOPE_VERSION) {
      console.error('[BlindRouting] Unsupported envelope version:', envelope.version);
      return null;
    }

    try {
      const encapsulatedKey = PostQuantumUtils.base64ToUint8Array(envelope.ephemeralKey);
      const sharedSecret = await PostQuantumKEM.decapsulate(
        encapsulatedKey,
        this.localKyberKeys.secretKey
      );

      // Derive decryption key
      const decryptionKey = blake3(sharedSecret, { dkLen: 32 });

      // Decrypt
      const nonce = PostQuantumUtils.base64ToUint8Array(envelope.nonce);
      const ciphertext = PostQuantumUtils.base64ToUint8Array(envelope.ciphertext);
      const frameData = await this.decryptWithKey(ciphertext, decryptionKey, nonce);

      // Parse frame
      const parsed = MessageFraming.parsePaddedFrame(frameData);
      if (!parsed.valid || !parsed.content) {
        console.error('[BlindRouting] Invalid frame');
        return null;
      }

      // Decode and unpad
      const jsonStr = new TextDecoder().decode(parsed.content);
      const paddedPayload = JSON.parse(jsonStr);
      const innerMessage = MessageFraming.unpadJsonPayload(paddedPayload);

      return {
        from: innerMessage.from,
        fromInbox: innerMessage.fromInbox,
        payload: innerMessage.payload,
        timestamp: innerMessage.timestamp
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * Send a message
   */
  async sendBlindMessage(
    recipientUsername: string,
    payload: any,
    messageType: SignalType = SignalType.CHAT
  ): Promise<boolean> {
    if (!this.sendFn) {
      throw new Error('Send function not configured');
    }

    // Look up peer inbox info
    const peerInbox = this.peerInboxes.get(recipientUsername);
    if (!peerInbox) {
      throw new Error(`No inbox info for peer: ${recipientUsername}`);
    }

    // Create sealed envelope
    const envelope = await this.createSealedEnvelope(
      peerInbox.inboxId,
      peerInbox.kyberPublicKey,
      {
        type: messageType,
        content: payload
      }
    );

    const blindRouteMessage: BlindRouteMessage = {
      type: SignalType.BLIND_ROUTE,
      sealedEnvelope: envelope
    };

    await this.sendFn(blindRouteMessage);
    return true;
  }

  /**
   * Claim our committed route with the server
   */
  async claimInbox(): Promise<boolean> {
    if (!this.sendFn || !this.credentials) {
      return false;
    }

    const inboxId = this.credentials.primaryInboxId;
    const routeId = this.getMyRouteId();
    if (!inboxId || !routeId) return false;

    const claimMessage: any = {
      type: SignalType.CLAIM_INBOX,
      capabilityToken: this.credentials.capabilityToken,
      routeId,
      bundleLookupId: this.getMyBundleLookupId() || routeId,
      blockListLookupId: this.getMyBlockListLookupId() || deriveBlockListLookupId(inboxId)
    };

    if (this.credentials.blindSignature) {
      claimMessage.blindSignature = this.credentials.blindSignature;
      if (this.credentials.blindSignatureKid) {
        claimMessage.blindSignatureKid = this.credentials.blindSignatureKid;
      }
    }

    await this.sendFn(claimMessage);
    return true;
  }

  /**
   * Request in session route commitment rotation
   */
  async rotateRouteCommitments(): Promise<RouteCommitmentRotationResult | null> {
    if (!this.sendFn || !this.credentials) {
      return null;
    }

    const newPrimaryId = this.generateLocalInboxId();
    const newSecondaryId = this.generateLocalInboxId();
    const nextRouteId = deriveRendezvousRouteId(newPrimaryId);
    const nextSecondaryRouteId = deriveRendezvousRouteId(newSecondaryId);
    const nextMailboxLookupId = deriveMailboxMetadataId(newPrimaryId);
    const nextBundleLookupId = deriveBundleLookupId(newPrimaryId);
    const nextBlockListLookupId = deriveBlockListLookupId(newPrimaryId);

    const rotationAck = this.waitForRouteRotationAck();
    await this.sendFn({
      type: SignalType.ROTATE_INBOX,
      capabilityToken: this.credentials.capabilityToken,
      oldRouteIds: [this.getMyRouteId(), this.credentials.secondaryRouteId].filter(isRendezvousRouteId),
      newRouteIds: [nextRouteId, nextSecondaryRouteId],
      oldBundleLookupIds: [this.getMyBundleLookupId()].filter(isRendezvousRouteId),
      newBundleLookupIds: [nextBundleLookupId],
      newBlockListLookupIds: [nextBlockListLookupId]
    });

    const accepted = await rotationAck;
    if (!accepted) {
      return null;
    }

    this.credentials.primaryInboxId = newPrimaryId;
    this.credentials.secondaryInboxId = newSecondaryId;
    this.credentials.primaryRouteId = nextRouteId;
    this.credentials.secondaryRouteId = nextSecondaryRouteId;
    this.credentials.primaryMailboxLookupId = nextMailboxLookupId;
    this.credentials.primaryBundleLookupId = nextBundleLookupId;
    this.credentials.primaryBlockListLookupId = nextBlockListLookupId;

    return {
      primaryInboxId: newPrimaryId,
      secondaryInboxId: newSecondaryId,
      routeId: nextRouteId,
      mailboxLookupId: nextMailboxLookupId,
      bundleLookupId: nextBundleLookupId,
      blockListLookupId: nextBlockListLookupId
    };
  }

  startAutomaticRouteRotation(
    onRotated?: (result: RouteCommitmentRotationResult) => Promise<void> | void
  ): void {
    this.stopAutomaticRouteRotation();

    const schedule = () => {
      const delay = ROUTE_ROTATION_INTERVAL_MS + Math.floor(Math.random() * ROUTE_ROTATION_JITTER_MS);
      this.routeRotationTimer = setTimeout(async () => {
        this.routeRotationTimer = null;
        if (this.routeRotationInFlight) {
          schedule();
          return;
        }
        this.routeRotationInFlight = true;
        try {
          const result = await this.rotateRouteCommitments();
          if (result && onRotated) {
            await onRotated(result);
          }
        } catch (error) {
          console.warn('[BlindRouting] Route commitment rotation failed');
        } finally {
          this.routeRotationInFlight = false;
          if (this.credentials) {
            schedule();
          }
        }
      }, delay);
    };

    if (this.credentials) {
      schedule();
    }
  }

  stopAutomaticRouteRotation(): void {
    if (this.routeRotationTimer) {
      clearTimeout(this.routeRotationTimer);
      this.routeRotationTimer = null;
    }
  }

  private waitForRouteRotationAck(timeoutMs = 15000): Promise<boolean> {
    if (typeof window === 'undefined') {
      return Promise.resolve(true);
    }

    return new Promise<boolean>((resolve) => {
      const cleanup = () => {
        clearTimeout(timeout);
        window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
        window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
      };

      const timeout = setTimeout(() => {
        cleanup();
        resolve(false);
      }, timeoutMs);

      const handler = (ev: Event) => {
        const detail = (ev as CustomEvent).detail;
        if (detail?.type !== SignalType.ROTATE_INBOX_RESPONSE) {
          return;
        }
        cleanup();
        resolve(!!detail.success);
      };

      window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
      window.addEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
    });
  }

  private normalizeCredentials(credentials: BlindRoutingCredentials): BlindRoutingCredentials {
    const normalized = { ...credentials };
    if (normalized.primaryInboxId) {
      normalized.primaryRouteId = normalized.primaryRouteId || deriveRendezvousRouteId(normalized.primaryInboxId);
      normalized.primaryMailboxLookupId = normalized.primaryMailboxLookupId || deriveMailboxMetadataId(normalized.primaryInboxId);
      normalized.primaryBundleLookupId = normalized.primaryBundleLookupId || deriveBundleLookupId(normalized.primaryInboxId);
      normalized.primaryBlockListLookupId = normalized.primaryBlockListLookupId || deriveBlockListLookupId(normalized.primaryInboxId);
    }
    if (normalized.secondaryInboxId) {
      normalized.secondaryRouteId = normalized.secondaryRouteId || deriveRendezvousRouteId(normalized.secondaryInboxId);
    }
    return normalized;
  }

  /**
   * Generate a local inbox ID
   */
  private generateLocalInboxId(): string {
    const entropy = PostQuantumRandom.randomBytes(64);
    const timestamp = new TextEncoder().encode(Date.now().toString());
    const combined = new Uint8Array(entropy.length + timestamp.length);
    combined.set(entropy);
    combined.set(timestamp, entropy.length);

    const hash = blake3(combined, { dkLen: 32 });
    const hex = Array.from(hash).map((b) => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-a${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
  }

  /**
   * Ensure data is at least minimum size
   */
  private ensureMinSize(data: Uint8Array, minSize: number): Uint8Array {
    if (data.length >= minSize) {
      return data;
    }

    const padded = new Uint8Array(minSize);
    padded.set(data);
    const padding = PostQuantumRandom.randomBytes(minSize - data.length);
    padded.set(padding, data.length);
    return padded;
  }

  /**
   * Encrypt data with symmetric key
   */
  private async encryptWithKey(
    data: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array
  ): Promise<Uint8Array> {
    const keyBuffer = new Uint8Array(key).buffer;
    const nonceBuffer = new Uint8Array(nonce).buffer;
    const dataBuffer = new Uint8Array(data).buffer;

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: new Uint8Array(nonceBuffer) },
      cryptoKey,
      new Uint8Array(dataBuffer)
    );

    return new Uint8Array(encrypted);
  }

  /**
   * Decrypt data with symmetric key
   */
  private async decryptWithKey(
    ciphertext: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array
  ): Promise<Uint8Array> {
    const keyBuffer = new Uint8Array(key).buffer;
    const nonceBuffer = new Uint8Array(nonce).buffer;
    const ciphertextBuffer = new Uint8Array(ciphertext).buffer;

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(nonceBuffer) },
      cryptoKey,
      new Uint8Array(ciphertextBuffer)
    );

    return new Uint8Array(decrypted);
  }
}

let blindRoutingClient: BlindRoutingClient | null = null;

export function getBlindRoutingClient(username?: string): BlindRoutingClient {
  if (!blindRoutingClient && username) {
    blindRoutingClient = new BlindRoutingClient(username);
  }
  if (!blindRoutingClient) {
    throw new Error('Blind routing client not initialized');
  }
  return blindRoutingClient;
}

export function resetBlindRoutingClient(): void {
  blindRoutingClient?.stopAutomaticRouteRotation();
  blindRoutingClient = null;
}
