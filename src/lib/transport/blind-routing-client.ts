/**
 * Blind Routing Client
 */

import { blake3 } from '@noble/hashes/blake3.js';
import { SignalType } from '../types/signal-types';
import { PostQuantumRandom } from '../cryptography/random';
import { PostQuantumUtils } from '../utils/pq-utils';
import { PostQuantumKEM } from '../cryptography/kem';
import { CryptoUtils } from '../utils/crypto-utils';
import { MessageFraming, FrameSize } from './message-framing';
import { MIN_ENVELOPE_SIZE } from '../constants';
import { storage } from '../tauri-bindings';

// Sealed envelope version
const SEALED_ENVELOPE_VERSION = 'ss-v1';

export interface BlindRoutingCredentials {
  capabilityToken: string;
  primaryInboxId?: string;
  secondaryInboxId?: string;
  blindSignature?: string;
  blindSignatureKid?: string;
  ownershipChallenge?: {
    challenge: string;
    commitment: string;
    inboxId: string;
    timestamp: number;
    nonce: string;
    expiresAt: number;
  };
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
  destinationInbox: string;
  sealedEnvelope: SealedEnvelope;
}

export interface PeerInboxInfo {
  inboxId: string;
  kyberPublicKey: Uint8Array;
  dilithiumPublicKey: Uint8Array;
}

/**
 * Blind Routing Client
 * Handles sealed sender envelope creation and routing
 */
export class BlindRoutingClient {
  private credentials: BlindRoutingCredentials | null = null;
  private localUsername: string;
  private localDilithiumKeys: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
  private localKyberKeys: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;

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
    this.credentials = credentials;
    await this.saveCredentials(credentials);
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
      console.error('[BlindRouting] Failed to save credentials:', e);
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
        this.credentials = JSON.parse(raw);
        return this.credentials;
      }
    } catch (e) {
      console.error('[BlindRouting] Failed to load credentials:', e);
    }
    return null;
  }

  /**
   * Set local Dilithium keys for signing ownership proofs
   */
  setDilithiumKeys(keys: { publicKey: Uint8Array; secretKey: Uint8Array }): void {
    this.localDilithiumKeys = keys;
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
    this.peerInboxes.set(username, inboxInfo);
  }

  /**
   * Get current inbox ID for receiving messages
   */
  getMyInboxId(): string | null {
    return this.credentials?.primaryInboxId ?? null;
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

    // Serialize and pad to fixed size
    const maxContentSize = MessageFraming.getMaxContentSize(FrameSize.XLARGE);
    const paddedPayload = MessageFraming.padJsonPayload(
      innerMessage,
      maxContentSize
    );
    const paddedJson = JSON.stringify(paddedPayload);
    const paddedBytes = new TextEncoder().encode(paddedJson);

    // Create padded frame
    const frame = MessageFraming.createPaddedFrame(paddedBytes, {
      forceFrameSize: FrameSize.XLARGE
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
      console.error('[BlindRouting] Failed to open envelope:', error);
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

    // Send in blind route
    const blindRouteMessage: BlindRouteMessage = {
      type: SignalType.BLIND_ROUTE,
      destinationInbox: peerInbox.inboxId,
      sealedEnvelope: envelope
    };

    await this.sendFn(blindRouteMessage);
    return true;
  }

  /**
   * Sign ownership proof for an inbox
   */
  async signOwnershipProof(challenge: string): Promise<string | null> {
    if (!this.localDilithiumKeys) {
      console.error('[BlindRouting] No Dilithium keys for signing');
      return null;
    }

    try {
      const challengeBytes = new TextEncoder().encode(challenge);
      const signature = await CryptoUtils.Dilithium.sign(
        this.localDilithiumKeys.secretKey,
        challengeBytes
      );
      return PostQuantumUtils.uint8ArrayToBase64(signature);
    } catch (error) {
      console.error('[BlindRouting] Failed to sign ownership proof:', error);
      return null;
    }
  }

  /**
   * Claim our inbox with the server
   */
  async claimInbox(): Promise<boolean> {
    if (!this.sendFn || !this.credentials) {
      return false;
    }

    const inboxId = this.credentials.primaryInboxId;
    if (!inboxId) return false;

    const claimMessage: any = {
      type: SignalType.CLAIM_INBOX,
      capabilityToken: this.credentials.capabilityToken,
      inboxId: inboxId,
    };

    let isAuthorized = false;

    if (this.credentials.blindSignature) {
      claimMessage.blindSignature = this.credentials.blindSignature;
      if (this.credentials.blindSignatureKid) {
        claimMessage.blindSignatureKid = this.credentials.blindSignatureKid;
      }
      isAuthorized = true;
    }

    if (!isAuthorized) {
      return false;
    }

    await this.sendFn(claimMessage);
    return true;
  }

  /**
   * Request inbox rotation
   */
  async rotateInboxes(): Promise<{ primary: string; secondary: string } | null> {
    if (!this.sendFn || !this.credentials) {
      return null;
    }

    // Generate new inbox IDs locally
    const newPrimaryId = this.generateLocalInboxId();
    const newSecondaryId = this.generateLocalInboxId();

    await this.sendFn({
      type: SignalType.ROTATE_INBOX,
      capabilityToken: this.credentials.capabilityToken,
      oldInboxIds: [this.credentials.primaryInboxId, this.credentials.secondaryInboxId],
      newInboxIds: [newPrimaryId, newSecondaryId]
    });

    // Update local credentials
    this.credentials.primaryInboxId = newPrimaryId;
    this.credentials.secondaryInboxId = newSecondaryId;

    return { primary: newPrimaryId, secondary: newSecondaryId };
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

    const hash = blake3(combined, { dkLen: 64 });
    return PostQuantumUtils.uint8ArrayToBase64(hash);
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
  blindRoutingClient = null;
}
