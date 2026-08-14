/**
 * Blind Routing Client
 */

import { blake3 } from '@noble/hashes/blake3.js';
import { SignalType } from '../types/signal-types';
import { PostQuantumRandom } from '../cryptography/random';
import { PostQuantumUtils } from '../utils/pq-utils';
import { PostQuantumKEM } from '../cryptography/kem';
import { account } from '../tauri-bindings';
import { MessageFraming, FrameSize } from './message-framing';
import {
  AUTH_USERNAME_REGEX,
  PQ_KEM_CIPHERTEXT_SIZE,
  PQ_KEM_PUBLIC_KEY_SIZE
} from '../constants';
import {
  SPOOL_TAG_BYTES,
  encodeSpoolTag,
  untargetedProbeHex,
} from '../../../shared/spool-tag-protocol.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

const SEALED_NONCE_BYTES = 12;
const SEALED_KDF_CONTEXT = new TextEncoder().encode(PROTOCOL_KEYS.SEALED_SENDER_KDF);
const SEALED_AAD_CONTEXT = new TextEncoder().encode(PROTOCOL_KEYS.SEALED_SENDER_AAD);
const COVER_CIPHERTEXT_BYTES = FrameSize.STANDARD + 16;
const COVER_EPHEMERAL_BYTES = PQ_KEM_CIPHERTEXT_SIZE;
const COVER_NONCE_BYTES = SEALED_NONCE_BYTES;

function deriveSealedSenderKey(sharedSecret: Uint8Array): Uint8Array {
  const input = PostQuantumUtils.concatBytes(
    SEALED_KDF_CONTEXT,
    new Uint8Array([0]),
    sharedSecret
  );
  try {
    return blake3(input, { dkLen: 32 });
  } finally {
    input.fill(0);
  }
}

function sealedSenderAdditionalData(kemCiphertext: Uint8Array): Uint8Array {
  return PostQuantumUtils.concatBytes(
    SEALED_AAD_CONTEXT,
    new Uint8Array([0]),
    kemCiphertext
  );
}

export interface SealedEnvelope {
  version: string;
  ciphertext: string;
  ephemeralKey: string;
  nonce: string;
  tag: string;
  probe: string;
}

function randomProbe(): string {
  return untargetedProbeHex();
}

function randomSpoolTag(): string {
  const bytes = PostQuantumRandom.randomBytes(SPOOL_TAG_BYTES);
  try {
    return encodeSpoolTag(bytes);
  } finally {
    bytes.fill(0);
  }
}

/**
 * Blind Routing Client
 * Handles sealed sender envelope creation and routing
 */
export class BlindRoutingClient {
  private localUsername: string;

  private sendFn: ((message: any) => Promise<void>) | null = null;

  constructor(username: string) {
    if (typeof username !== 'string' || username !== username.trim().toLowerCase() || !AUTH_USERNAME_REGEX.test(username)) {
      throw new Error('Invalid blind routing identity');
    }
    this.localUsername = username;
  }

  isCompatible(username: string): boolean {
    return this.localUsername === username;
  }

  get identity(): string {
    return this.localUsername;
  }

  destroy(): void {
    this.sendFn = null;
  }

  /**
   * Set WebSocket send function
   */
  setSendFunction(fn: (message: any) => Promise<void>): void {
    this.sendFn = fn;
  }

  /**
   * Create a sealed sender envelope
   */
  async createSealedEnvelope(
    recipientKyberPublicKey: Uint8Array,
    innerPayload: any,
    options: {
      forceLargeFrame?: boolean;
      forceStandardFrame?: boolean;
      tag?: string;
      probe?: string;
    } = {}
  ): Promise<SealedEnvelope> {
    if (!AUTH_USERNAME_REGEX.test(this.localUsername)) {
      throw new Error('Local routing identity is unavailable');
    }
    if (!(recipientKyberPublicKey instanceof Uint8Array) || recipientKyberPublicKey.length !== PQ_KEM_PUBLIC_KEY_SIZE) {
      throw new Error('Invalid recipient ML-KEM public key');
    }

    const innerMessage = {
      from: this.localUsername,
      payload: innerPayload
    };

    const rawJson = JSON.stringify(innerMessage);
    const rawBytes = new TextEncoder().encode(rawJson);
    if (options.forceLargeFrame && options.forceStandardFrame) {
      rawBytes.fill(0);
      throw new Error('Conflicting sealed sender frame requirements');
    }
    const frameSize = options.forceLargeFrame
      ? FrameSize.XLARGE
      : options.forceStandardFrame
        ? FrameSize.STANDARD
        : MessageFraming.selectFrameSize(rawBytes.length);
    if (rawBytes.length > MessageFraming.getMaxContentSize(frameSize)) {
      rawBytes.fill(0);
      throw new Error('Sealed sender payload exceeds the maximum fixed frame');
    }

    let frame: ReturnType<typeof MessageFraming.createPaddedFrame> | null = null;
    let sharedSecret: Uint8Array | null = null;
    let encryptionKey: Uint8Array | null = null;
    let additionalData: Uint8Array | null = null;
    let nonce: Uint8Array | null = null;
    let kemCiphertext: Uint8Array | null = null;
    let encryptedData: Uint8Array | null = null;
    try {
      frame = MessageFraming.createPaddedFrame(rawBytes, {
        forceFrameSize: frameSize
      });
      const encapsulated = await PostQuantumKEM.encapsulate(recipientKyberPublicKey);
      sharedSecret = encapsulated.sharedSecret;
      kemCiphertext = encapsulated.ciphertext;
      encryptionKey = deriveSealedSenderKey(sharedSecret);
      additionalData = sealedSenderAdditionalData(kemCiphertext);
      nonce = PostQuantumRandom.randomBytes(SEALED_NONCE_BYTES);
      encryptedData = await this.encryptWithKey(frame.data, encryptionKey, nonce, additionalData);

      return {
        version: PROTOCOL_KEYS.SEALED_ENVELOPE_VERSION,
        ciphertext: PostQuantumUtils.uint8ArrayToBase64(encryptedData),
        ephemeralKey: PostQuantumUtils.uint8ArrayToBase64(kemCiphertext),
        nonce: PostQuantumUtils.uint8ArrayToBase64(nonce),
        tag: options.tag ?? randomSpoolTag(),
        probe: options.probe ?? randomProbe()
      };
    } finally {
      rawBytes.fill(0);
      frame?.data.fill(0);
      sharedSecret?.fill(0);
      encryptionKey?.fill(0);
      additionalData?.fill(0);
      nonce?.fill(0);
      kemCiphertext?.fill(0);
      encryptedData?.fill(0);
    }
  }

  createCoverSealedEnvelope(): SealedEnvelope {
    const ciphertext = PostQuantumRandom.randomBytes(COVER_CIPHERTEXT_BYTES);
    const ephemeralKey = PostQuantumRandom.randomBytes(COVER_EPHEMERAL_BYTES);
    const nonce = PostQuantumRandom.randomBytes(COVER_NONCE_BYTES);
    try {
      return {
        version: PROTOCOL_KEYS.SEALED_ENVELOPE_VERSION,
        ciphertext: PostQuantumUtils.uint8ArrayToBase64(ciphertext),
        ephemeralKey: PostQuantumUtils.uint8ArrayToBase64(ephemeralKey),
        nonce: PostQuantumUtils.uint8ArrayToBase64(nonce),
        tag: randomSpoolTag(),
        probe: randomProbe()
      };
    } finally {
      ciphertext.fill(0);
      ephemeralKey.fill(0);
      nonce.fill(0);
    }
  }

  /**
   * Decrypt a sealed envelope addressed to us
   */
  async openSealedEnvelope(envelope: SealedEnvelope): Promise<{
    from: string;
    payload: any;
  } | null> {
    const opened = await account.openSealedEnvelope(envelope);
    if (
      !opened ||
      typeof opened.from !== 'string' ||
      !opened.payload ||
      typeof opened.payload !== 'object' ||
      Array.isArray(opened.payload)
    ) return null;
    return { from: opened.from, payload: opened.payload };
  }

  /** Activate this authorized socket as a recipient of the global mix stream. */
  async activateDelivery(requestId: string): Promise<boolean> {
    if (!this.sendFn) {
      return false;
    }
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(requestId)) {
      return false;
    }
    const activationMessage = {
      type: SignalType.ACTIVATE_DELIVERY,
      requestId
    };

    await this.sendFn(activationMessage);
    return true;
  }

  // Encrypt data with symmetric key
  private async encryptWithKey(
    data: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array,
    additionalData: Uint8Array
  ): Promise<Uint8Array> {
    const keyBytes = new Uint8Array(key);
    const nonceBytes = new Uint8Array(nonce);
    const dataBytes = new Uint8Array(data);
    const aadBytes = new Uint8Array(additionalData);
    try {
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyBytes.buffer,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
      );
      const encrypted = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: nonceBytes.buffer,
          additionalData: aadBytes.buffer
        },
        cryptoKey,
        dataBytes.buffer
      );
      return new Uint8Array(encrypted);
    } finally {
      keyBytes.fill(0);
      nonceBytes.fill(0);
      dataBytes.fill(0);
      aadBytes.fill(0);
    }
  }

}

let blindRoutingClient: BlindRoutingClient | null = null;

export function getBlindRoutingClient(username?: string): BlindRoutingClient {
  if (blindRoutingClient && username && !blindRoutingClient.isCompatible(username)) {
    blindRoutingClient.destroy();
    blindRoutingClient = null;
  }
  if (!blindRoutingClient && username) {
    blindRoutingClient = new BlindRoutingClient(username);
  }
  if (!blindRoutingClient) {
    throw new Error('Blind routing client not initialized');
  }
  return blindRoutingClient;
}

export function resetBlindRoutingClient(): void {
  blindRoutingClient?.destroy();
  blindRoutingClient = null;
}
