import { SignalType } from './signal-types';
import websocketClient from './websocket';
import { screenSharingSettings } from './screen-sharing-settings';
import {
  PostQuantumKEM,
  PostQuantumHash,
  PostQuantumAEAD,
  PostQuantumRandom,
  PostQuantumSignature,
  PostQuantumUtils,
  SecurityAuditLogger
} from './post-quantum-crypto';
import { syncEncryptedStorage } from './encrypted-storage';
import {
  ScreenSharingSettings,
  SCREEN_SHARING_RESOLUTIONS,
  SCREEN_SHARING_FRAMERATES,
  ScreenSharingFrameRate,
} from './screen-sharing-consts';
import { torNetworkManager } from './tor-network';
import {
  type CallState,
  type CallOffer,
  type CallAnswer,
  type CallSignal,
  CALL_SIGNAL_RATE_WINDOW_MS,
  CALL_SIGNAL_RATE_MAX,
  validateCallSignal,
} from './webrtc-calling-types';
import { EventType } from './event-types';

export type { CallState, CallOffer, CallAnswer, CallSignal };

export class WebRTCCallingService {
  private localStream: MediaStream | null = null;
  private remoteStream: MediaStream | null = null;
  private remoteScreenStream: MediaStream | null = null;
  private screenStream: MediaStream | null = null;
  private screenShareSender: RTCRtpSender | null = null;
  private peerConnection: RTCPeerConnection | null = null;
  private currentCall: CallState | null = null;
  private isScreenSharing: boolean = false;
  private isTogglingScreenShare: boolean = false;
  private isRenegotiating: boolean = false;
  private renegotiationTimeoutId: ReturnType<typeof setTimeout> | null = null;
  private iceConnectionFailureTimeoutId: ReturnType<typeof setTimeout> | null = null;
  private expectingScreenShare: boolean = false;
  private connectedDetectedAtLocal: number | null = null;
  private ringStartAt: number | null = null;
  private localUsername: string = '';
  private preferredCameraDeviceId: string | null = null;
  private pqDeviceKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array } | null = null;
  private pqCallSigningKey: { publicKey: Uint8Array; privateKey: Uint8Array } | null = null;
  private pqSessionKeys: { send: Uint8Array; receive: Uint8Array } | null = null;
  private pqAuditPublicKey: Uint8Array | null = null;
  private pqMediaSessionKeyPair: { keyPair: { publicKey: Uint8Array; privateKey: Uint8Array }; generatedAt: number } | null = null;
  private peerSignatureKeys = new Map<string, Uint8Array>();
  private peerPqKyberKeyCache = new Map<string, { key: string; updatedAt: number }>();
  private kyberRefreshTimestamps = new Map<string, number>();
  private peerHybridKeysCache = new Map<string, { keys: any; updatedAt: number }>();
  private readonly MEDIA_SESSION_KEY_TTL_MS = 5 * 60 * 1000;
  private readonly KYBER_CACHE_TTL_MS = 10 * 60 * 1000;
  private readonly KYBER_REFRESH_BACKOFF_MS = 5_000; // min gap between refresh attempts per peer

  private onIncomingCallCallback: ((call: CallState) => void) | null = null;
  private onCallStateChangeCallback: ((call: CallState) => void) | null = null;
  private onRemoteStreamCallback: ((stream: MediaStream | null) => void) | null = null;
  private onRemoteScreenStreamCallback: ((stream: MediaStream | null) => void) | null = null;
  private onLocalStreamCallback: ((stream: MediaStream) => void) | null = null;

  private rtcConfig: RTCConfiguration;
  private readonly CALL_TIMEOUT = 60000;
  private readonly RING_TIMEOUT = 60000;
  private callTimeoutId: ReturnType<typeof setTimeout> | null = null;
  private auditLogger = SecurityAuditLogger;
  private pendingIceCandidates: RTCIceCandidate[] = [];
  private callSignalHandler: EventListener | null = null;
  private userKeysAvailableHandler: EventListener | null = null;
  private windowCloseHandler: EventListener | null = null;

  private async getOrGenerateSessionKeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
    const now = Date.now();
    if (this.pqMediaSessionKeyPair && now - this.pqMediaSessionKeyPair.generatedAt < this.MEDIA_SESSION_KEY_TTL_MS) {
      return this.pqMediaSessionKeyPair.keyPair;
    }

    const kp = await PostQuantumKEM.generateKeyPair();
    const keyPair = { publicKey: kp.publicKey as Uint8Array, privateKey: (kp as any).secretKey as Uint8Array };
    this.pqMediaSessionKeyPair = { keyPair, generatedAt: now };
    return keyPair;
  }

  private updateSessionKeys(update: { send?: Uint8Array; receive?: Uint8Array }): void {
    if (!this.pqSessionKeys) {
      this.pqSessionKeys = {
        send: update.send ?? PostQuantumRandom.randomBytes(32),
        receive: update.receive ?? PostQuantumRandom.randomBytes(32)
      };
      return;
    }

    if (update.send) {
      this.pqSessionKeys.send = update.send;
    }
    if (update.receive) {
      this.pqSessionKeys.receive = update.receive;
    }
  }

  private async deriveMediaSessionKey(
    keyPair: { publicKey: Uint8Array; privateKey: Uint8Array },
    context: 'screen' | 'camera' | 'audio',
    peer: string
  ): Promise<Uint8Array> {
    const seed = PostQuantumRandom.randomBytes(32);
    const contextBytes = new TextEncoder().encode(`${peer}:${context}:${Date.now()}`);
    const combined = new Uint8Array(seed.length + keyPair.publicKey.length + contextBytes.length);
    combined.set(seed, 0);
    combined.set(keyPair.publicKey, seed.length);
    combined.set(contextBytes, seed.length + keyPair.publicKey.length);
    const derived = PostQuantumHash.blake3(combined, { dkLen: 32 });
    PostQuantumUtils.clearMemory(seed);
    PostQuantumUtils.clearMemory(combined);
    return derived;
  }

  private async encryptDeviceIdPQ(deviceId: string, publicKey: Uint8Array): Promise<string> {
    if (!deviceId) return '';
    if (!publicKey || publicKey.length !== PostQuantumKEM.SIZES.publicKey) {
      throw new Error('Invalid PQ device public key');
    }

    const plaintext = new TextEncoder().encode(deviceId);
    const aad = new TextEncoder().encode('device-id-pq-v2');
    const salt = new TextEncoder().encode('device-id-pq-kem-v1');

    const { ciphertext: kemCiphertext, sharedSecret } = PostQuantumKEM.encapsulate(publicKey);
    let aeadKey: Uint8Array | null = null;
    try {
      aeadKey = PostQuantumHash.deriveKey(sharedSecret, salt, 'device-id-pq-v2', 32);
      const nonce = PostQuantumRandom.randomBytes(36);
      const { ciphertext, tag } = PostQuantumAEAD.encrypt(plaintext, aeadKey, aad, nonce);

      return [
        'v2',
        PostQuantumUtils.uint8ArrayToBase64(kemCiphertext),
        PostQuantumUtils.uint8ArrayToBase64(nonce),
        PostQuantumUtils.uint8ArrayToBase64(ciphertext),
        PostQuantumUtils.uint8ArrayToBase64(tag)
      ].join('.');
    } finally {
      if (aeadKey) {
        PostQuantumUtils.clearMemory(aeadKey);
      }
      PostQuantumUtils.clearMemory(sharedSecret);
    }
  }

  private async decryptDeviceIdPQ(encryptedData: string, privateKey: Uint8Array): Promise<string> {
    if (!encryptedData) return '';
    try {
      const parts = encryptedData.split('.');
      // New format: v2.<kemCiphertext>.<nonce>.<ciphertext>.<tag>
      if (parts[0] === 'v2' && parts.length === 5) {
        if (!privateKey || privateKey.length !== PostQuantumKEM.SIZES.secretKey) {
          return '';
        }
        const kemCiphertext = PostQuantumUtils.base64ToUint8Array(parts[1]);
        const nonce = PostQuantumUtils.base64ToUint8Array(parts[2]);
        const ciphertext = PostQuantumUtils.base64ToUint8Array(parts[3]);
        const tag = PostQuantumUtils.base64ToUint8Array(parts[4]);

        const salt = new TextEncoder().encode('device-id-pq-kem-v1');
        const aad = new TextEncoder().encode('device-id-pq-v2');

        const sharedSecret = PostQuantumKEM.decapsulate(kemCiphertext, privateKey);
        let aeadKey: Uint8Array | null = null;
        try {
          aeadKey = PostQuantumHash.deriveKey(sharedSecret, salt, 'device-id-pq-v2', 32);
          const decrypted = PostQuantumAEAD.decrypt(ciphertext, nonce, tag, aeadKey, aad);
          return new TextDecoder().decode(decrypted);
        } finally {
          if (aeadKey) {
            PostQuantumUtils.clearMemory(aeadKey);
          }
          PostQuantumUtils.clearMemory(sharedSecret);
        }
      }
      return '';
    } catch {
      return '';
    }
  }

  private markConnectedIfConnecting(source: string): void {
    if (this.currentCall && this.currentCall.status === 'connecting') {
      this.currentCall.status = 'connected';
      const now = Date.now();
      this.connectedDetectedAtLocal = now;
      if (!this.currentCall.startTime) {
        this.currentCall.startTime = now;
      }
      if (this.callTimeoutId) {
        clearTimeout(this.callTimeoutId);
        this.callTimeoutId = null;
      }
      const ringStartedAt = this.ringStartAt;
      const details: Record<string, unknown> = { source, startTime: this.currentCall.startTime };
      if (typeof ringStartedAt === 'number' && ringStartedAt > 0) {
        const ringDurationMs = Math.max(0, now - ringStartedAt);
        details.ringDurationMs = ringDurationMs;
      }
      this.logAuditEvent('call-connected', this.currentCall.id, this.currentCall.peer, details);
      this.ringStartAt = null;
      this.onCallStateChangeCallback?.(this.currentCall);
      try {
        this.sendCallSignal({
          type: 'connected',
          callId: this.currentCall.id,
          from: this.localUsername,
          to: this.currentCall.peer,
          data: { connectedAt: this.currentCall.startTime, source },
          timestamp: now
        }).catch(() => { });
      } catch { }
    }
  }

  private async attachSignalSignature(signal: CallSignal): Promise<CallSignal> {
    if (!this.pqCallSigningKey) {
      const kp = await PostQuantumSignature.generateKeyPair();
      this.pqCallSigningKey = { publicKey: new Uint8Array(kp.publicKey), privateKey: new Uint8Array(kp.secretKey) } as any;
    }

    const payload = `${signal.callId}:${signal.type}:${signal.timestamp}:${signal.from}:${signal.to}`;
    const message = new TextEncoder().encode(payload);
    const signature = PostQuantumSignature.sign(message, this.pqCallSigningKey.privateKey);

    return {
      ...signal,
      pqSignature: {
        signature: PostQuantumUtils.uint8ArrayToBase64(signature),
        publicKey: PostQuantumUtils.uint8ArrayToBase64(this.pqCallSigningKey.publicKey)
      }
    };
  }

  private async verifySignalSignature(signal: CallSignal): Promise<boolean> {
    try {
      if (!signal.pqSignature) return false;
      const payload = `${signal.callId}:${signal.type}:${signal.timestamp}:${signal.from}:${signal.to}`;
      const message = new TextEncoder().encode(payload);
      const signature = PostQuantumUtils.base64ToUint8Array(signal.pqSignature.signature);
      const publicKey = PostQuantumUtils.base64ToUint8Array(signal.pqSignature.publicKey);
      this.peerSignatureKeys.set(signal.from, publicKey);
      return PostQuantumSignature.verify(signature, message, publicKey);
    } catch {
      this.logAuditEvent('signature-verify-failed', signal.callId, signal.from, { type: signal.type });
      return false;
    }
  }

  private generatePQDeviceKey(): { publicKey: Uint8Array; privateKey: Uint8Array } {
    const { publicKey, secretKey } = PostQuantumKEM.generateKeyPair();
    return { publicKey, privateKey: secretKey };
  }

  private buildPqAuditEnvelope(data: Record<string, unknown>): string | null {
    if (!this.pqAuditPublicKey || this.pqAuditPublicKey.length !== PostQuantumKEM.SIZES.publicKey) {
      return null;
    }
    try {
      const payloadBytes = new TextEncoder().encode(JSON.stringify(data));
      const aad = new TextEncoder().encode('call-audit-pq-v1');
      const salt = new TextEncoder().encode('call-audit-pq-kem-v1');
      const { ciphertext: kemCiphertext, sharedSecret } = PostQuantumKEM.encapsulate(this.pqAuditPublicKey);
      let aeadKey: Uint8Array | null = null;
      try {
        aeadKey = PostQuantumHash.deriveKey(sharedSecret, salt, 'call-audit-pq-v1', 32);
        const nonce = PostQuantumRandom.randomBytes(36);
        const { ciphertext, tag } = PostQuantumAEAD.encrypt(payloadBytes, aeadKey, aad, nonce);
        return [
          'v1',
          PostQuantumUtils.uint8ArrayToBase64(kemCiphertext),
          PostQuantumUtils.uint8ArrayToBase64(nonce),
          PostQuantumUtils.uint8ArrayToBase64(ciphertext),
          PostQuantumUtils.uint8ArrayToBase64(tag)
        ].join('.');
      } finally {
        if (aeadKey) {
          PostQuantumUtils.clearMemory(aeadKey);
        }
        PostQuantumUtils.clearMemory(sharedSecret);
      }
    } catch {
      return null;
    }
  }

  private logAuditEvent(event: string, callId: string, peer: string, details: Record<string, unknown> = {}): void {
    try {
      const base = { callId, peer, ...details };
      const auditPayload = this.buildPqAuditEnvelope(base);
      this.auditLogger.log('info', event, {
        ...base,
        ...(auditPayload ? { auditPayload } : {})
      });
    } catch {
    }
  }
  constructor(username: string) {
    this.localUsername = username;
    this.rtcConfig = this.getInitialRtcConfig();

    (async () => {
      try {
        try {
          const { encryptedStorage } = await import('./encrypted-storage');
          const storedKeys = await encryptedStorage.getItem('pq_calling_device_keys');
          if (storedKeys) {
            const parsed = typeof storedKeys === 'string' ? JSON.parse(storedKeys) : storedKeys;
            if (parsed?.publicKey && parsed?.privateKey) {
              try {
                const publicKey = PostQuantumUtils.hexToBytes(parsed.publicKey);
                const privateKey = PostQuantumUtils.hexToBytes(parsed.privateKey);
                if (
                  publicKey.length === PostQuantumKEM.SIZES.publicKey &&
                  privateKey.length === PostQuantumKEM.SIZES.secretKey
                ) {
                  this.pqDeviceKeyPair = { publicKey, privateKey };
                } else {
                  this.pqDeviceKeyPair = null;
                }
              } catch {
                this.pqDeviceKeyPair = null;
              }
            }
          }
        } catch { }

        try {
          const { encryptedStorage } = await import('./encrypted-storage');
          const storedCamera = await encryptedStorage.getItem('preferred_camera_deviceId_v1_pq');
          if (storedCamera && this.pqDeviceKeyPair?.privateKey) {
            const encStr = typeof storedCamera === 'string' ? storedCamera : String(storedCamera);
            this.decryptDeviceIdPQ(encStr, this.pqDeviceKeyPair.privateKey)
              .then(deviceId => { this.preferredCameraDeviceId = deviceId; })
              .catch(() => { this.preferredCameraDeviceId = null; });
          }
        } catch { }

        try {
          const { encryptedStorage } = await import('./encrypted-storage');
          const storedAuditKey = await encryptedStorage.getItem('pq_calling_audit_pubkey');
          const keyStr = typeof storedAuditKey === 'string' ? storedAuditKey : null;
          if (keyStr) {
            try { this.pqAuditPublicKey = PostQuantumUtils.hexToBytes(keyStr); } catch { this.pqAuditPublicKey = null; }
          }
        } catch { }

        try {
          const { encryptedStorage } = await import('./encrypted-storage');
          const storedSigning = await encryptedStorage.getItem('pq_call_signing_key_v1');
          if (storedSigning) {
            const parsedSigning = typeof storedSigning === 'string' ? JSON.parse(storedSigning) : storedSigning;
            if (parsedSigning?.publicKey && parsedSigning?.privateKey) {
              this.pqCallSigningKey = {
                publicKey: PostQuantumUtils.base64ToUint8Array(parsedSigning.publicKey),
                privateKey: PostQuantumUtils.base64ToUint8Array(parsedSigning.privateKey)
              };
            }
          }
        } catch { }
      } catch { }
    })();
  }

  async initialize(): Promise<void> {
    SecurityAuditLogger.log('info', 'calling-service-init', { username: this.localUsername });

    const handleWindowClose = () => {
      if (this.currentCall && this.currentCall.status !== 'ended') {
        this.endCall('shutdown').catch(() => { });
      }
    };
    this.windowCloseHandler = handleWindowClose as EventListener;
    window.addEventListener('beforeunload', this.windowCloseHandler);
    window.addEventListener('pagehide', this.windowCloseHandler);

    try {
      const handlerHybrid = (event: Event) => {
        try {
          const { username, hybridKeys } = (event as CustomEvent).detail || {};
          if (typeof username === 'string' && hybridKeys && typeof hybridKeys.kyberPublicBase64 === 'string') {
            this.peerHybridKeysCache.set(username, { keys: hybridKeys, updatedAt: Date.now() });
          }
        } catch { }
      };
      this.userKeysAvailableHandler = handlerHybrid as EventListener;
      window.addEventListener(EventType.USER_KEYS_AVAILABLE, this.userKeysAvailableHandler);
    } catch { }

    if (!this.pqDeviceKeyPair) {
      this.pqDeviceKeyPair = this.generatePQDeviceKey();
      try {
        const { encryptedStorage } = await import('./encrypted-storage');
        await encryptedStorage.setItem('pq_calling_device_keys', JSON.stringify({
          publicKey: PostQuantumUtils.bytesToHex(this.pqDeviceKeyPair.publicKey),
          privateKey: PostQuantumUtils.bytesToHex(this.pqDeviceKeyPair.privateKey)
        }));
      } catch { }
    }

    if (!this.pqCallSigningKey) {
      const kp = await PostQuantumSignature.generateKeyPair();
      this.pqCallSigningKey = { publicKey: new Uint8Array(kp.publicKey), privateKey: new Uint8Array(kp.secretKey) } as any;

      try {
        const { encryptedStorage } = await import('./encrypted-storage');
        await encryptedStorage.setItem('pq_call_signing_key_v1', JSON.stringify({
          publicKey: PostQuantumUtils.uint8ArrayToBase64(this.pqCallSigningKey.publicKey),
          privateKey: PostQuantumUtils.uint8ArrayToBase64(this.pqCallSigningKey.privateKey)
        }));
      } catch { }
    }

    this.setupSignalHandlers();
  }

  async startCall(targetUser: string, callType: 'audio' | 'video' = 'audio'): Promise<string> {
    if (this.currentCall) {
      throw new Error('Another call is already in progress');
    }

    const callId = this.generateCallId();
    await this.resolveRecipientHybridKeys(targetUser);

    this.currentCall = {
      id: callId,
      type: callType,
      direction: 'outgoing',
      status: 'connecting',
      peer: targetUser
    };

    this.ringStartAt = Date.now();
    this.onCallStateChangeCallback?.(this.currentCall);

    try {
      await this.ensurePqSecureMediaReady(targetUser);

      if (!this.currentCall || this.currentCall.id !== callId) {
        throw new Error('Call was cancelled');
      }

      await this.setupLocalMedia(callType);

      if (!this.currentCall || this.currentCall.id !== callId) {
        throw new Error('Call was cancelled');
      }

      await this.createPeerConnection();

      if (!this.currentCall || this.currentCall.id !== callId) {
        throw new Error('Call was cancelled');
      }

      if (this.localStream) {
        this.localStream.getTracks().forEach(track => {
          const sender = this.peerConnection!.addTrack(track, this.localStream!);
          const ctx = track.kind === 'audio' ? 'audio' : 'camera';
          try { this.enablePqE2eeForSender(sender, ctx as any, targetUser); } catch { }
        });
      }

      let offer = await this.peerConnection!.createOffer({
        offerToReceiveAudio: true,
        offerToReceiveVideo: callType === 'video'
      });

      // SDP munging for Opus CBR and bitrate clamp
      offer = { ...offer, sdp: this.mungeOpusForCBR(offer.sdp || '') };
      await this.peerConnection!.setLocalDescription(offer);

      if (!this.currentCall || this.currentCall.id !== callId) {
        throw new Error('Call was cancelled before sending offer');
      }

      await this.sendCallSignal({
        type: 'offer',
        callId,
        from: this.localUsername,
        to: targetUser,
        data: { sdp: offer, callType },
        timestamp: Date.now()
      });

      if (this.currentCall && this.currentCall.id === callId) {
        this.currentCall.status = 'ringing';
        this.onCallStateChangeCallback?.(this.currentCall);

        this.callTimeoutId = setTimeout(() => {
          if (this.currentCall?.status === 'ringing') {
            this.endCall('timeout');
          }
        }, this.CALL_TIMEOUT);
      }

      return callId;

    } catch (_error) {
      console.error('[Calling] Failed to start call:', _error);
      if (this.currentCall && this.currentCall.id === callId) {
        this.endCall('failed');
      }
      throw _error;
    }
  }

  async answerCall(callId: string): Promise<void> {
    if (!this.currentCall || this.currentCall.id !== callId) {
      throw new Error('No matching incoming call found');
    }

    if (!this.peerConnection || this.currentCall.status !== 'ringing') {
      return;
    }
    const signalingState = this.peerConnection.signalingState;
    if (signalingState !== 'have-remote-offer' && signalingState !== 'have-local-pranswer') {
      return;
    }

    try {
      await this.ensurePqSecureMediaReady(this.currentCall.peer);

      await this.setupLocalMedia(this.currentCall.type);

      if (this.localStream && this.peerConnection) {
        this.localStream.getTracks().forEach(track => {
          const sender = this.peerConnection!.addTrack(track, this.localStream!);
          const ctx = track.kind === 'audio' ? 'audio' : 'camera';
          try { this.enablePqE2eeForSender(sender, ctx as any, this.currentCall!.peer); } catch { }
        });
      }

      let answer = await this.peerConnection!.createAnswer();
      answer = { ...answer, sdp: this.mungeOpusForCBR(answer.sdp || '') };
      await this.peerConnection!.setLocalDescription(answer);

      this.currentCall.status = 'connecting';
      this.onCallStateChangeCallback?.(this.currentCall);

      if (this.peerConnection) {
        try {
          const receivers = this.peerConnection.getReceivers();
          for (const receiver of receivers) {
            if (receiver.track && !receiver.track.muted) {
              this.markConnectedIfConnecting('answer-already-unmuted');
              break;
            }
          }
        } catch { }
      }

      await this.sendCallSignal({
        type: 'answer',
        callId,
        from: this.localUsername,
        to: this.currentCall.peer,
        data: { sdp: answer, accepted: true },
        timestamp: Date.now()
      });

    } catch (_error) {
      console.error('[Calling] Failed to answer call:', _error);
      return;
    }
  }

  async declineCall(callId: string): Promise<void> {
    if (!this.currentCall || this.currentCall.id !== callId) {
      return;
    }
    try {
      await this.sendCallSignal({
        type: 'decline-call',
        callId,
        from: this.localUsername,
        to: this.currentCall.peer,
        timestamp: Date.now()
      });
    } catch (err) {
      console.warn('[Calling] Failed to send decline-call signal:', err);
    }

    const now = Date.now();
    this.currentCall.status = 'declined';
    this.currentCall.endTime = now;
    const start = this.currentCall.startTime ?? this.ringStartAt ?? now;
    this.currentCall.startTime = start;
    this.currentCall.duration = Math.max(0, now - start);
    this.onCallStateChangeCallback?.(this.currentCall);

    this.cleanup();
  }

  async endCall(reason: string = 'user'): Promise<void> {
    if (!this.currentCall) {
      return;
    }
    if (this.currentCall.status !== 'ended') {
      try {
        const endTime = Date.now();
        let duration = 0;
        if (this.currentCall.startTime) {
          duration = endTime - this.currentCall.startTime;
        }

        await this.sendCallSignal({
          type: 'end-call',
          callId: this.currentCall.id,
          from: this.localUsername,
          to: this.currentCall.peer,
          data: { reason, duration },
          timestamp: Date.now()
        });

        this.currentCall.endTime = endTime;
        this.currentCall.duration = duration;
      } catch (err) {
        console.warn('[Calling] Failed to send end-call signal:', err);
      }
    }

    this.currentCall.status = 'ended';
    if (!this.currentCall.endTime) {
      this.currentCall.endTime = Date.now();
      if (this.currentCall.startTime) {
        this.currentCall.duration = this.currentCall.endTime - this.currentCall.startTime;
      }
    }

    if (this.currentCall) {
      this.currentCall.endReason = reason as CallState['endReason'];
    }
    this.onCallStateChangeCallback?.(this.currentCall);

    this.cleanup();
  }

  private async replaceOrAddVideoTrack(newVideo: MediaStreamTrack): Promise<void> {
    if (this.peerConnection) {
      const sender = this.peerConnection.getSenders().find(s => s.track && s.track.kind === 'video');
      if (sender) {
        await sender.replaceTrack(newVideo);
      } else {
        this.peerConnection.addTrack(newVideo, new MediaStream([newVideo]));
        await this.renegotiateConnection();
      }
    }
    if (!this.localStream) this.localStream = new MediaStream();
    this.localStream.addTrack(newVideo);
    this.onLocalStreamCallback?.(this.localStream);
  }


  toggleMute(): boolean {
    if (!this.localStream) return false;

    const audioTrack = this.localStream.getAudioTracks()[0];
    if (audioTrack) {
      audioTrack.enabled = !audioTrack.enabled;
      return !audioTrack.enabled;
    }
    return false;
  }

  async toggleVideo(): Promise<boolean> {
    if (!this.localStream) return false;

    let videoTrack = this.localStream.getVideoTracks()[0];

    if (!videoTrack || videoTrack.readyState === 'ended') {
      try {
        if (this.preferredCameraDeviceId) {
          const constraints = {
            video: { deviceId: { exact: this.preferredCameraDeviceId } },
            audio: false
          };
          try {
            const newStream = await navigator.mediaDevices.getUserMedia(constraints);
            const newVideo = newStream.getVideoTracks()[0];
            if (newVideo) {
              await this.replaceOrAddVideoTrack(newVideo);
              videoTrack = newVideo;
            }
          } catch (err) {
            console.error('[Calling] Preferred camera failed to start. strictly aborting.', err);
            return false;
          }
        } else {
          const newStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
          const newVideo = newStream.getVideoTracks()[0];
          if (newVideo) {
            await this.replaceOrAddVideoTrack(newVideo);
            videoTrack = newVideo;
          }
        }
      } catch (_e) {
        console.error('[Calling] Failed to reacquire camera track on toggle:', _e);
        return false;
      }
    }

    videoTrack.enabled = !videoTrack.enabled;
    return videoTrack.enabled;
  }

  async switchCamera(deviceId?: string): Promise<void> {
    if (!this.localStream) return;

    const videoTrack = this.localStream.getVideoTracks()[0];
    if (!videoTrack) return;

    try {
      let newStream: MediaStream;

      if (deviceId) {
        newStream = await navigator.mediaDevices.getUserMedia({
          video: { deviceId: { exact: deviceId } },
          audio: false
        });
      } else {
        const constraints = videoTrack.getConstraints();
        const newFacingMode = constraints.facingMode === 'user' ? 'environment' : 'user';
        newStream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: newFacingMode },
          audio: false
        });
      }

      const newVideoTrack = newStream.getVideoTracks()[0];
      if (this.peerConnection) {
        const sender = this.peerConnection.getSenders().find(s => s.track && s.track.kind === 'video');
        if (sender) {
          await sender.replaceTrack(newVideoTrack);
        }
      }
      this.localStream.removeTrack(videoTrack);
      this.localStream.addTrack(newVideoTrack);
      this.onLocalStreamCallback?.(this.localStream);

    } catch (_error) {
      console.error('[Calling] Failed to switch camera:', _error);
    }
  }

  async switchMicrophone(deviceId: string): Promise<void> {
    if (!this.localStream) return;

    const audioTrack = this.localStream.getAudioTracks()[0];
    if (!audioTrack) return;

    try {
      const newStream = await navigator.mediaDevices.getUserMedia({
        audio: { deviceId: { exact: deviceId } },
        video: false
      });
      const newAudioTrack = newStream.getAudioTracks()[0];

      if (this.peerConnection) {
        const sender = this.peerConnection.getSenders().find(s => s.track && s.track.kind === 'audio');
        if (sender) {
          await sender.replaceTrack(newAudioTrack);
        }
      }

      newAudioTrack.enabled = audioTrack.enabled;
      this.localStream.removeTrack(audioTrack);
      this.localStream.addTrack(newAudioTrack);
      audioTrack.stop();

      this.onLocalStreamCallback?.(this.localStream);
    } catch (_error) {
      console.error('[Calling] Failed to switch microphone:', _error);
      throw _error;
    }
  }

  async startScreenShare(selectedSource?: { id: string; name: string; type?: 'screen' | 'window' }): Promise<void> {
    if (!this.peerConnection) {
      throw new Error('No active call to share screen');
    }

    if (this.currentCall?.status === 'ringing') {
      throw new Error('Cannot start screen sharing during ringing call');
    }

    if (this.isScreenSharing) {
      throw new Error('Screen sharing is already active');
    }

    if (this.isTogglingScreenShare) {
      throw new Error('Screen sharing operation already in progress');
    }

    this.isTogglingScreenShare = true;

    try {
      const electronApi = (window as any).electronAPI || null;
      const edgeApi = (window as any).edgeApi || null;
      const isElectron = !!electronApi || !!edgeApi;
      const getScreenSourcesFn = electronApi?.getScreenSources || edgeApi?.getScreenSources || null;

      this.screenStream = null;

      if (!isElectron || !getScreenSourcesFn || !selectedSource) {
        if (!navigator.mediaDevices?.getDisplayMedia) {
          throw new Error('Screen sharing not supported');
        }
        const videoConstraints = await screenSharingSettings.getVideoConstraints();
        const isLinux = ((window as any).electronAPI?.platform) === 'linux';
        this.screenStream = await navigator.mediaDevices.getDisplayMedia({
          video: videoConstraints,
          audio: isLinux ? false : true
        });
      } else {
        try {
          let screenSource: any = selectedSource;

          if (!screenSource || !screenSource.id) {
            const sources = await getScreenSourcesFn();
            if (!sources || sources.length === 0) {
              throw new Error('No screen sources available');
            }

            screenSource = sources.find((source: any) => source.id.startsWith('screen:'));
            if (!screenSource && sources.length > 0) {
              screenSource = sources[0];
            }
          }

          if (!screenSource || !screenSource.id) {
            throw new Error('No screen sources available');
          }

          const electronConstraints = await screenSharingSettings.getElectronVideoConstraints();
          if (!(electronConstraints as any).mandatory) {
            (electronConstraints as any).mandatory = {};
          }
          (electronConstraints as any).mandatory.chromeMediaSource = 'desktop';
          (electronConstraints as any).mandatory.chromeMediaSourceId = screenSource.id;

          this.screenStream = await navigator.mediaDevices.getUserMedia({
            audio: false,
            video: electronConstraints as MediaTrackConstraints
          });
        } catch (electronError) {
          console.error('[Calling] Electron screen capture failed:', electronError);
          throw new Error(`Failed to capture selected screen source: ${(electronError as Error).message}`);
        }
      }

      if (!this.screenStream) {
        throw new Error('Screen sharing not supported');
      }

      const videoTrack = this.screenStream.getVideoTracks()[0];
      if (!videoTrack) {
        throw new Error('No video track available for screen sharing');
      }

      try {
        const pqKeyPair = await this.getOrGenerateSessionKeyPair();
        (this.screenStream as any)._pqSessionKey = pqKeyPair;
      } catch { }

      try { (videoTrack as any).contentHint = 'detail'; } catch { }
      videoTrack.onended = () => this.stopScreenShare();

      this.screenShareSender = this.peerConnection.addTrack(videoTrack, this.screenStream);

      // Apply PQ E2EE to screen sender
      try {
        if (this.screenShareSender) {
          await this.enablePqE2eeForSender(
            this.screenShareSender,
            'screen',
            this.currentCall?.peer || 'unknown'
          );
        }
      } catch { }

      try {
        if (this.screenShareSender.setParameters) {
          const params: RTCRtpSendParameters = this.screenShareSender.getParameters();
          if (!params.encodings || params.encodings.length === 0) {
            params.encodings = [{}];
          }
          const settings: ScreenSharingSettings = await screenSharingSettings.getSettings();
          let { quality, resolution, frameRate } = settings;
          const fallbackResolution = SCREEN_SHARING_RESOLUTIONS[0];
          if (!SCREEN_SHARING_RESOLUTIONS.some(r => r.id === resolution.id)) {
            resolution = fallbackResolution;
          }
          const allowedFrameRates = SCREEN_SHARING_FRAMERATES as readonly ScreenSharingFrameRate[];
          if (!allowedFrameRates.includes(frameRate as ScreenSharingFrameRate)) {
            frameRate = allowedFrameRates[1];
          }
          const is4k = !resolution.isNative && (resolution.width >= 3840 || resolution.height >= 2160);
          let maxBitrate = 6_000_000;
          if (quality === 'high') maxBitrate = is4k ? 12_000_000 : 8_000_000;
          if (quality === 'low') maxBitrate = 2_500_000;
          if (frameRate <= 15) {
            maxBitrate = Math.min(maxBitrate, 4_000_000);
          } else if (frameRate >= 60) {
            maxBitrate = Math.max(maxBitrate, 8_000_000);
          }
          (params.encodings[0] as any).maxBitrate = maxBitrate;
          (params.encodings[0] as any).scaleResolutionDownBy = 1.0;
          try { await (this.screenShareSender as any).setParameters(params); } catch { }
        }
      } catch { }

      await this.renegotiateConnection();
      this.isScreenSharing = true;

      if (this.localStream) {
        const audioTracks = this.localStream.getAudioTracks();
        const combinedStream = new MediaStream([videoTrack, ...audioTracks]);
        this.onLocalStreamCallback?.(combinedStream);
      } else {
        this.onLocalStreamCallback?.(this.screenStream);
      }

    } catch (_error) {
      console.error('[Calling] Failed to start screen sharing:', _error);
      if (this.screenStream) {
        this.screenStream.getTracks().forEach(track => track.stop());
        this.screenStream = null;
      }
      this.isScreenSharing = false;
      throw _error;
    } finally {
      this.isTogglingScreenShare = false;
    }
  }

  async stopScreenShare(): Promise<void> {
    if (!this.isScreenSharing && !this.screenStream) {
      return;
    }

    if (this.isTogglingScreenShare) {
      let attempts = 0;
      while (this.isTogglingScreenShare && attempts < 50) {
        await new Promise(resolve => setTimeout(resolve, 100));
        attempts++;
      }
      return;
    }

    this.isTogglingScreenShare = true;
    const screenStream = this.screenStream;
    const peerConnection = this.peerConnection;
    const localStream = this.localStream;

    try {
      if (screenStream) {
        screenStream.getTracks().forEach(track => track.stop());
      }

      if (peerConnection && this.screenShareSender) {
        try {
          peerConnection.removeTrack(this.screenShareSender);
        } catch { }
      } else if (localStream && peerConnection) {
        const cameraTrack = localStream.getVideoTracks()[0];
        if (cameraTrack) {
          const sender = peerConnection.getSenders().find(s => s.track && s.track.kind === 'video');
          if (sender) {
            try {
              await sender.replaceTrack(cameraTrack);
            } catch { }
          }
        }
      }

      await this.renegotiateConnection();

      if (localStream) {
        this.onLocalStreamCallback?.(localStream);
      }

    } catch (_error) {
      console.error('[Calling] Failed to stop screen sharing:', _error);
    } finally {
      if (this.screenStream) {
        try {
          this.screenStream.getTracks().forEach(track => {
            if (track.readyState !== 'ended') {
              track.stop();
            }
          });
        } catch { }
        if ((this.screenStream as any)._pqSessionKey) {
          const keyMaterial = (this.screenStream as any)._pqSessionKey;
          try {
            if (keyMaterial?.secretKey) {
              PostQuantumUtils.clearMemory(keyMaterial.secretKey);
            }
            if (keyMaterial?.publicKey) {
              PostQuantumUtils.clearMemory(keyMaterial.publicKey);
            }
          } catch { }
          delete (this.screenStream as any)._pqSessionKey;
        }
        this.screenStream = null;
      }
      this.isScreenSharing = false;
      this.screenShareSender = null;
      this.isTogglingScreenShare = false;
    }
  }

  getScreenSharingStatus(): boolean {
    return this.isScreenSharing;
  }

  private hasInsertableStreamsSupport(): boolean {
    try {
      const sAny: any = (RTCRtpSender as any);
      const rAny: any = (RTCRtpReceiver as any);
      return !!(sAny && sAny.prototype && typeof sAny.prototype.createEncodedStreams === 'function' &&
        rAny && rAny.prototype && typeof rAny.prototype.createEncodedStreams === 'function');
    } catch { return false; }
  }

  private async waitForP2PService(timeoutMs: number): Promise<any | null> {
    const start = Date.now();
    const pollMs = 100;
    while ((Date.now() - start) < timeoutMs) {
      const svc: any = (window as any).p2pService || null;
      if (svc) {
        return svc;
      }
      await new Promise(resolve => setTimeout(resolve, pollMs));
    }
    return null;
  }

  private async ensurePqSecureMediaReady(peer: string): Promise<void> {
    if (!this.hasInsertableStreamsSupport()) {
      throw new Error('Secure media unavailable: insertable streams not supported');
    }

    let svc: any = (window as any).p2pService || null;
    if (!svc) {
      try { window.dispatchEvent(new CustomEvent(EventType.P2P_INIT_REQUIRED, { detail: { source: 'calling', peer } })); } catch { }
      svc = await this.waitForP2PService(15000);
    }
    if (!svc) {
      throw new Error('Secure media unavailable: P2P transport not initialized');
    }

    const hasSession = (): boolean => {
      try {
        const status = typeof svc.getSessionStatus === 'function' ? svc.getSessionStatus(peer) : null;
        const result = !!(status && status.established && status.sendKey && status.receiveKey);
        return result;
      } catch { return false; }
    };

    // Ensure peer connection exists before we wait for PQ keys
    const peers: string[] = typeof svc.getConnectedPeers === 'function' ? svc.getConnectedPeers() : [];
    if (!peers.includes(peer) && typeof svc.connectToPeer === 'function') {
      await svc.connectToPeer(peer);
    }

    if (hasSession()) {
      return;
    }

    // Wait for PQ session to establish
    await new Promise<void>((resolve, reject) => {
      let settled = false;
      const timeoutMs = 90_000;
      const pollIntervalMs = 500;

      const finish = (err?: Error) => {
        if (settled) return;
        settled = true;
        try { clearTimeout(timer); } catch { }
        try { clearInterval(poller); } catch { }
        try { window.removeEventListener(EventType.P2P_PQ_ESTABLISHED, on as EventListener); } catch { }
        if (err) return reject(err);
        resolve();
      };

      let pollCount = 0;
      const poller = setInterval(() => {
        pollCount++;
        if (pollCount % 10 === 0) {
        }
        if (hasSession()) {
          finish();
        }
      }, pollIntervalMs);

      const timer = setTimeout(() => {
        const stats = torNetworkManager.getStats();
        finish(new Error(`Secure media unavailable: PQ session not established (timeout). Tor: ${stats.isConnected ? 'Connected' : 'Disconnected'}, Bootstrapped: ${stats.isBootstrapped ? 'Yes' : 'No'}`));
      }, timeoutMs);

      const on = (e: Event) => {
        const d: any = (e as CustomEvent).detail || {};
        if (d?.peer === peer) {
          finish();
        }
      };

      try {
        window.addEventListener(EventType.P2P_PQ_ESTABLISHED, on as EventListener);
      } catch {
      }
    });


    if (!hasSession()) {
      throw new Error('Secure media unavailable: PQ session not established');
    }
  }

  private deriveMediaKeyFromSession(baseKey: Uint8Array, peer: string, context: 'audio' | 'camera' | 'screen'): Uint8Array {
    const salt = new TextEncoder().encode(`pq-media-salt-v1:${peer}`);
    const info = `pq-media-${context}:${this.currentCall?.id || 'unknown'}`;
    return PostQuantumHash.deriveKey(baseKey, salt, info, 32);
  }

  private KEY_ROTATION_INTERVAL_MS = 10_000; // 10s
  private AUDIO_PADDING_STEP = 128;
  private AUDIO_PADDING_MAX = 4096;

  private epochKey(baseKey: Uint8Array, epoch: number): Uint8Array {
    const epochBytes = new TextEncoder().encode(`epoch:${epoch}`);
    const merged = new Uint8Array(baseKey.length + epochBytes.length);
    merged.set(baseKey, 0);
    merged.set(epochBytes, baseKey.length);
    const out = PostQuantumHash.blake3(merged, { dkLen: 32 });
    PostQuantumUtils.clearMemory(merged);
    return out;
  }

  private nextAudioPaddedSize(len: number): number {
    const step = this.AUDIO_PADDING_STEP;
    const padded = Math.ceil((len + 2) / step) * step;
    return Math.min(padded, this.AUDIO_PADDING_MAX);
  }

  private async enablePqE2eeForSender(sender: RTCRtpSender, context: 'audio' | 'camera' | 'screen', peer: string): Promise<void> {
    try {
      const svc: any = (window as any).p2pService || null;
      if (!svc || typeof svc.getSessionStatus !== 'function') return;
      const status = svc.getSessionStatus(peer);
      if (!status?.established || !status.sendKey) return;
      const baseMediaKey = this.deriveMediaKeyFromSession(status.sendKey as Uint8Array, peer, context);
      const streams = (sender as any).createEncodedStreams ? (sender as any).createEncodedStreams() : null;
      if (!streams) return;
      const readable: ReadableStream<any> = streams.readable;
      const writable: WritableStream<any> = streams.writable;
      const aad = new TextEncoder().encode(`pq-media-${context}-v1`);
      const intervalMs = this.KEY_ROTATION_INTERVAL_MS;

      const transformer = new TransformStream({
        transform: (chunk: any, controller: any) => {
          try {
            const epoch = Math.floor(Date.now() / intervalMs);
            const mediaKey = this.epochKey(baseMediaKey, epoch);
            const data = new Uint8Array(chunk.data);
            const nonce = PostQuantumRandom.randomBytes(36);
            const { ciphertext, tag } = PostQuantumAEAD.encrypt(data, mediaKey, aad, nonce);
            let outBuf: Uint8Array;
            if (context === 'audio') {
              const sealedLen = 36 + ciphertext.length + 32;
              const paddedLen = this.nextAudioPaddedSize(sealedLen);
              outBuf = new Uint8Array(paddedLen);
              new DataView(outBuf.buffer).setUint16(0, sealedLen, false);
              let off = 2;
              outBuf.set(nonce, off); off += 36;
              outBuf.set(ciphertext, off); off += ciphertext.length;
              outBuf.set(tag, off);
            } else {
              const sealed = new Uint8Array(nonce.length + ciphertext.length + 32);
              sealed.set(nonce, 0);
              sealed.set(ciphertext, nonce.length);
              sealed.set(tag, nonce.length + ciphertext.length);
              outBuf = sealed;
            }
            chunk.data = outBuf.buffer;
            controller.enqueue(chunk);
          } catch {
          }
        }
      });
      // @ts-ignore
      readable.pipeThrough(transformer).pipeTo(writable).catch(() => { });

      if (context === 'audio' && typeof sender.getParameters === 'function' && typeof sender.setParameters === 'function') {
        try {
          const params: RTCRtpSendParameters = sender.getParameters();
          if (!params.encodings || params.encodings.length === 0) params.encodings = [{}];
          (params.encodings[0] as any).maxBitrate = 40_000;
          await (sender as any).setParameters(params);
        } catch { }
      }
    } catch { }
  }

  private async enablePqE2eeForReceiver(receiver: RTCRtpReceiver, context: 'audio' | 'camera' | 'screen', peer: string): Promise<void> {
    try {
      const svc: any = (window as any).p2pService || null;
      if (!svc || typeof svc.getSessionStatus !== 'function') return;
      const status = svc.getSessionStatus(peer);
      if (!status?.established || !status.receiveKey) return;
      const baseMediaKey = this.deriveMediaKeyFromSession(status.receiveKey as Uint8Array, peer, context);
      const streams = (receiver as any).createEncodedStreams ? (receiver as any).createEncodedStreams() : null;
      if (!streams) return;
      const readable: ReadableStream<any> = streams.readable;
      const writable: WritableStream<any> = streams.writable;
      const aad = new TextEncoder().encode(`pq-media-${context}-v1`);
      const intervalMs = this.KEY_ROTATION_INTERVAL_MS;

      const transformer = new TransformStream({
        transform: (chunk: any, controller: any) => {
          try {
            const epochNow = Math.floor(Date.now() / intervalMs);
            const currKey = this.epochKey(baseMediaKey, epochNow);
            const prevKey = this.epochKey(baseMediaKey, epochNow - 1);

            const buf = new Uint8Array(chunk.data);
            let nonce: Uint8Array, tag: Uint8Array, ciphertext: Uint8Array;
            if (context === 'audio') {
              if (buf.length < 2) return;
              const sealedLen = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint16(0, false);
              if (sealedLen < 36 + 32 || sealedLen + 2 > buf.length) return;
              const sealed = buf.subarray(2, 2 + sealedLen);
              nonce = sealed.slice(0, 36);
              tag = sealed.slice(sealed.length - 32);
              ciphertext = sealed.slice(36, sealed.length - 32);
            } else {
              if (buf.length < 36 + 32) return;
              nonce = buf.slice(0, 36);
              tag = buf.slice(buf.length - 32);
              ciphertext = buf.slice(36, buf.length - 32);
            }

            let plaintext: Uint8Array | null = null;
            try {
              plaintext = PostQuantumAEAD.decrypt(ciphertext, nonce, tag, currKey, aad);
            } catch {
              try { plaintext = PostQuantumAEAD.decrypt(ciphertext, nonce, tag, prevKey, aad); } catch { plaintext = null; }
            }
            if (!plaintext) return;
            chunk.data = plaintext.buffer;
            controller.enqueue(chunk);
          } catch {
          }
        }
      });
      // @ts-ignore
      readable.pipeThrough(transformer).pipeTo(writable).catch(() => { });
    } catch { }
  }

  private async renegotiateConnection(): Promise<void> {
    if (!this.peerConnection || !this.currentCall) {
      return;
    }

    try {
      this.isRenegotiating = true;
      if (this.peerConnection.signalingState !== 'stable') {
        this.isRenegotiating = false;
        return;
      }

      const offerOptions: RTCOfferOptions = (this.isScreenSharing || (this.currentCall?.type === 'video')) ? { offerToReceiveVideo: true } : {};
      let offer = await this.peerConnection.createOffer(offerOptions);
      offer = { ...offer, sdp: this.mungeOpusForCBR(offer.sdp || '') };
      await this.peerConnection.setLocalDescription(offer);

      await this.sendCallSignal({
        type: 'offer',
        callId: this.currentCall.id,
        from: this.localUsername,
        to: this.currentCall.peer,
        data: offer,
        timestamp: Date.now(),
        isRenegotiation: true
      });

      if (this.renegotiationTimeoutId) {
        clearTimeout(this.renegotiationTimeoutId);
        this.renegotiationTimeoutId = null;
      }
      this.renegotiationTimeoutId = setTimeout(async () => {
        if (!this.peerConnection) return;
        if (this.peerConnection.signalingState === 'have-local-offer') {
          try {
            await this.peerConnection.setLocalDescription({ type: 'rollback' } as RTCSessionDescriptionInit);
          } catch { }
        }
        this.isRenegotiating = false;
      }, 10000);
    } catch (_error) {
      console.error('[Calling] Failed to renegotiate connection:', _error);
      this.isRenegotiating = false;
    }
  }

  async getAvailableScreenSources(): Promise<Array<{ id: string; name: string; type: 'screen' | 'window' }>> {
    try {
      const electronApi = (window as any).electronAPI || null;
      const edgeApi = (window as any).edgeApi || null;
      const getScreenSourcesFn = electronApi?.getScreenSources || edgeApi?.getScreenSources || null;

      if (!getScreenSourcesFn) {
        throw new Error('Screen source selection not available');
      }

      const sources = await getScreenSourcesFn();
      if (!sources || sources.length === 0) {
        throw new Error('No screen sources available');
      }

      return sources.map((source: any) => ({
        id: source.id,
        name: source.name,
        type: source.id.startsWith('screen:') ? 'screen' as const : 'window' as const
      }));
    } catch (_error) {
      console.error('[Calling] Failed to get screen sources:', _error);
      throw _error;
    }
  }

  getCurrentCall(): CallState | null {
    return this.currentCall;
  }

  getRemoteScreenStream(): MediaStream | null {
    return this.remoteScreenStream;
  }

  getPeerConnection(): RTCPeerConnection | null {
    return this.peerConnection;
  }

  private async setupLocalMedia(callType: 'audio' | 'video'): Promise<void> {
    try {
      if (callType === 'video') {
        try {
          const devices = await navigator.mediaDevices.enumerateDevices();
          const videoDevices = devices.filter(device => device.kind === 'videoinput');

          if (videoDevices.length === 0) {
            callType = 'audio';
          }
        } catch { }
      }

      let video: boolean | MediaTrackConstraints = false;
      if (callType === 'video') {
        const base: MediaTrackConstraints = {
          width: { ideal: 1280, max: 1920 },
          height: { ideal: 720, max: 1080 },
          frameRate: { ideal: 30, max: 60 },
          facingMode: 'user'
        };
        if (this.preferredCameraDeviceId) {
          (base as any).deviceId = { exact: this.preferredCameraDeviceId };
        }
        video = base;
      }

      let echoCancellation = true;
      let noiseSuppression = true;
      let preferredMicId: string | null = null;
      try {
        const stored = syncEncryptedStorage.getItem('app_settings_v1');
        if (stored) {
          const parsed = JSON.parse(stored);
          if (parsed.audioSettings) {
            echoCancellation = parsed.audioSettings.echoCancellation ?? true;
            noiseSuppression = parsed.audioSettings.noiseSuppression ?? true;
          }
          // Load default mic from settings
          if (parsed.preferredMicId) {
            preferredMicId = parsed.preferredMicId;
            try {
              const devices = await navigator.mediaDevices.enumerateDevices();
              const micAvailable = devices.some(d => d.kind === 'audioinput' && d.deviceId === preferredMicId);
              if (!micAvailable) {
                preferredMicId = null;
              }
            } catch { }
          }
        }
      } catch { }

      const audioConstraints: MediaTrackConstraints = {
        echoCancellation,
        noiseSuppression,
        autoGainControl: true,
        sampleRate: 48000,
        channelCount: 1
      };
      if (preferredMicId) {
        audioConstraints.deviceId = { ideal: preferredMicId };
      }

      const constraints: MediaStreamConstraints = {
        audio: audioConstraints,
        video
      };

      this.localStream = await navigator.mediaDevices.getUserMedia(constraints);

      const pqKeyPair = await this.getOrGenerateSessionKeyPair();
      (this.localStream as any)._pqSessionKey = pqKeyPair;

      this.onLocalStreamCallback?.(this.localStream);

    } catch (error: any) {
      console.error('[Calling] Failed to get user media:', error);

      let errorMessage = 'Failed to access camera/microphone';
      if (error.name === 'NotFoundError') {
        errorMessage = callType === 'video' ?
          'No camera found' :
          'No microphone found';
      } else if (error.name === 'NotAllowedError') {
        errorMessage = 'Camera/microphone access denied';
      } else if (error.name === 'NotReadableError') {
        errorMessage = 'Camera/microphone is already in use';
      } else if (error.name === 'OverconstrainedError') {
        errorMessage = 'Camera/microphone settings not supported';
      } else if (error.name === 'AbortError') {
        errorMessage = 'Camera/microphone access was interrupted';
      }

      if (callType === 'video') {
        try {
          const audioOnlyConstraints: MediaStreamConstraints = {
            audio: {
              echoCancellation: true,
              noiseSuppression: true,
              autoGainControl: true,
              sampleRate: 48000,
              channelCount: 1
            },
            video: false
          };
          this.localStream = await navigator.mediaDevices.getUserMedia(audioOnlyConstraints);
          this.onLocalStreamCallback?.(this.localStream);
          return;
        } catch (fallbackError: any) {
          console.error('[Calling] Audio-only fallback failed:', fallbackError);
          if (fallbackError.name === 'NotFoundError') {
            errorMessage = 'No camera or microphone found';
          } else if (fallbackError.name === 'NotAllowedError') {
            errorMessage = 'Microphone access denied';
          }
        }
      }
      throw new Error(errorMessage);
    }
  }

  private clearRemoteScreenStream(): void {
    if (this.remoteScreenStream) {
      this.remoteScreenStream = null;
      this.onRemoteScreenStreamCallback?.(null);
    }
  }

  private clearRemoteStream(): void {
    if (this.remoteStream) {
      this.remoteStream = null;
      this.onRemoteStreamCallback?.(null);
    }
  }

  private isScreenShareTrack(settings: MediaTrackSettings): boolean {
    const deviceId = (settings as MediaTrackSettings & { deviceId?: string }).deviceId;
    const isDesktopDeviceId =
      typeof deviceId === 'string' &&
      (deviceId.startsWith('screen:') || deviceId.startsWith('window:'));

    if (isDesktopDeviceId) {
      return true;
    }

    const hasNoFacingMode = !settings.facingMode;
    const hasWidth = typeof settings.width === 'number' && settings.width > 0;
    const hasHeight = typeof settings.height === 'number' && settings.height > 0;
    const isLargeResolution = hasWidth && hasHeight && (settings.width! >= 1280 || settings.height! >= 720);
    const isWideAspectRatio = hasWidth && hasHeight ?
      (settings.width! / settings.height!) > 1.5 : false;

    return hasNoFacingMode && (isLargeResolution || isWideAspectRatio);
  }

  private async createPeerConnection(): Promise<void> {
    this.peerConnection = new RTCPeerConnection(this.rtcConfig);

    this.peerConnection.ontrack = async (event) => {
      let stream: MediaStream;
      if (event.streams && event.streams[0]) {
        stream = event.streams[0];
      } else {
        stream = new MediaStream([event.track]);
      }

      const videoTrack = stream.getVideoTracks()[0];

      if (videoTrack) {
        const settings = videoTrack.getSettings();
        let isScreenShare = false;

        if (this.currentCall?.type === 'audio') {
          isScreenShare = true;
        }
        else if (this.expectingScreenShare) {
          isScreenShare = true;
          this.expectingScreenShare = false;
        } else {
          isScreenShare = this.isScreenShareTrack(settings);
        }

        if (isScreenShare) {
          if (this.remoteScreenStream) {
            this.clearRemoteScreenStream();
          }

          this.remoteScreenStream = stream;

          videoTrack.onended = () => this.clearRemoteScreenStream();
          const handleRemove = () => this.clearRemoteScreenStream();
          try { (stream as any).onremovetrack = handleRemove; } catch { }

          try {
            const pqKeyPair = await this.getOrGenerateSessionKeyPair();
            (stream as any)._pqSessionKey = pqKeyPair;
            const receiveKey = await this.deriveMediaSessionKey(pqKeyPair, 'screen', this.currentCall?.peer || 'unknown');
            this.updateSessionKeys({ receive: receiveKey });
          } catch { }

          // Enable PQ E2EE decrypt on receiver for screen
          try {
            const receiver = event.receiver;
            if (receiver) { await this.enablePqE2eeForReceiver(receiver, 'screen', this.currentCall?.peer || 'unknown'); }
          } catch { }

          this.onRemoteScreenStreamCallback?.(this.remoteScreenStream);
        } else {
          if (this.remoteStream) {
            this.clearRemoteStream();
          }

          this.remoteStream = stream;

          videoTrack.onended = () => this.clearRemoteStream();
          const handleRemoveCam = () => this.clearRemoteStream();
          try { (stream as any).onremovetrack = handleRemoveCam; } catch { }

          try {
            const pqKeyPair = await this.getOrGenerateSessionKeyPair();
            (stream as any)._pqSessionKey = pqKeyPair;
            const receiveKey = await this.deriveMediaSessionKey(pqKeyPair, 'camera', this.currentCall?.peer || 'unknown');
            this.updateSessionKeys({ receive: receiveKey });
          } catch { }

          // Enable PQ E2EE decrypt on receiver for camera/video
          try {
            const receiver = event.receiver;
            if (receiver) { await this.enablePqE2eeForReceiver(receiver, 'camera', this.currentCall?.peer || 'unknown'); }
          } catch { }

          this.onRemoteStreamCallback?.(this.remoteStream);
        }
      } else {
        if (this.remoteStream) {
          this.clearRemoteStream();
        }

        this.remoteStream = stream;

        const audioTrack = stream.getAudioTracks()[0];
        if (audioTrack) {
          audioTrack.onended = () => this.clearRemoteStream();
        }

        // Enable PQ E2EE decrypt on receiver for audio-only streams
        try {
          const receiver = event.receiver;
          if (receiver) { await this.enablePqE2eeForReceiver(receiver, 'audio', this.currentCall?.peer || 'unknown'); }
        } catch { }

        this.onRemoteStreamCallback?.(this.remoteStream);
      }

      const bindUnmute = (t?: MediaStreamTrack, label?: string) => {
        if (!t) return;
        try {
          t.onunmute = () => this.markConnectedIfConnecting(`onunmute:${label}`);
          if (!t.muted) {
            this.markConnectedIfConnecting(`immediate:${label}`);
          }
        } catch { }
      };
      try {
        bindUnmute(stream.getAudioTracks()[0], 'audio');
      } catch { }
      try {
        bindUnmute(stream.getVideoTracks()[0], 'video');
      } catch { }
    };

    this.peerConnection.onconnectionstatechange = () => {
      const state = this.peerConnection?.connectionState;

      if (this.currentCall) {
        switch (state) {
          case 'connected':
            this.markConnectedIfConnecting('pc-connectionstate');
            if (this.iceConnectionFailureTimeoutId) {
              clearTimeout(this.iceConnectionFailureTimeoutId);
              this.iceConnectionFailureTimeoutId = null;
            }
            if (this.renegotiationTimeoutId) {
              clearTimeout(this.renegotiationTimeoutId);
              this.renegotiationTimeoutId = null;
            }
            if (this.isRenegotiating) {
              this.isRenegotiating = false;
            }
            break;
          case 'disconnected':
            if (this.isRenegotiating) {
              if (this.iceConnectionFailureTimeoutId) {
                clearTimeout(this.iceConnectionFailureTimeoutId);
              }
              this.iceConnectionFailureTimeoutId = setTimeout(() => {
                if (this.currentCall?.status !== 'ended' && this.peerConnection?.iceConnectionState === 'disconnected') {
                  this.endCall('connection-lost');
                }
              }, 10000);
            } else if (this.currentCall.status !== 'ended') {
              this.endCall('connection-lost');
            }
            break;
          case 'failed':
          case 'closed':
            if (this.currentCall.status !== 'ended') {
              this.endCall('connection-lost');
            }
            break;
        }
        this.onCallStateChangeCallback?.(this.currentCall);
      }
    };

    // Handle ICE candidates
    this.peerConnection.onicecandidate = async (event) => {
      if (event.candidate && this.currentCall) {
        await this.sendCallSignal({
          type: 'ice-candidate',
          callId: this.currentCall.id,
          from: this.localUsername,
          to: this.currentCall.peer,
          data: event.candidate,
          timestamp: Date.now()
        });
      }
    };

    this.peerConnection.oniceconnectionstatechange = () => {
      const state = this.peerConnection?.iceConnectionState;
      if (this.currentCall) {
        if (state === 'connected' || state === 'completed') {
          if (this.currentCall.status !== 'connected') {
            this.currentCall.status = 'connected';
            if (this.callTimeoutId) {
              clearTimeout(this.callTimeoutId);
              this.callTimeoutId = null;
            }
            if (this.iceConnectionFailureTimeoutId) {
              clearTimeout(this.iceConnectionFailureTimeoutId);
              this.iceConnectionFailureTimeoutId = null;
            }
            this.onCallStateChangeCallback?.(this.currentCall);
          }
        } else if (state === 'checking' && this.currentCall.status === 'ringing') {
          this.currentCall.status = 'connecting';
          this.onCallStateChangeCallback?.(this.currentCall);
        }
      }
    };
  }

  /**
   * Send encrypted call signal through existing secure channel
   */
  private async sendCallSignal(signal: CallSignal): Promise<void> {
    try {
      const signedSignal = await this.attachSignalSignature(signal);
      this.logAuditEvent('call-signal-send', signal.callId, signal.to, { type: signal.type });

      // Try P2P-first signaling if available
      try {
        const reqId = this.generateCallId();
        const tryP2P = new Promise<boolean>((resolve) => {
          let settled = false;
          const timeout = setTimeout(() => { if (!settled) { settled = true; resolve(false); } }, 700);
          const onResult = (e: Event) => {
            try {
              const d: any = (e as CustomEvent).detail || {};
              if (d?.requestId === reqId) {
                if (!settled) { settled = true; }
                clearTimeout(timeout);
                window.removeEventListener(EventType.P2P_CALL_SIGNAL_RESULT, onResult as EventListener);
                resolve(!!d.success);
              }
            } catch { }
          };
          try { window.addEventListener(EventType.P2P_CALL_SIGNAL_RESULT, onResult as EventListener); } catch { }
          try {
            window.dispatchEvent(new CustomEvent(EventType.P2P_CALL_SIGNAL_SEND, {
              detail: { to: signal.to, signal: signedSignal, requestId: reqId }
            }));
          } catch { resolve(false); }
        });
        const ok = await tryP2P;
        if (ok) return;
      } catch { }

      const signalData = {
        messageId: this.generateCallId(),
        from: this.localUsername,
        to: signal.to,
        content: JSON.stringify(signedSignal),
        timestamp: Date.now(),
        messageType: SignalType.SIGNAL_PROTOCOL,
        type: EventType.CALL_SIGNAL
      };

      try {
        const has = await (window as any).edgeApi?.hasSession?.({ selfUsername: this.localUsername, peerUsername: signal.to, deviceId: 1 });
        if (!has?.hasSession) {
          const reqBase = {
            type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
            username: signal.to,
            from: this.localUsername,
            timestamp: Date.now(),
            challenge: (window as any).CryptoUtils?.Base64?.arrayBufferToBase64?.(crypto.getRandomValues(new Uint8Array(32))) || ''
          };
          try { await websocketClient.sendSecureControlMessage(reqBase); } catch { }
          await new Promise<void>((resolve) => {
            const timeout = setTimeout(() => {
              window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, handler as EventListener);
              resolve();
            }, 5000);
            const handler = (e: Event) => {
              const d = (e as CustomEvent).detail;
              if (d?.peer === signal.to) {
                clearTimeout(timeout);
                window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, handler as EventListener);
                resolve();
              }
            };
            window.addEventListener(EventType.LIBSIGNAL_SESSION_READY, handler as EventListener, { once: true });
          });
        }
      } catch { }

      let recipientResolved = await this.resolveRecipientHybridKeys(signal.to);

      if (!recipientResolved && (signal.type === 'end-call' || signal.type === 'decline-call')) {
        await new Promise(resolve => setTimeout(resolve, 500));
        recipientResolved = await this.resolveRecipientHybridKeys(signal.to);
      }

      let recipientKyber = recipientResolved?.kyber || null;
      let recipientHybridKeys = recipientResolved?.hybrid || undefined;

      if (!recipientHybridKeys || !recipientHybridKeys.dilithiumPublicBase64) {
        const errMsg = `Cannot send call signal: missing recipient hybrid keys for ${signal.to}`;
        console.error('[Calling]', errMsg);
        if (signal.type === 'end-call' || signal.type === 'decline-call') {
          return;
        }
        throw new Error(errMsg);
      }

      const attemptEncrypt = async (): Promise<any> => {
        const enc = await (window as any).edgeApi?.encrypt?.({
          fromUsername: this.localUsername,
          toUsername: signal.to,
          plaintext: JSON.stringify(signalData),
          recipientKyberPublicKey: recipientKyber,
          recipientHybridKeys
        });
        return enc;
      };

      let encryptedMessage = await attemptEncrypt();

      if (!encryptedMessage?.success || !encryptedMessage?.encryptedPayload) {
        const maxRetries = 2;
        for (let attempt = 0; attempt < maxRetries && (!encryptedMessage?.success || !encryptedMessage?.encryptedPayload); attempt++) {
          const errorText = String(encryptedMessage?.error || '');
          const isSessionErr = /session|whisper|no valid sessions|invalid whisper message|decryption failed/i.test(errorText);
          if (!isSessionErr) break;
          try {
            await websocketClient.sendSecureControlMessage({
              type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
              username: signal.to,
              from: this.localUsername,
              timestamp: Date.now(),
              reason: 'call-signal-retry'
            });
          } catch { }
          await new Promise<void>((resolve) => {
            let settled = false;
            const timeout = setTimeout(() => { if (!settled) { settled = true; resolve(); } }, 5000);
            const handler = (e: Event) => {
              const d = (e as CustomEvent).detail;
              if (d?.peer === signal.to) {
                if (!settled) { settled = true; clearTimeout(timeout); }
                resolve();
              }
            };
            window.addEventListener(EventType.LIBSIGNAL_SESSION_READY, handler as EventListener, { once: true });
          });

          const reResolved = await this.resolveRecipientHybridKeys(signal.to);
          if (reResolved?.hybrid) {
            recipientResolved = reResolved;
            recipientKyber = reResolved.kyber;
            recipientHybridKeys = reResolved.hybrid;
          }
          encryptedMessage = await attemptEncrypt();
        }
      }

      let encryptedPayload: any;
      if (encryptedMessage?.encryptedPayload) {
        encryptedPayload = encryptedMessage.encryptedPayload;
      } else if (encryptedMessage?.ciphertext) {
        encryptedPayload = {
          from: this.localUsername,
          to: signal.to,
          content: encryptedMessage.ciphertext,
          nonce: encryptedMessage.nonce,
          tag: encryptedMessage.tag,
          mac: encryptedMessage.mac,
          aad: encryptedMessage.aad,
          kemCiphertext: encryptedMessage.kemCiphertext,
          envelopeVersion: encryptedMessage.envelopeVersion,
          messageId: signalData.messageId,
          type: encryptedMessage.type,
          sessionId: encryptedMessage.sessionId
        };
      } else {
        const errMsg = encryptedMessage?.error ? `: ${encryptedMessage.error}` : '';
        throw new Error('Failed to encrypt call signal' + errMsg);
      }

      const payload = {
        type: SignalType.ENCRYPTED_MESSAGE,
        to: signal.to,
        encryptedPayload
      };

      websocketClient.send(JSON.stringify(payload));

    } catch (_error) {
      console.error('[Calling] Failed to send call signal:', (_error as any)?.message || _error);
      throw _error as any;
    }
  }

  // Resolve recipient's static hybrid keys (incl. static ML-KEM Kyber key) for PQ envelope
  private async resolveRecipientHybridKeys(peer: string): Promise<{ kyber: string; hybrid: any } | null> {
    try {
      const now = Date.now();

      const cachedHybrid = this.peerHybridKeysCache.get(peer);
      if (cachedHybrid && now - cachedHybrid.updatedAt < this.KYBER_CACHE_TTL_MS) {
        const kyber = cachedHybrid.keys?.kyberPublicBase64;
        if (typeof kyber === 'string' && kyber.length > 0) {
          this.peerPqKyberKeyCache.set(peer, { key: kyber, updatedAt: cachedHybrid.updatedAt });
          return { kyber, hybrid: cachedHybrid.keys };
        }
      }

      const lastRefresh = this.kyberRefreshTimestamps.get(peer) || 0;
      if (now - lastRefresh < this.KYBER_REFRESH_BACKOFF_MS) {
        const cachedKyber = this.peerPqKyberKeyCache.get(peer);
        const cachedHybrid2 = this.peerHybridKeysCache.get(peer);
        if (cachedKyber && cachedHybrid2?.keys && typeof cachedKyber.key === 'string' && cachedKyber.key.length > 0) {
          return { kyber: cachedKyber.key, hybrid: cachedHybrid2.keys };
        }
        return null;
      }
      this.kyberRefreshTimestamps.set(peer, now);

      try { await websocketClient.sendSecureControlMessage({ type: SignalType.CHECK_USER_EXISTS, username: peer }); } catch { }

      await new Promise<void>((resolve) => {
        let settled = false;
        const timeout = setTimeout(() => { if (!settled) { settled = true; resolve(); } }, 1500);
        const handler = (evt: Event) => {
          const d = (evt as CustomEvent).detail;
          if (d?.username === peer && d?.hybridKeys) {
            window.removeEventListener(EventType.USER_KEYS_AVAILABLE, handler as EventListener);
            if (!settled) {
              settled = true;
              clearTimeout(timeout);
              const updatedAt = Date.now();
              this.peerHybridKeysCache.set(peer, { keys: d.hybridKeys, updatedAt });
              const kyberKeyStr = typeof d.hybridKeys.kyberPublicBase64 === 'string' ? d.hybridKeys.kyberPublicBase64 : '';
              if (kyberKeyStr) {
                this.peerPqKyberKeyCache.set(peer, { key: kyberKeyStr, updatedAt });
              }
              resolve();
            }
          }
        };
        window.addEventListener(EventType.USER_KEYS_AVAILABLE, handler as EventListener, { once: true });
      });

      const updated = this.peerHybridKeysCache.get(peer);
      const kyber2 = updated?.keys?.kyberPublicBase64;
      if (typeof kyber2 === 'string' && kyber2.length > 0) {
        const updatedAt = updated?.updatedAt ?? now;
        this.peerPqKyberKeyCache.set(peer, { key: kyber2, updatedAt });
        return { kyber: kyber2, hybrid: updated!.keys };
      }
      return null;
    } catch {
      return null;
    }
  }

  private mungeOpusForCBR(sdp: string): string {
    try {
      const norm = sdp.replace(/\r\n/g, '\n');
      const lines = norm.split('\n');

      // Collect opus payload types only within audio m= sections
      const opusPts: string[] = [];
      let inAudio = false;
      for (const l of lines) {
        if (l.startsWith('m=')) inAudio = l.startsWith('m=audio');
        if (!inAudio) continue;
        const m = l.match(/^a=rtpmap:(\d+)\s+opus\/(\d+)/i);
        if (m) opusPts.push(m[1]);
      }
      if (opusPts.length === 0) return sdp;

      const ensureFmtp = (pt: string, params: Record<string, string | number>) => {
        const idx = lines.findIndex(l => l.startsWith(`a=fmtp:${pt} `) || l === `a=fmtp:${pt}`);
        const kv = idx >= 0 ? lines[idx].split(' ').slice(1).join(' ') : '';
        const existing: Record<string, string> = {};
        if (kv) {
          kv.split(';').forEach(p => {
            const [k, v] = p.split('=');
            if (k) existing[k.trim()] = (v || '').trim();
          });
        }
        for (const [k, v] of Object.entries(params)) existing[k] = String(v);
        const merged = Object.entries(existing).map(([k, v]) => `${k}=${v}`).join(';');
        const line = `a=fmtp:${pt} ${merged}`;
        if (idx >= 0) {
          lines[idx] = line;
        } else {
          const rtpIdx = lines.findIndex(l => l.startsWith(`a=rtpmap:${pt} `));
          if (rtpIdx >= 0) {
            lines.splice(rtpIdx + 1, 0, line);
          } else {
            const audioIdx = lines.findIndex(l => l.startsWith('m=audio'));
            if (audioIdx >= 0) lines.splice(audioIdx + 1, 0, line); else lines.push(line);
          }
        }
      };

      for (const pt of opusPts) {
        ensureFmtp(pt, {
          stereo: 0,
          sprop_stereo: 0,
          useinbandfec: 1,
          cbr: 1,
          maxaveragebitrate: 32000,
          maxplaybackrate: 48000,
          minptime: 20
        });
      }

      const audioStart = lines.findIndex(l => l.startsWith('m=audio'));
      if (audioStart >= 0) {
        const nextMedia = lines.findIndex((l, idx) => idx > audioStart && l.startsWith('m='));
        const end = nextMedia > audioStart ? nextMedia : lines.length;
        const hasPtime = lines.slice(audioStart, end).some(l => l.startsWith('a=ptime:'));
        if (!hasPtime) lines.splice(audioStart + 1, 0, 'a=ptime:20');
      }

      return lines.join('\r\n');
    } catch {
      return sdp;
    }
  }

  private getInitialRtcConfig(): RTCConfiguration {
    const config: RTCConfiguration = {
      iceServers: [],
      iceCandidatePoolSize: 0,
      bundlePolicy: 'max-bundle',
      rtcpMuxPolicy: 'require',
      iceTransportPolicy: 'all'
    };

    // Fetch ICE config from server API asynchronously
    // This will update rtcConfig when the response arrives
    try {
      let baseHttp = '';
      try {
        const envUrl = (import.meta as any).env?.VITE_WS_URL as string | undefined;
        if (envUrl && typeof envUrl === 'string') {
          const u = new URL(envUrl.replace('ws://', 'http://').replace('wss://', 'https://'));
          baseHttp = `${u.protocol}//${u.host}`;
        }
      } catch { }
      try {
        if (!baseHttp && typeof window !== 'undefined' && window.location?.origin) {
          const { protocol, origin } = window.location as Location;
          if (protocol === 'http:' || protocol === 'https:') {
            baseHttp = origin;
          }
        }
      } catch { }

      if (baseHttp && (baseHttp.startsWith('http://') || baseHttp.startsWith('https://'))) {
        fetch(`${baseHttp}/api/ice/config`, { method: 'GET', credentials: 'omit' })
          .then(async (resp) => {
            if (!resp.ok) return;
            const ice = await resp.json();
            if (ice && Array.isArray(ice.iceServers) && ice.iceServers.length > 0) {
              // Sanitize ICE servers
              const sanitized: RTCIceServer[] = [];
              for (const server of ice.iceServers) {
                const urls = Array.isArray(server.urls) ? server.urls : [server.urls];
                const isTurn = urls.some((url: string) => typeof url === 'string' && (url.startsWith('turn:') || url.startsWith('turns:')));
                const isStun = urls.some((url: string) => typeof url === 'string' && url.startsWith('stun:'));
                if (isTurn && (!server.username || !server.credential)) continue;
                if (isStun || (isTurn && server.username && server.credential)) {
                  sanitized.push(server);
                }
              }

              this.rtcConfig = {
                iceServers: sanitized,
                iceCandidatePoolSize: 0,
                bundlePolicy: 'max-bundle',
                rtcpMuxPolicy: 'require',
                iceTransportPolicy: (ice.iceTransportPolicy === 'relay' || ice.iceTransportPolicy === 'all') ? ice.iceTransportPolicy : 'all'
              };
              SecurityAuditLogger.log('info', 'ice-config-updated-from-server', {
                iceServers: sanitized.length,
                iceTransportPolicy: this.rtcConfig.iceTransportPolicy
              });
            }
          }).catch(() => { });
      }
    } catch { }

    // Sanitize ICE servers: remove TURN without credentials validate all entries
    const sanitized: RTCIceServer[] = [];
    for (const server of (config.iceServers || [])) {
      const urls = Array.isArray(server.urls) ? server.urls : [server.urls];
      const isTurn = urls.some(url => typeof url === 'string' && (url.startsWith('turn:') || url.startsWith('turns:')));
      const isStun = urls.some(url => typeof url === 'string' && url.startsWith('stun:'));

      if (isTurn && (!server.username || !server.credential)) {
        SecurityAuditLogger.log('warn', 'ice-turn-dropped-no-creds', { urls });
        continue;
      }

      if (isStun || (isTurn && server.username && server.credential)) {
        sanitized.push(server);
      }
    }
    config.iceServers = sanitized;

    const hasTurnServer = sanitized.some(server => {
      const urls = Array.isArray(server.urls) ? server.urls : [server.urls];
      return urls.some(url => typeof url === 'string' && (url.startsWith('turn:') || url.startsWith('turns:')));
    });

    if (hasTurnServer && config.iceTransportPolicy === 'all') {
      config.iceTransportPolicy = 'relay';
      SecurityAuditLogger.log('info', 'ice-config-upgraded', { policy: 'relay' });
    }

    if (config.iceTransportPolicy === 'relay' && !hasTurnServer) {
      config.iceTransportPolicy = 'all';
      SecurityAuditLogger.log('warn', 'ice-config-downgraded', { policy: 'all' });
    }

    SecurityAuditLogger.log('info', 'ice-config-final', {
      iceServers: config.iceServers?.length || 0,
      iceTransportPolicy: config.iceTransportPolicy
    });

    return config;
  }

  private setupSignalHandlers(): void {
    let windowStart = Date.now();
    let count = 0;

    const handler = (event: Event) => {
      try {
        const now = Date.now();
        if (now - windowStart > CALL_SIGNAL_RATE_WINDOW_MS) {
          windowStart = now;
          count = 0;
        }
        count += 1;
        if (count > CALL_SIGNAL_RATE_MAX) {
          console.warn('[Calling] Rate limit exceeded for call signals');
          return;
        }

        if (!(event instanceof CustomEvent)) {
          return;
        }

        const signal = validateCallSignal(event.detail);
        if (!signal) {
          console.warn('[Calling] Call signal validation failed:', event.detail);
          return;
        }

        void this.handleCallSignal(signal);
      } catch {
        return;
      }
    };

    this.callSignalHandler = handler as EventListener;
    window.addEventListener(EventType.CALL_SIGNAL, this.callSignalHandler);
  }

  private async handleCallSignal(signal: CallSignal): Promise<void> {
    const isSignatureValid = await this.verifySignalSignature(signal);
    if (!isSignatureValid) {
      console.error('[Calling] Call signal signature invalid:', signal);
      return;
    }

    this.logAuditEvent('call-signal-receive', signal.callId, signal.from, { type: signal.type });

    try {
      switch (signal.type) {
        case 'offer':
          await this.handleCallOffer(signal);
          break;
        case 'answer':
          await this.handleCallAnswer(signal);
          break;
        case 'ice-candidate':
          await this.handleIceCandidate(signal);
          break;
        case 'decline-call':
          this.handleCallDeclined(signal);
          break;
        case 'end-call':
          this.handleCallEnded(signal);
          break;
        case 'connected':
          this.handlePeerConnectedSignal(signal);
          break;
        default:
          console.warn('[Calling] Unknown signal type:', (signal as any).type);
      }
    } catch (_error) {
      console.error('[Calling] Error handling call signal:', (_error as any)?.message || _error);
    }
  }

  private async handleCallOffer(signal: CallSignal): Promise<void> {
    if (this.currentCall) {
      if (signal.isRenegotiation && signal.callId === this.currentCall.id) {
        if (this.currentCall.status === 'ringing') {
          return;
        }

        try {
          if (!this.peerConnection) return;

          this.expectingScreenShare = true;
          setTimeout(() => { this.expectingScreenShare = false; }, 7000);

          if (this.peerConnection.signalingState === 'have-local-offer') {
            try {
              await this.peerConnection.setLocalDescription({ type: 'rollback' } as RTCSessionDescriptionInit);
            } catch { }
          }

          await this.peerConnection.setRemoteDescription(signal.data);
          await this.processPendingIceCandidates();

          let answer = await this.peerConnection.createAnswer();
          answer = { ...answer, sdp: this.mungeOpusForCBR(answer.sdp || '') };
          await this.peerConnection.setLocalDescription(answer);
          await this.sendCallSignal({
            type: 'answer',
            callId: signal.callId,
            from: this.localUsername,
            to: signal.from,
            data: answer,
            timestamp: Date.now(),
            isRenegotiation: true
          });
        } catch (_error) {
          console.error('[Calling] Failed to handle renegotiation offer:', _error);
        }
        return;
      }

      // Already in a call with different ID, decline automatically // to do soon: make it show the call ring other user instead of declining automatically
      await this.sendCallSignal({
        type: 'decline-call',
        callId: signal.callId,
        from: this.localUsername,
        to: signal.from,
        data: { reason: 'busy' },
        timestamp: Date.now()
      });
      return;
    }

    const offerData = signal.data as { sdp: RTCSessionDescriptionInit; callType?: 'audio' | 'video' };

    if (!offerData.callType || (offerData.callType !== 'audio' && offerData.callType !== 'video')) {
      console.warn('[Calling] Rejecting legacy/invalid call offer without explicit type');
      return;
    }

    const sdp = offerData.sdp;
    const callType = offerData.callType;

    await this.resolveRecipientHybridKeys(signal.from);

    this.currentCall = {
      id: signal.callId,
      type: callType,
      direction: 'incoming',
      status: 'ringing',
      peer: signal.from
    };

    this.ringStartAt = Date.now();

    await this.createPeerConnection();

    this.logAuditEvent('call-offer-received', signal.callId, signal.from, { type: callType });
    if (!this.peerConnection) {
      console.error('[Calling] PeerConnection lost during handleCallOffer setup');
      this.cleanup();
      return;
    }
    await this.peerConnection.setRemoteDescription(sdp);

    await this.processPendingIceCandidates();

    this.onIncomingCallCallback?.(this.currentCall);
    this.onCallStateChangeCallback?.(this.currentCall);

    this.callTimeoutId = setTimeout(() => {
      if (this.currentCall?.status === 'ringing') {
        const now = Date.now();
        this.currentCall.status = 'missed';
        this.currentCall.endTime = now;
        const start = this.currentCall.startTime ?? this.ringStartAt ?? now;
        this.currentCall.startTime = start;
        this.currentCall.duration = Math.max(0, now - start);
        this.onCallStateChangeCallback?.(this.currentCall);
        this.sendCallSignal({
          type: 'end-call',
          callId: this.currentCall.id,
          from: this.localUsername,
          to: this.currentCall.peer,
          data: { reason: 'missed' },
          timestamp: now
        }).catch(() => { });
        this.cleanup();
      }
    }, this.RING_TIMEOUT);
  }

  private async handleCallAnswer(signal: CallSignal): Promise<void> {
    if (!this.currentCall || this.currentCall.id !== signal.callId) {
      return;
    }

    if (signal.isRenegotiation) {
      if (this.peerConnection) {
        try {
          const sdp = signal.data as RTCSessionDescriptionInit;
          await this.peerConnection.setRemoteDescription(sdp);
          await this.processPendingIceCandidates();
          this.isRenegotiating = false;
          if (this.renegotiationTimeoutId) {
            clearTimeout(this.renegotiationTimeoutId);
            this.renegotiationTimeoutId = null;
          }
        } catch (_error) {
          console.error('[Calling] Failed to process renegotiation answer:', _error);
        }
      }
      return;
    }

    const answerData = signal.data as { sdp: RTCSessionDescriptionInit; accepted: boolean };

    if (answerData.accepted && this.peerConnection) {
      if (this.callTimeoutId) {
        clearTimeout(this.callTimeoutId);
        this.callTimeoutId = null;
      }

      if (this.currentCall) {
        this.currentCall.status = 'connecting';
        this.onCallStateChangeCallback?.(this.currentCall);
      }

      await this.peerConnection.setRemoteDescription(answerData.sdp);
      await this.processPendingIceCandidates();

      if (this.peerConnection && this.currentCall && this.currentCall.status === 'connecting') {
        try {
          const receivers = this.peerConnection.getReceivers();
          for (const receiver of receivers) {
            if (receiver.track && !receiver.track.muted) {
              this.markConnectedIfConnecting('caller-answer-already-unmuted');
              break;
            }
          }
        } catch { }
      }
    } else {
      this.currentCall.status = 'declined';
      this.currentCall.endTime = Date.now();
      this.onCallStateChangeCallback?.(this.currentCall);
      this.logAuditEvent('call-declined', signal.callId, signal.from);
      this.cleanup();
    }
  }

  private async handleIceCandidate(signal: CallSignal): Promise<void> {
    if (!this.currentCall || this.currentCall.id !== signal.callId || !this.peerConnection) {
      return;
    }

    const candidate = signal.data as RTCIceCandidate;

    if (!this.peerConnection.remoteDescription) {
      this.pendingIceCandidates.push(candidate);
      return;
    }

    try {
      await this.peerConnection.addIceCandidate(candidate);
    } catch (e) {
      console.warn('[Calling] Failed to add ICE candidate:', e);
    }
  }

  private async processPendingIceCandidates(): Promise<void> {
    if (!this.peerConnection || this.pendingIceCandidates.length === 0) {
      return;
    }

    const candidates = [...this.pendingIceCandidates];
    this.pendingIceCandidates = [];

    for (const candidate of candidates) {
      try {
        await this.peerConnection.addIceCandidate(candidate);
      } catch (e) {
        console.warn('[Calling] Failed to add queued ICE candidate:', e);
      }
    }
  }

  private handleCallDeclined(signal: CallSignal): void {
    if (!this.currentCall || this.currentCall.id !== signal.callId) {
      return;
    }

    this.currentCall.status = 'declined';
    this.currentCall.endTime = Date.now();
    this.onCallStateChangeCallback?.(this.currentCall);
    this.cleanup();
  }

  private handlePeerConnectedSignal(signal: CallSignal): void {
    if (!this.currentCall || this.currentCall.id !== signal.callId) {
      return;
    }
    const remoteConnectedAt = typeof (signal.data?.connectedAt) === 'number' ? signal.data.connectedAt : signal.timestamp;

    if (this.callTimeoutId) {
      clearTimeout(this.callTimeoutId);
      this.callTimeoutId = null;
    }

    if (this.currentCall.status === 'ringing' || this.currentCall.status === 'connecting') {
      this.currentCall.status = 'connected';
      const local = this.connectedDetectedAtLocal ?? Date.now();
      this.currentCall.startTime = Math.min(local, remoteConnectedAt);
      this.onCallStateChangeCallback?.(this.currentCall);
      return;
    }

    if (this.currentCall.status === 'connected') {
      const localStart = this.currentCall.startTime ?? this.connectedDetectedAtLocal ?? Date.now();
      const synced = Math.min(localStart, remoteConnectedAt);
      if (Math.abs((this.currentCall.startTime || 0) - synced) > 1000) {
        this.currentCall.startTime = synced;
        this.onCallStateChangeCallback?.(this.currentCall);
      }
    }
  }

  private handleCallEnded(signal: CallSignal): void {
    if (!this.currentCall || this.currentCall.id !== signal.callId) {
      return;
    }

    this.currentCall.status = 'ended';
    this.currentCall.endTime = Date.now();

    if (signal.data?.duration && typeof signal.data.duration === 'number') {
      this.currentCall.duration = signal.data.duration;
    } else if (this.currentCall.startTime) {
      this.currentCall.duration = this.currentCall.endTime - this.currentCall.startTime;
    }

    this.onCallStateChangeCallback?.(this.currentCall);
    this.cleanup();
  }

  private generateCallId(): string {
    const bytes = PostQuantumRandom.randomBytes(16);
    return 'call_' + Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  public destroy(): void {
    if (this.currentCall && this.currentCall.status !== 'ended' && this.currentCall.status !== 'declined' && this.currentCall.status !== 'missed') {
      void this.endCall('shutdown');
    }
    this.cleanup();

    // Remote all window event listeners
    if (this.windowCloseHandler) {
      window.removeEventListener('beforeunload', this.windowCloseHandler);
      window.removeEventListener('pagehide', this.windowCloseHandler);
      this.windowCloseHandler = null;
    }

    if (this.userKeysAvailableHandler) {
      window.removeEventListener(EventType.USER_KEYS_AVAILABLE, this.userKeysAvailableHandler);
      this.userKeysAvailableHandler = null;
    }

    if (this.callSignalHandler) {
      window.removeEventListener(EventType.CALL_SIGNAL, this.callSignalHandler);
      this.callSignalHandler = null;
    }

    this.onIncomingCallCallback = null;
    this.onCallStateChangeCallback = null;
    this.onRemoteStreamCallback = null;
    this.onRemoteScreenStreamCallback = null;
    this.onLocalStreamCallback = null;
  }

  private cleanup(): void {
    if (this.callTimeoutId) {
      clearTimeout(this.callTimeoutId);
      this.callTimeoutId = null;
    }
    if (this.iceConnectionFailureTimeoutId) {
      clearTimeout(this.iceConnectionFailureTimeoutId);
      this.iceConnectionFailureTimeoutId = null;
    }
    if (this.renegotiationTimeoutId) {
      clearTimeout(this.renegotiationTimeoutId);
      this.renegotiationTimeoutId = null;
    }

    const clearPQKeys = (keyMaterial: any) => {
      try {
        if (keyMaterial?.secretKey) {
          PostQuantumUtils.clearMemory(keyMaterial.secretKey);
        }
        if (keyMaterial?.publicKey) {
          PostQuantumUtils.clearMemory(keyMaterial.publicKey);
        }
      } catch { }
    };

    if (this.localStream) {
      this.localStream.getTracks().forEach(track => track.stop());
      if ((this.localStream as any)._pqSessionKey) {
        clearPQKeys((this.localStream as any)._pqSessionKey);
        delete (this.localStream as any)._pqSessionKey;
      }
      this.localStream = null;
    }

    if (this.screenStream) {
      this.screenStream.getTracks().forEach(track => track.stop());
      if ((this.screenStream as any)._pqSessionKey) {
        clearPQKeys((this.screenStream as any)._pqSessionKey);
        delete (this.screenStream as any)._pqSessionKey;
      }
      this.screenStream = null;
    }

    this.screenShareSender = null;

    if (this.peerConnection) {
      this.peerConnection.close();
      this.peerConnection = null;
    }

    this.pendingIceCandidates = [];

    if (this.remoteStream) {
      if ((this.remoteStream as any)._pqSessionKey) {
        clearPQKeys((this.remoteStream as any)._pqSessionKey);
        delete (this.remoteStream as any)._pqSessionKey;
      }
      this.remoteStream = null;
    }
    if (this.remoteScreenStream) {
      if ((this.remoteScreenStream as any)._pqSessionKey) {
        clearPQKeys((this.remoteScreenStream as any)._pqSessionKey);
        delete (this.remoteScreenStream as any)._pqSessionKey;
      }
      this.remoteScreenStream = null;
    }

    this.isScreenSharing = false;
    this.isTogglingScreenShare = false;
    this.pqSessionKeys = null;
    this.currentCall = null;
    this.ringStartAt = null;
    this.connectedDetectedAtLocal = null;
  }

  onIncomingCall(callback: (call: CallState) => void): void {
    this.onIncomingCallCallback = callback;
  }

  onCallStateChange(callback: (call: CallState) => void): void {
    this.onCallStateChangeCallback = callback;
  }

  onRemoteStream(callback: (stream: MediaStream | null) => void): void {
    this.onRemoteStreamCallback = callback;
  }

  onRemoteScreenStream(callback: (stream: MediaStream | null) => void): void {
    this.onRemoteScreenStreamCallback = callback;
  }

  onLocalStream(callback: (stream: MediaStream) => void): void {
    this.onLocalStreamCallback = callback;
  }

  static async getVideoInputDevices(): Promise<MediaDeviceInfo[]> {
    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      return devices.filter(d => d.kind === 'videoinput');
    } catch {
      return [];
    }
  }

  getPreferredCameraDeviceId(): string | null {
    return this.preferredCameraDeviceId;
  }

  async setPreferredCameraDeviceId(deviceId: string): Promise<void> {
    this.preferredCameraDeviceId = deviceId || null;
    if (this.pqDeviceKeyPair) {
      try {
        const encrypted = await this.encryptDeviceIdPQ(deviceId || '', this.pqDeviceKeyPair.publicKey);
        try { const { encryptedStorage } = await import('./encrypted-storage'); await encryptedStorage.setItem('preferred_camera_deviceId_v1_pq', encrypted); } catch { }
      } catch { }
    }

    if (this.peerConnection) {
      try {
        const newStream = await navigator.mediaDevices.getUserMedia({
          video: { deviceId: { exact: deviceId } },
          audio: false
        });
        const newVideo = newStream.getVideoTracks()[0];
        if (newVideo) {
          const sender = this.peerConnection.getSenders().find(s => s.track && s.track.kind === 'video');
          if (sender) {
            await sender.replaceTrack(newVideo);
          }
          if (!this.localStream) {
            this.localStream = new MediaStream([newVideo]);
          } else {
            const old = this.localStream.getVideoTracks()[0];
            if (old) { old.stop(); this.localStream.removeTrack(old); }
            this.localStream.addTrack(newVideo);
          }
          this.onLocalStreamCallback?.(this.localStream);
        }
      } catch (_e) {
        console.error('[Calling] Failed to apply selected camera:', _e);
      }
    }
  }
}
