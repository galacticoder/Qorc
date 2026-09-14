import type { ServerKeyMaterial } from '../types/websocket-types';
import { DISCOVERY_LOOKUP_TIMEOUT_MS } from '../../../shared/anonymous-transfer-policy.js';

export interface AnonymousServerContext {
  readonly material: ServerKeyMaterial;
  readonly signal: AbortSignal;
  readonly now: () => number;
}

function copyMaterial(material: ServerKeyMaterial): ServerKeyMaterial {
  return {
    kyberPublicKey: material.kyberPublicKey.slice(),
    dilithiumPublicKey: material.dilithiumPublicKey?.slice(),
    x25519PublicKey: material.x25519PublicKey?.slice(),
    fingerprint: material.fingerprint,
    serverId: material.serverId,
  };
}

function wipeMaterial(material: ServerKeyMaterial): void {
  material.kyberPublicKey.fill(0);
  material.dilithiumPublicKey?.fill(0);
  material.x25519PublicKey?.fill(0);
}

export class AnonymousServerTrust {
  private state: {
    material: ServerKeyMaterial;
    controller: AbortController;
    serverTime: number;
    monotonicTime: number;
  } | null = null;
  private expiryTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(private readonly monotonicNow: () => number = () => performance.now()) {}

  authenticate(material: ServerKeyMaterial, serverTime: number): void {
    if (!material.dilithiumPublicKey || !material.x25519PublicKey ||
      !/^[a-f0-9]{64}$/.test(material.fingerprint) || !Number.isSafeInteger(serverTime) || serverTime < 0) {
      this.invalidate();
      throw new Error('Invalid authenticated anonymous server identity');
    }
    this.expire();
    if (this.state && this.state.material.fingerprint !== material.fingerprint) this.invalidate();
    const controller = this.state?.controller ?? new AbortController();
    if (this.state) wipeMaterial(this.state.material);
    this.state = { material: copyMaterial(material), controller, serverTime, monotonicTime: this.monotonicNow() };
    if (this.expiryTimer !== null) clearTimeout(this.expiryTimer);
    this.expiryTimer = setTimeout(() => this.invalidate(), DISCOVERY_LOOKUP_TIMEOUT_MS);
  }

  invalidate(): void {
    const previous = this.state;
    this.state = null;
    if (this.expiryTimer !== null) clearTimeout(this.expiryTimer);
    this.expiryTimer = null;
    if (previous) {
      wipeMaterial(previous.material);
      previous.controller.abort();
    }
  }

  private expire(): void {
    if (this.state && this.monotonicNow() - this.state.monotonicTime >= DISCOVERY_LOOKUP_TIMEOUT_MS) {
      this.invalidate();
    }
  }

  identity(): AbortSignal | null {
    this.expire();
    return this.state?.controller.signal ?? null;
  }

  now(): number | null {
    this.expire();
    return this.state
      ? this.state.serverTime + Math.floor(this.monotonicNow() - this.state.monotonicTime)
      : null;
  }

  capture(): AnonymousServerContext | null {
    this.expire();
    const state = this.state;
    if (!state) return null;
    const { serverTime, monotonicTime } = state;
    return {
      material: copyMaterial(state.material),
      signal: state.controller.signal,
      now: () => serverTime + Math.floor(this.monotonicNow() - monotonicTime),
    };
  }
}
