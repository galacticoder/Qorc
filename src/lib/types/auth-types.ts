export interface ServerHybridPublicKeys {
  x25519PublicBase64: string;
  kyberPublicBase64: string;
  dilithiumPublicBase64: string;
  blindPublicKey?: {
    kid: string;
    n: string;
    e: string;
    modulusLength: number;
    hash: string;
    saltLength: number;
    scheme: string;
  };
}

export interface HybridKeys {
  x25519: { private: Uint8Array; publicKeyBase64: string };
  kyber: { publicKeyBase64: string; secretKey: Uint8Array };
  dilithium: { publicKeyBase64: string; secretKey: Uint8Array };
  accountRoot: { publicKeyBase64: string; secretKey: Uint8Array };
}

export interface ServerTrustRequest {
  newKeys: ServerHybridPublicKeys;
  pinned: ServerHybridPublicKeys | null;
}

export type HashParams = {
  salt: string;
  memoryCost: number;
  timeCost: number;
  parallelism: number;
  version?: number;
} | null;

export type MaxStepReached = 'login' | 'server';
