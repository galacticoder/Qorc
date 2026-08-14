export interface ServerHybridPublicKeys {
  x25519PublicBase64: string;
  kyberPublicBase64: string;
  dilithiumPublicBase64: string;
}

export interface HybridKeys {
  readonly native: true;
  readonly x25519: { readonly publicKeyBase64: string };
  readonly kyber: { readonly publicKeyBase64: string };
  readonly dilithium: { readonly publicKeyBase64: string };
  readonly accountRoot: { readonly publicKeyBase64: string };
}
