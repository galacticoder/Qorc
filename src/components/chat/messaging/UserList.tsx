export interface User {
  readonly id: string;
  readonly username: string;
  readonly peerCertificateFingerprint?: string;
  readonly peerCertificateVerifiedAt?: number;
  readonly identityRootFingerprint?: string;
  readonly identityBundleFingerprint?: string;
  readonly hybridPublicKeys?: {
    readonly x25519PublicBase64: string;
    readonly kyberPublicBase64: string;
    readonly dilithiumPublicBase64: string;
  };
}
