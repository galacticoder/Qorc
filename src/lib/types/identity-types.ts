import type { PeerCertificateBundle } from './p2p-types';

export const CERTIFIED_IDENTITY_BUNDLE_VERSION = 2 as const;

export type CertifiedIdentityAuthorityModel = 'account-device-chain';
export type CertifiedIdentitySignatureAlgorithm = 'ML-DSA-87';
export type CertifiedIdentityKemAlgorithm = 'ML-KEM-1024';
export type CertifiedIdentityClassicalKeyAgreementAlgorithm = 'X25519';
export type CertifiedIdentitySignalIdentityAlgorithm = 'Signal-X25519';

export interface AccountRootCertV2 {
  version: typeof CERTIFIED_IDENTITY_BUNDLE_VERSION;
  authorityModel: CertifiedIdentityAuthorityModel;
  username: string;
  algorithm: CertifiedIdentitySignatureAlgorithm;
  accountRootPublicKey: string;
  issuedAt: number;
  expiresAt: number;
  signedPayloadDigest: string;
  rootSelfSignature: string;
  rootFingerprint: string;
}

export interface DeviceCertV2 {
  version: typeof CERTIFIED_IDENTITY_BUNDLE_VERSION;
  username: string;
  deviceId: string;
  accountRootFingerprint: string;
  signedBy: 'account-root';
  signatureAlgorithm: CertifiedIdentitySignatureAlgorithm;
  accountRootSignature: string;
  signedPayloadDigest: string;
  attestationFormat: 'qor-peer-certificate-v2';
  attestationSignature: string;
  attestedPayloadDigest: string;
  deviceDilithiumPublicKey: string;
  deviceKyberPublicKey: string;
  deviceX25519PublicKey: string;
  issuedAt: number;
  expiresAt: number;
  deviceCertificateFingerprint: string;
}

export interface DeviceSubkeyBindingV2 {
  version: typeof CERTIFIED_IDENTITY_BUNDLE_VERSION;
  username: string;
  deviceId: string;
  accountRootFingerprint: string;
  deviceCertificateFingerprint: string;
  algorithms: {
    signature: CertifiedIdentitySignatureAlgorithm;
    kem: CertifiedIdentityKemAlgorithm;
    classicalKeyAgreement: CertifiedIdentityClassicalKeyAgreementAlgorithm;
    signalIdentity: CertifiedIdentitySignalIdentityAlgorithm;
  };
  inboxId: string;
  signalIdentityX25519PublicKey: string;
  kyberPublicKey: string;
  dilithiumPublicKey: string;
  x25519PublicKey: string;
  p2pEndpointUrl?: string;
  issuedAt: number;
  expiresAt: number;
  signedPayloadDigest: string;
  deviceSignature: string;
  bindingFingerprint: string;
}

export interface CertifiedPeerBundleV2 {
  version: typeof CERTIFIED_IDENTITY_BUNDLE_VERSION;
  authorityModel: CertifiedIdentityAuthorityModel;
  username: string;
  accountRoot: AccountRootCertV2;
  deviceCert: DeviceCertV2;
  subkeyBinding: DeviceSubkeyBindingV2;
  peerCertificateFingerprint: string;
  identityRootFingerprint: string;
  bundleFingerprint: string;
  generatedAt: number;
}

export interface CertifiedPeerBundleBuildInput {
  username: string;
  inboxId: string;
  publicKeys: {
    kyberPublicBase64: string;
    dilithiumPublicBase64: string;
    x25519PublicBase64: string;
  };
  fullBundle?: unknown;
  peerCertificate: PeerCertificateBundle;
  peerCertificateFingerprint?: string;
  accountRootPublicKey: string;
  accountRootSecretKey: Uint8Array;
  deviceDilithiumSecretKey: Uint8Array;
}

export interface CertifiedPeerBundleValidationContext {
  targetHandle?: string;
  inboxId?: string;
  publicKeys?: {
    kyberPublicBase64?: string;
    dilithiumPublicBase64?: string;
    x25519PublicBase64?: string;
  };
  fullBundle?: unknown;
  peerCertificate?: PeerCertificateBundle;
  peerCertificateFingerprint?: string;
  now?: number;
}

export interface CertifiedPeerBundleValidationResult {
  valid: boolean;
  reason?: string;
  bundle?: CertifiedPeerBundleV2;
  identityRootFingerprint?: string;
  bundleFingerprint?: string;
  peerCertificateFingerprint?: string;
}
