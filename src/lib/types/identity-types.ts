import type { PeerCertificateBundle } from './p2p-types';

export const CERTIFIED_IDENTITY_BUNDLE_VERSION = 3 as const;

export type CertifiedIdentityAuthorityModel = 'account-device-chain';
export type CertifiedIdentitySignatureAlgorithm = 'ML-DSA-87';
export type CertifiedIdentityKemAlgorithm = 'ML-KEM-1024';
export type CertifiedIdentityClassicalKeyAgreementAlgorithm = 'X25519';
export type CertifiedIdentitySignalIdentityAlgorithm = 'Signal-X25519';

export interface AccountRootCertV3 {
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

export interface DeviceCertV3 {
  version: typeof CERTIFIED_IDENTITY_BUNDLE_VERSION;
  username: string;
  deviceId: string;
  accountRootFingerprint: string;
  signedBy: 'account-root';
  signatureAlgorithm: CertifiedIdentitySignatureAlgorithm;
  accountRootSignature: string;
  signedPayloadDigest: string;
  attestationFormat: typeof PROTOCOL_KEYS.PEER_CERTIFICATE_ATTESTATION;
  attestationSignature: string;
  attestedPayloadDigest: string;
  deviceDilithiumPublicKey: string;
  deviceKyberPublicKey: string;
  deviceX25519PublicKey: string;
  issuedAt: number;
  expiresAt: number;
  deviceCertificateFingerprint: string;
}

export interface DeviceSubkeyBindingV3 {
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
  signalIdentityX25519PublicKey: string;
  signalPreKeyBundleDigest: string;
  kyberPublicKey: string;
  dilithiumPublicKey: string;
  x25519PublicKey: string;
  issuedAt: number;
  expiresAt: number;
  signedPayloadDigest: string;
  deviceSignature: string;
  bindingFingerprint: string;
}

export interface CertifiedPeerBundleV3 {
  version: typeof CERTIFIED_IDENTITY_BUNDLE_VERSION;
  authorityModel: CertifiedIdentityAuthorityModel;
  username: string;
  accountRoot: AccountRootCertV3;
  deviceCert: DeviceCertV3;
  subkeyBinding: DeviceSubkeyBindingV3;
  peerCertificateFingerprint: string;
  identityRootFingerprint: string;
  bundleFingerprint: string;
}

export interface CertifiedPeerBundleBuildInput {
  username: string;
  publicKeys: {
    kyberPublicBase64: string;
    dilithiumPublicBase64: string;
    x25519PublicBase64: string;
  };
  fullBundle?: unknown;
  peerCertificate: PeerCertificateBundle;
  peerCertificateFingerprint?: string;
  accountRootPublicKey: string;
  signAccountRoot: (canonicalPayload: Uint8Array) => Promise<string>;
  signDevice: (canonicalPayload: Uint8Array) => Promise<string>;
}

export interface CertifiedPeerBundleValidationContext {
  targetHandle?: string;
  publicKeys?: {
    kyberPublicBase64?: string;
    dilithiumPublicBase64?: string;
    x25519PublicBase64?: string;
  };
  fullBundle?: unknown;
  peerCertificate?: PeerCertificateBundle;
  peerCertificateFingerprint?: string;
  now?: number;
  allowExpired?: boolean;
}

export interface CertifiedPeerBundleValidationResult {
  valid: boolean;
  reason?: string;
  bundle?: CertifiedPeerBundleV3;
  identityRootFingerprint?: string;
  bundleFingerprint?: string;
  peerCertificateFingerprint?: string;
}
import { PROTOCOL_KEYS } from '../config/protocol-keys';
