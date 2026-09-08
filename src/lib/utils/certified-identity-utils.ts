import { blake3 } from '@noble/hashes/blake3.js';
import { AUTH_USERNAME_REGEX, CERT_CLOCK_SKEW_MS } from '../constants';
import type {
  AccountRootCert,
  CertifiedPeerBundleBuildInput,
  CertifiedPeerBundle,
  CertifiedPeerBundleValidationContext,
  CertifiedPeerBundleValidationResult,
  DeviceCert,
  DeviceSubkeyBinding
} from '../types/identity-types';
import { CERTIFIED_IDENTITY_BUNDLE_VERSION } from '../types/identity-types';
import type { PeerCertificateBundle } from '../types/p2p-types';
import { hasExactObjectKeys } from '../sanitizers';
import { CryptoUtils } from './crypto-utils';
import { bytesToHex } from './byte-utils';
import {
  computePeerCertificateFingerprint,
  encodePeerCertificateSigningPayload,
  extractStaticMlKemFromSignalBundle,
  extractX25519FromSignalBundle,
  validatePeerCertificateBundle
} from './peer-certificate-utils';
import {
  isCanonicalBase64OfLength,
  isValidDilithiumPublicKeyBase64,
  isValidDilithiumSignatureBase64,
  isValidKyberPublicKeyBase64,
  isValidX25519PublicKeyBase64
} from './messaging-validators';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

const textEncoder = new TextEncoder();
const HEX_64 = /^[a-f0-9]{64}$/i;
const ACCOUNT_ROOT_KEYS = [
  'version', 'authorityModel', 'username', 'algorithm', 'accountRootPublicKey',
  'issuedAt', 'expiresAt', 'signedPayloadDigest', 'rootSelfSignature', 'rootFingerprint'
] as const;
const DEVICE_CERT_KEYS = [
  'version', 'username', 'deviceId', 'accountRootFingerprint', 'signedBy',
  'signatureAlgorithm', 'accountRootSignature', 'signedPayloadDigest',
  'attestationFormat', 'attestationSignature', 'attestedPayloadDigest',
  'deviceDilithiumPublicKey', 'deviceKyberPublicKey', 'deviceX25519PublicKey',
  'issuedAt', 'expiresAt', 'deviceCertificateFingerprint'
] as const;
const SUBKEY_BINDING_KEYS = [
  'version', 'username', 'deviceId', 'accountRootFingerprint',
  'deviceCertificateFingerprint', 'algorithms', 'signalIdentityX25519PublicKey',
  'signalPreKeyBundleDigest', 'kyberPublicKey', 'dilithiumPublicKey',
  'x25519PublicKey', 'issuedAt', 'expiresAt', 'signedPayloadDigest',
  'deviceSignature', 'bindingFingerprint'
] as const;
const BINDING_ALGORITHM_KEYS = [
  'signature', 'kem', 'classicalKeyAgreement', 'signalIdentity'
] as const;
const CERTIFIED_BUNDLE_KEYS = [
  'version', 'authorityModel', 'username', 'accountRoot', 'deviceCert',
  'subkeyBinding', 'peerCertificateFingerprint', 'identityRootFingerprint',
  'bundleFingerprint'
] as const;

const SIGNAL_BUNDLE_KEYS = [
  'registrationId', 'deviceId', 'identityKeyBase64', 'signedPreKey',
  'mlKemPreKey', 'staticMlKem'
] as const;
const SIGNAL_SIGNED_PREKEY_KEYS = [
  'keyId', 'publicKeyBase64', 'signatureBase64'
] as const;
const SIGNAL_STATIC_ML_KEM_KEYS = ['publicKeyBase64', 'signatureBase64'] as const;

function hasSerializedKeyTag(value: string, expectedBytes: number, tag: number): boolean {
  if (!isCanonicalBase64OfLength(value, expectedBytes)) return false;
  let bytes: Uint8Array | null = null;
  try {
    bytes = CryptoUtils.Base64.base64ToUint8Array(value);
    return bytes[0] === tag;
  } catch {
    return false;
  } finally {
    bytes?.fill(0);
  }
}

function isValidSignalPreKeyBundle(value: unknown): boolean {
  if (!hasExactObjectKeys(value, SIGNAL_BUNDLE_KEYS)) return false;
  const bundle = value as Record<string, unknown>;
  if (
    !Number.isSafeInteger(bundle.registrationId) ||
    (bundle.registrationId as number) < 1 ||
    (bundle.registrationId as number) > 16_380 ||
    !Number.isSafeInteger(bundle.deviceId) ||
    (bundle.deviceId as number) < 1 ||
    (bundle.deviceId as number) > 127 ||
    !hasSerializedKeyTag(bundle.identityKeyBase64 as string, 33, 0x05)
  ) {
    return false;
  }
  const signedPreKey = bundle.signedPreKey;
  const mlKemPreKey = bundle.mlKemPreKey;
  const staticMlKem = bundle.staticMlKem;
  if (
    !hasExactObjectKeys(signedPreKey, SIGNAL_SIGNED_PREKEY_KEYS) ||
    !hasExactObjectKeys(mlKemPreKey, SIGNAL_SIGNED_PREKEY_KEYS) ||
    !hasExactObjectKeys(staticMlKem, SIGNAL_STATIC_ML_KEM_KEYS)
  ) {
    return false;
  }
  const signed = signedPreKey as Record<string, unknown>;
  const mlKem = mlKemPreKey as Record<string, unknown>;
  const staticKey = staticMlKem as Record<string, unknown>;
  return (
    Number.isSafeInteger(signed.keyId) &&
    (signed.keyId as number) >= 0 &&
    (signed.keyId as number) <= 0xffff_ffff &&
    hasSerializedKeyTag(signed.publicKeyBase64 as string, 33, 0x05) &&
    isCanonicalBase64OfLength(signed.signatureBase64, 64) &&
    Number.isSafeInteger(mlKem.keyId) &&
    (mlKem.keyId as number) >= 0 &&
    (mlKem.keyId as number) <= 0xffff_ffff &&
    hasSerializedKeyTag(mlKem.publicKeyBase64 as string, 1569, 0x0a) &&
    isCanonicalBase64OfLength(mlKem.signatureBase64, 64) &&
    isValidKyberPublicKeyBase64(staticKey.publicKeyBase64) &&
    isCanonicalBase64OfLength(staticKey.signatureBase64, 64)
  );
}

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

function stableNormalize(value: unknown): JsonValue {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (Array.isArray(value)) return value.map((item) => stableNormalize(item));
  if (typeof value === 'object') {
    const out: Record<string, JsonValue> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const normalized = stableNormalize((value as Record<string, unknown>)[key]);
      if (normalized !== null) out[key] = normalized;
    }
    return out;
  }
  return null;
}

export function canonicalIdentityJson(value: unknown): string {
  return JSON.stringify(stableNormalize(value));
}

function fingerprintBytes(domain: string, bytes: Uint8Array): string {
  return bytesToHex(blake3(new Uint8Array([
    ...textEncoder.encode(domain),
    0,
    ...bytes
  ]), { dkLen: 32 }));
}

export function fingerprintIdentityObject(domain: string, value: unknown): string {
  return fingerprintBytes(domain, textEncoder.encode(canonicalIdentityJson(value)));
}

function normalizeHandle(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function requireValidTimeWindow(
  issuedAt: unknown,
  expiresAt: unknown,
  now: number,
  allowExpired: boolean,
): string | null {
  if (!Number.isFinite(issuedAt as number) || !Number.isFinite(expiresAt as number)) {
    return 'INVALID_CERTIFICATE_TIME';
  }
  const issued = Math.trunc(issuedAt as number);
  const expires = Math.trunc(expiresAt as number);
  if (expires <= issued) return 'INVALID_CERTIFICATE_WINDOW';
  if (issued > now + CERT_CLOCK_SKEW_MS) return 'CERTIFICATE_NOT_YET_VALID';
  if (!allowExpired && expires <= now - CERT_CLOCK_SKEW_MS) return 'CERTIFICATE_EXPIRED';
  return null;
}

export function computeIdentityRootFingerprint(
  username: string,
  accountRootPublicKey: string,
  authorityModel: CertifiedPeerBundle['authorityModel'] = 'account-device-chain'
): string {
  return fingerprintIdentityObject(PROTOCOL_KEYS.IDENTITY_ROOT, {
    version: CERTIFIED_IDENTITY_BUNDLE_VERSION,
    authorityModel,
    username: normalizeHandle(username),
    algorithm: 'ML-DSA-87',
    accountRootPublicKey
  });
}

function accountRootSignedPayload(root: Omit<AccountRootCert, 'signedPayloadDigest' | 'rootSelfSignature' | 'rootFingerprint'>) {
  return root;
}

function computeDeviceId(username: string, cert: PeerCertificateBundle): string {
  return fingerprintIdentityObject(PROTOCOL_KEYS.DEVICE_ID, {
    version: CERTIFIED_IDENTITY_BUNDLE_VERSION,
    username: normalizeHandle(username),
    dilithiumPublicKey: cert.dilithiumPublicKey,
    kyberPublicKey: cert.kyberPublicKey,
    x25519PublicKey: cert.x25519PublicKey
  });
}

function deviceCertSignedPayload(
  deviceCert: Omit<DeviceCert, 'accountRootSignature' | 'signedPayloadDigest' | 'deviceCertificateFingerprint'>
) {
  return deviceCert;
}

function deviceCertFingerprintSeed(deviceCert: Omit<DeviceCert, 'deviceCertificateFingerprint'>) {
  return {
    ...deviceCert,
    deviceCertificateFingerprint: undefined
  };
}

function subkeyBindingSignedPayload(
  binding: Omit<DeviceSubkeyBinding, 'signedPayloadDigest' | 'deviceSignature' | 'bindingFingerprint'>
) {
  return binding;
}

function subkeyBindingFingerprintSeed(binding: Omit<DeviceSubkeyBinding, 'bindingFingerprint'>) {
  return {
    ...binding,
    bindingFingerprint: undefined
  };
}

async function signIdentityPayload(
  signer: (canonicalPayload: Uint8Array) => Promise<string>,
  value: unknown,
): Promise<string> {
  const canonical = textEncoder.encode(canonicalIdentityJson(value));
  try {
    return await signer(canonical);
  } finally {
    canonical.fill(0);
  }
}

async function verifyIdentityPayload(signatureBase64: string, value: unknown, publicKeyBase64: string): Promise<boolean> {
  const signature = CryptoUtils.Base64.base64ToUint8Array(signatureBase64);
  const publicKey = CryptoUtils.Base64.base64ToUint8Array(publicKeyBase64);
  return CryptoUtils.Dilithium.verify(signature, textEncoder.encode(canonicalIdentityJson(value)), publicKey);
}

function bundleFingerprintSeed(bundle: Omit<CertifiedPeerBundle, 'bundleFingerprint'>) {
  return {
    ...bundle,
    bundleFingerprint: undefined
  };
}

export async function buildCertifiedPeerBundle(input: CertifiedPeerBundleBuildInput): Promise<CertifiedPeerBundle> {
  const username = normalizeHandle(input.username);
  const signalIdentityX25519PublicKey = extractX25519FromSignalBundle(input.fullBundle);
  const staticMlKemPublicKey = extractStaticMlKemFromSignalBundle(input.fullBundle);

  if (!username || username !== input.username) {
    throw new Error('Certified peer bundle requires a username');
  }
  if (!AUTH_USERNAME_REGEX.test(username) || !isValidSignalPreKeyBundle(input.fullBundle)) {
    throw new Error('Certified peer bundle requires a canonical Signal pre-key bundle');
  }
  if (!signalIdentityX25519PublicKey || !isValidX25519PublicKeyBase64(signalIdentityX25519PublicKey)) {
    throw new Error('Certified peer bundle requires a Signal identity key');
  }
  if (
    !staticMlKemPublicKey ||
    !isValidKyberPublicKeyBase64(staticMlKemPublicKey) ||
    staticMlKemPublicKey !== input.publicKeys.kyberPublicBase64
  ) {
    throw new Error('Certified peer bundle requires its bound static ML-KEM key');
  }
  const cert = await validatePeerCertificateBundle(input.peerCertificate, username);
  if (!cert) throw new Error('Certified peer bundle requires a valid device certificate');
  const peerCertificateFingerprint = computePeerCertificateFingerprint(cert);
  if (
    !isValidDilithiumPublicKeyBase64(input.accountRootPublicKey) ||
    typeof input.signAccountRoot !== 'function' ||
    typeof input.signDevice !== 'function'
  ) {
    throw new Error('Certified peer bundle requires an account identity root');
  }
  if (input.accountRootPublicKey === cert.dilithiumPublicKey) {
    throw new Error('Account identity root must be separate from the device signing key');
  }
  if (cert.username !== username) {
    throw new Error('Certified peer bundle certificate does not match identity scope');
  }
  if (
    cert.kyberPublicKey !== input.publicKeys.kyberPublicBase64 ||
    cert.dilithiumPublicKey !== input.publicKeys.dilithiumPublicBase64 ||
    cert.x25519PublicKey !== input.publicKeys.x25519PublicBase64
  ) {
    throw new Error('Certified peer bundle key mismatch');
  }
  const authorityModel = 'account-device-chain' as const;
  const identityRootFingerprint = computeIdentityRootFingerprint(username, input.accountRootPublicKey, authorityModel);
  const deviceId = computeDeviceId(username, cert);
  const attestedPayloadDigest = fingerprintBytes(
    PROTOCOL_KEYS.PEER_CERTIFICATE_PAYLOAD,
    encodePeerCertificateSigningPayload(cert)
  );

  const accountRootPayload: Omit<AccountRootCert, 'signedPayloadDigest' | 'rootSelfSignature' | 'rootFingerprint'> = {
    version: CERTIFIED_IDENTITY_BUNDLE_VERSION,
    authorityModel,
    username,
    algorithm: 'ML-DSA-87',
    accountRootPublicKey: input.accountRootPublicKey,
    issuedAt: cert.issuedAt,
    expiresAt: cert.expiresAt
  };
  const accountRootSigned = accountRootSignedPayload(accountRootPayload);
  const accountRoot: AccountRootCert = {
    ...accountRootPayload,
    signedPayloadDigest: fingerprintIdentityObject(PROTOCOL_KEYS.ACCOUNT_ROOT_PAYLOAD, accountRootSigned),
    rootSelfSignature: await signIdentityPayload(input.signAccountRoot, accountRootSigned),
    rootFingerprint: identityRootFingerprint
  };

  const unsignedDeviceCert: Omit<DeviceCert, 'accountRootSignature' | 'signedPayloadDigest' | 'deviceCertificateFingerprint'> = {
    version: CERTIFIED_IDENTITY_BUNDLE_VERSION,
    username,
    deviceId,
    accountRootFingerprint: identityRootFingerprint,
    signedBy: 'account-root',
    signatureAlgorithm: 'ML-DSA-87',
    attestationFormat: PROTOCOL_KEYS.PEER_CERTIFICATE_ATTESTATION,
    attestationSignature: cert.signature,
    attestedPayloadDigest,
    deviceDilithiumPublicKey: cert.dilithiumPublicKey,
    deviceKyberPublicKey: cert.kyberPublicKey,
    deviceX25519PublicKey: cert.x25519PublicKey,
    issuedAt: cert.issuedAt,
    expiresAt: cert.expiresAt
  };
  const signedDevicePayload = deviceCertSignedPayload(unsignedDeviceCert);
  const deviceCertSeed: Omit<DeviceCert, 'deviceCertificateFingerprint'> = {
    ...unsignedDeviceCert,
    signedPayloadDigest: fingerprintIdentityObject(PROTOCOL_KEYS.DEVICE_CERTIFICATE_PAYLOAD, signedDevicePayload),
    accountRootSignature: await signIdentityPayload(input.signAccountRoot, signedDevicePayload)
  };

  const deviceCert: DeviceCert = {
    ...deviceCertSeed,
    deviceCertificateFingerprint: fingerprintIdentityObject(
      PROTOCOL_KEYS.DEVICE_CERTIFICATE,
      deviceCertFingerprintSeed(deviceCertSeed)
    )
  };

  const unsignedBinding: Omit<DeviceSubkeyBinding, 'signedPayloadDigest' | 'deviceSignature' | 'bindingFingerprint'> = {
    version: CERTIFIED_IDENTITY_BUNDLE_VERSION,
    username,
    deviceId,
    accountRootFingerprint: identityRootFingerprint,
    deviceCertificateFingerprint: deviceCert.deviceCertificateFingerprint,
    algorithms: {
      signature: 'ML-DSA-87',
      kem: 'ML-KEM-1024',
      classicalKeyAgreement: 'X25519',
      signalIdentity: 'Signal-X25519'
    },
    signalIdentityX25519PublicKey,
    signalPreKeyBundleDigest: fingerprintIdentityObject(
      PROTOCOL_KEYS.SIGNAL_PREKEY_BUNDLE,
      input.fullBundle
    ),
    kyberPublicKey: input.publicKeys.kyberPublicBase64,
    dilithiumPublicKey: input.publicKeys.dilithiumPublicBase64,
    x25519PublicKey: input.publicKeys.x25519PublicBase64,
    issuedAt: cert.issuedAt,
    expiresAt: cert.expiresAt
  };
  const signedBindingPayload = subkeyBindingSignedPayload(unsignedBinding);
  const bindingSeed: Omit<DeviceSubkeyBinding, 'bindingFingerprint'> = {
    ...unsignedBinding,
    signedPayloadDigest: fingerprintIdentityObject(PROTOCOL_KEYS.DEVICE_SUBKEY_BINDING_PAYLOAD, signedBindingPayload),
    deviceSignature: await signIdentityPayload(input.signDevice, signedBindingPayload)
  };

  const subkeyBinding: DeviceSubkeyBinding = {
    ...bindingSeed,
    bindingFingerprint: fingerprintIdentityObject(
      PROTOCOL_KEYS.DEVICE_SUBKEY_BINDING,
      subkeyBindingFingerprintSeed(bindingSeed)
    )
  };

  const bundleSeed: Omit<CertifiedPeerBundle, 'bundleFingerprint'> = {
    version: CERTIFIED_IDENTITY_BUNDLE_VERSION,
    authorityModel,
    username,
    accountRoot,
    deviceCert,
    subkeyBinding,
    peerCertificateFingerprint,
    identityRootFingerprint
  };

  return {
    ...bundleSeed,
    bundleFingerprint: fingerprintIdentityObject(PROTOCOL_KEYS.CERTIFIED_PEER_BUNDLE, bundleFingerprintSeed(bundleSeed))
  };
}

export async function validateCertifiedPeerBundle(
  candidate: unknown,
  context: CertifiedPeerBundleValidationContext
): Promise<CertifiedPeerBundleValidationResult> {
  try {
    if (!candidate || typeof candidate !== 'object') {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_BUNDLE_MISSING' };
    }

    const bundle = candidate as CertifiedPeerBundle;
    if (
      !hasExactObjectKeys(bundle, CERTIFIED_BUNDLE_KEYS) ||
      !hasExactObjectKeys(bundle.accountRoot, ACCOUNT_ROOT_KEYS) ||
      !hasExactObjectKeys(bundle.deviceCert, DEVICE_CERT_KEYS) ||
      !hasExactObjectKeys(bundle.subkeyBinding, SUBKEY_BINDING_KEYS) ||
      !hasExactObjectKeys(bundle.subkeyBinding?.algorithms, BINDING_ALGORITHM_KEYS)
    ) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_SCHEMA_INVALID' };
    }
    const now = Number.isFinite(context.now as number) ? Math.trunc(context.now as number) : Date.now();
    const allowExpired = context.allowExpired === true;

    if (bundle.version !== CERTIFIED_IDENTITY_BUNDLE_VERSION) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_VERSION_UNSUPPORTED' };
    }
    if (bundle.authorityModel !== 'account-device-chain') {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_AUTHORITY_UNSUPPORTED' };
    }
    if (!bundle.username || typeof bundle.username !== 'string') {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_USERNAME_MISSING' };
    }
    if (!AUTH_USERNAME_REGEX.test(bundle.username) || !isValidSignalPreKeyBundle(context.fullBundle)) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_SIGNAL_BUNDLE_SCHEMA_INVALID' };
    }

    const targetHandle = normalizeHandle(context.targetHandle);
    if (
      !AUTH_USERNAME_REGEX.test(targetHandle) ||
      bundle.username.toLowerCase() !== targetHandle.toLowerCase()
    ) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_USERNAME_MISMATCH' };
    }

    const peerCertificate = await validatePeerCertificateBundle(
      context.peerCertificate,
      bundle.username,
      now,
      allowExpired
    );
    if (!peerCertificate) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_CERTIFICATE_MISSING' };
    }
    if (peerCertificate.username !== bundle.username) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_CERTIFICATE_USERNAME_MISMATCH' };
    }

    const certificateTimeError = requireValidTimeWindow(
      peerCertificate.issuedAt,
      peerCertificate.expiresAt,
      now,
      allowExpired,
    );
    if (certificateTimeError) return { valid: false, reason: certificateTimeError };

    const root = bundle.accountRoot;
    const device = bundle.deviceCert;
    const binding = bundle.subkeyBinding;
    if (!root || !device || !binding) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_CHAIN_INCOMPLETE' };
    }
    if (
      root.username !== bundle.username ||
      device.username !== bundle.username ||
      binding.username !== bundle.username ||
      root.authorityModel !== bundle.authorityModel
    ) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_CHAIN_USERNAME_MISMATCH' };
    }
    if (
      root.issuedAt !== peerCertificate.issuedAt ||
      root.expiresAt !== peerCertificate.expiresAt ||
      device.issuedAt !== peerCertificate.issuedAt ||
      device.expiresAt !== peerCertificate.expiresAt ||
      binding.issuedAt !== peerCertificate.issuedAt ||
      binding.expiresAt !== peerCertificate.expiresAt
    ) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_CHAIN_TIME_MISMATCH' };
    }

    const rootTimeError = requireValidTimeWindow(root.issuedAt, root.expiresAt, now, allowExpired);
    if (rootTimeError) return { valid: false, reason: rootTimeError };
    const deviceTimeError = requireValidTimeWindow(device.issuedAt, device.expiresAt, now, allowExpired);
    if (deviceTimeError) return { valid: false, reason: deviceTimeError };
    const bindingTimeError = requireValidTimeWindow(binding.issuedAt, binding.expiresAt, now, allowExpired);
    if (bindingTimeError) return { valid: false, reason: bindingTimeError };

    if (root.version !== CERTIFIED_IDENTITY_BUNDLE_VERSION || device.version !== CERTIFIED_IDENTITY_BUNDLE_VERSION || binding.version !== CERTIFIED_IDENTITY_BUNDLE_VERSION) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_CHAIN_VERSION_MISMATCH' };
    }
    if (
      root.algorithm !== 'ML-DSA-87' ||
      device.signatureAlgorithm !== 'ML-DSA-87' ||
      device.signedBy !== 'account-root'
    ) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_WEAK_SIGNATURE_ALGORITHM' };
    }
    if (
      binding.algorithms?.signature !== 'ML-DSA-87' ||
      binding.algorithms?.kem !== 'ML-KEM-1024' ||
      binding.algorithms?.classicalKeyAgreement !== 'X25519' ||
      binding.algorithms?.signalIdentity !== 'Signal-X25519'
    ) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_WEAK_BINDING_ALGORITHM' };
    }

    if (!isValidDilithiumPublicKeyBase64(root.accountRootPublicKey)) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_ROOT_KEY_INVALID' };
    }
    if (
      !isValidDilithiumSignatureBase64(root.rootSelfSignature) ||
      !isValidDilithiumSignatureBase64(device.accountRootSignature) ||
      !isValidDilithiumSignatureBase64(device.attestationSignature) ||
      !isValidDilithiumSignatureBase64(binding.deviceSignature)
    ) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_SIGNATURE_ENCODING_INVALID' };
    }
    if (root.accountRootPublicKey === device.deviceDilithiumPublicKey) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_ROOT_DEVICE_KEY_COLLISION' };
    }
    if (
      !isValidDilithiumPublicKeyBase64(device.deviceDilithiumPublicKey) ||
      !isValidKyberPublicKeyBase64(device.deviceKyberPublicKey) ||
      !isValidX25519PublicKeyBase64(device.deviceX25519PublicKey)
    ) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_DEVICE_KEYS_INVALID' };
    }
    if (
      !isValidDilithiumPublicKeyBase64(binding.dilithiumPublicKey) ||
      !isValidKyberPublicKeyBase64(binding.kyberPublicKey) ||
      !isValidX25519PublicKeyBase64(binding.x25519PublicKey) ||
      !isValidX25519PublicKeyBase64(binding.signalIdentityX25519PublicKey) ||
      !HEX_64.test(binding.signalPreKeyBundleDigest)
    ) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_BOUND_KEYS_INVALID' };
    }

    const expectedPeerCertificateFingerprint = computePeerCertificateFingerprint(peerCertificate);
    const suppliedPeerCertificateFingerprint = bundle.peerCertificateFingerprint.trim().toLowerCase();
    if (!suppliedPeerCertificateFingerprint || suppliedPeerCertificateFingerprint !== expectedPeerCertificateFingerprint) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_CERTIFICATE_FINGERPRINT_MISMATCH' };
    }

    const expectedRootFingerprint = computeIdentityRootFingerprint(bundle.username, root.accountRootPublicKey, bundle.authorityModel);
    if (
      root.rootFingerprint !== expectedRootFingerprint ||
      bundle.identityRootFingerprint !== expectedRootFingerprint ||
      device.accountRootFingerprint !== expectedRootFingerprint ||
      binding.accountRootFingerprint !== expectedRootFingerprint
    ) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_ROOT_FINGERPRINT_MISMATCH' };
    }

    if (
      device.deviceDilithiumPublicKey !== peerCertificate.dilithiumPublicKey ||
      device.deviceKyberPublicKey !== peerCertificate.kyberPublicKey ||
      device.deviceX25519PublicKey !== peerCertificate.x25519PublicKey
    ) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_CERTIFICATE_KEY_MISMATCH' };
    }

    if (
      binding.dilithiumPublicKey !== device.deviceDilithiumPublicKey ||
      binding.kyberPublicKey !== device.deviceKyberPublicKey ||
      binding.x25519PublicKey !== device.deviceX25519PublicKey ||
      binding.deviceId !== device.deviceId ||
      binding.deviceCertificateFingerprint !== device.deviceCertificateFingerprint
    ) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_SUBKEY_BINDING_MISMATCH' };
    }

    if (
      binding.kyberPublicKey !== context.publicKeys.kyberPublicBase64 ||
      binding.dilithiumPublicKey !== context.publicKeys.dilithiumPublicBase64 ||
      binding.x25519PublicKey !== context.publicKeys.x25519PublicBase64
    ) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_DISCOVERY_KEY_MISMATCH' };
    }

    const signalBundleX25519 = extractX25519FromSignalBundle(context.fullBundle);
    if (!signalBundleX25519 || signalBundleX25519 !== binding.signalIdentityX25519PublicKey) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_SIGNAL_BINDING_MISMATCH' };
    }
    const signalBundleMlKem = extractStaticMlKemFromSignalBundle(context.fullBundle);
    if (!signalBundleMlKem || signalBundleMlKem !== binding.kyberPublicKey) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_STATIC_ML_KEM_BINDING_MISMATCH' };
    }
    const signalPreKeyBundleDigest = fingerprintIdentityObject(
      PROTOCOL_KEYS.SIGNAL_PREKEY_BUNDLE,
      context.fullBundle
    );
    if (signalPreKeyBundleDigest !== binding.signalPreKeyBundleDigest) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_SIGNAL_PREKEY_BUNDLE_MISMATCH' };
    }

    const expectedDeviceId = computeDeviceId(bundle.username, peerCertificate);
    if (device.deviceId !== expectedDeviceId || binding.deviceId !== expectedDeviceId) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_DEVICE_ID_MISMATCH' };
    }

    const expectedAttestedPayloadDigest = fingerprintBytes(
      PROTOCOL_KEYS.PEER_CERTIFICATE_PAYLOAD,
      encodePeerCertificateSigningPayload(peerCertificate)
    );
    if (
      device.attestationFormat !== PROTOCOL_KEYS.PEER_CERTIFICATE_ATTESTATION ||
      device.attestationSignature !== peerCertificate.signature ||
      device.attestedPayloadDigest !== expectedAttestedPayloadDigest
    ) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_ATTESTATION_MISMATCH' };
    }

    const {
      signedPayloadDigest: _rootSignedPayloadDigest,
      rootSelfSignature: _rootSelfSignature,
      rootFingerprint: _rootFingerprint,
      ...rootPayload
    } = root;
    const rootSignedPayload = accountRootSignedPayload(rootPayload);
    const expectedRootPayloadDigest = fingerprintIdentityObject(PROTOCOL_KEYS.ACCOUNT_ROOT_PAYLOAD, rootSignedPayload);
    if (root.signedPayloadDigest !== expectedRootPayloadDigest) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_ROOT_PAYLOAD_DIGEST_MISMATCH' };
    }
    const rootSelfSignatureValid = await verifyIdentityPayload(
      root.rootSelfSignature,
      rootSignedPayload,
      root.accountRootPublicKey
    );
    if (!rootSelfSignatureValid) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_ROOT_SIGNATURE_INVALID' };
    }

    const {
      accountRootSignature: _accountRootSignature,
      signedPayloadDigest: _deviceSignedPayloadDigest,
      deviceCertificateFingerprint: _deviceCertFingerprint,
      ...devicePayload
    } = device;
    const deviceSignedPayload = deviceCertSignedPayload(devicePayload);
    const expectedDevicePayloadDigest = fingerprintIdentityObject(PROTOCOL_KEYS.DEVICE_CERTIFICATE_PAYLOAD, deviceSignedPayload);
    if (device.signedPayloadDigest !== expectedDevicePayloadDigest) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_DEVICE_PAYLOAD_DIGEST_MISMATCH' };
    }
    const deviceRootSignatureValid = await verifyIdentityPayload(
      device.accountRootSignature,
      deviceSignedPayload,
      root.accountRootPublicKey
    );
    if (!deviceRootSignatureValid) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_DEVICE_ROOT_SIGNATURE_INVALID' };
    }

    const {
      signedPayloadDigest: _bindingSignedPayloadDigest,
      deviceSignature: _deviceSignature,
      bindingFingerprint: _bindingFingerprintForPayload,
      ...bindingPayload
    } = binding;
    const bindingSignedPayload = subkeyBindingSignedPayload(bindingPayload);
    const expectedBindingPayloadDigest = fingerprintIdentityObject(PROTOCOL_KEYS.DEVICE_SUBKEY_BINDING_PAYLOAD, bindingSignedPayload);
    if (binding.signedPayloadDigest !== expectedBindingPayloadDigest) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_BINDING_PAYLOAD_DIGEST_MISMATCH' };
    }
    const bindingDeviceSignatureValid = await verifyIdentityPayload(
      binding.deviceSignature,
      bindingSignedPayload,
      device.deviceDilithiumPublicKey
    );
    if (!bindingDeviceSignatureValid) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_BINDING_DEVICE_SIGNATURE_INVALID' };
    }

    const { deviceCertificateFingerprint: _deviceCertificateFingerprint, ...deviceSeed } = device;
    const expectedDeviceCertificateFingerprint = fingerprintIdentityObject(
      PROTOCOL_KEYS.DEVICE_CERTIFICATE,
      deviceCertFingerprintSeed(deviceSeed)
    );
    if (device.deviceCertificateFingerprint !== expectedDeviceCertificateFingerprint) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_DEVICE_FINGERPRINT_MISMATCH' };
    }

    const { bindingFingerprint: _bindingFingerprint, ...bindingSeed } = binding;
    const expectedBindingFingerprint = fingerprintIdentityObject(
      PROTOCOL_KEYS.DEVICE_SUBKEY_BINDING,
      subkeyBindingFingerprintSeed(bindingSeed)
    );
    if (binding.bindingFingerprint !== expectedBindingFingerprint) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_BINDING_FINGERPRINT_MISMATCH' };
    }

    const { bundleFingerprint: _bundleFingerprint, ...bundleSeed } = bundle;
    const expectedBundleFingerprint = fingerprintIdentityObject(
      PROTOCOL_KEYS.CERTIFIED_PEER_BUNDLE,
      bundleFingerprintSeed(bundleSeed)
    );
    if (bundle.bundleFingerprint !== expectedBundleFingerprint) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_BUNDLE_FINGERPRINT_MISMATCH' };
    }

    return {
      valid: true,
      bundle,
      identityRootFingerprint: expectedRootFingerprint,
      bundleFingerprint: expectedBundleFingerprint,
      peerCertificateFingerprint: expectedPeerCertificateFingerprint
    };
  } catch (error) {
    return {
      valid: false,
      reason: error instanceof Error ? error.message : 'CERTIFIED_IDENTITY_VALIDATION_FAILED'
    };
  }
}
