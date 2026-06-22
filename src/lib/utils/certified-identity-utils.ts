import { blake3 } from '@noble/hashes/blake3.js';
import { CERT_CLOCK_SKEW_MS } from '../constants';
import type {
  AccountRootCertV2,
  CertifiedPeerBundleBuildInput,
  CertifiedPeerBundleV2,
  CertifiedPeerBundleValidationContext,
  CertifiedPeerBundleValidationResult,
  DeviceCertV2,
  DeviceSubkeyBindingV2
} from '../types/identity-types';
import { CERTIFIED_IDENTITY_BUNDLE_VERSION } from '../types/identity-types';
import type { PeerCertificateBundle } from '../types/p2p-types';
import { CryptoUtils } from './crypto-utils';
import {
  computePeerCertificateFingerprint,
  encodePeerCertificateSigningPayload,
  extractX25519FromSignalBundle,
  isSelfSignedPeerCertificate,
  normalizePeerCertificateBundle
} from './peer-certificate-utils';
import {
  isValidDilithiumPublicKeyBase64,
  isValidKyberPublicKeyBase64,
  isValidX25519PublicKeyBase64
} from './messaging-validators';

const textEncoder = new TextEncoder();
const HEX_64 = /^[a-f0-9]{64}$/i;

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

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
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

function isHashedHandle(value: string): boolean {
  return HEX_64.test(value);
}

function requireValidTimeWindow(
  issuedAt: unknown,
  expiresAt: unknown,
  now: number
): string | null {
  if (!Number.isFinite(issuedAt as number) || !Number.isFinite(expiresAt as number)) {
    return 'INVALID_CERTIFICATE_TIME';
  }
  const issued = Math.trunc(issuedAt as number);
  const expires = Math.trunc(expiresAt as number);
  if (issued > now + CERT_CLOCK_SKEW_MS) return 'CERTIFICATE_NOT_YET_VALID';
  if (expires <= now - CERT_CLOCK_SKEW_MS) return 'CERTIFICATE_EXPIRED';
  if (expires <= issued) return 'INVALID_CERTIFICATE_WINDOW';
  return null;
}

export function computeIdentityRootFingerprint(
  username: string,
  accountRootPublicKey: string,
  authorityModel: CertifiedPeerBundleV2['authorityModel'] = 'account-device-chain'
): string {
  return fingerprintIdentityObject('qor-identity-root-v2', {
    version: CERTIFIED_IDENTITY_BUNDLE_VERSION,
    authorityModel,
    username: normalizeHandle(username),
    algorithm: 'ML-DSA-87',
    accountRootPublicKey
  });
}

function accountRootSignedPayload(root: Omit<AccountRootCertV2, 'signedPayloadDigest' | 'rootSelfSignature' | 'rootFingerprint'>) {
  return root;
}

function computeDeviceId(username: string, cert: PeerCertificateBundle): string {
  return fingerprintIdentityObject('qor-device-id-v2', {
    version: CERTIFIED_IDENTITY_BUNDLE_VERSION,
    username: normalizeHandle(username),
    dilithiumPublicKey: cert.dilithiumPublicKey,
    kyberPublicKey: cert.kyberPublicKey,
    x25519PublicKey: cert.x25519PublicKey
  });
}

function deviceCertSignedPayload(
  deviceCert: Omit<DeviceCertV2, 'accountRootSignature' | 'signedPayloadDigest' | 'deviceCertificateFingerprint'>
) {
  return deviceCert;
}

function deviceCertFingerprintSeed(deviceCert: Omit<DeviceCertV2, 'deviceCertificateFingerprint'>) {
  return {
    ...deviceCert,
    deviceCertificateFingerprint: undefined
  };
}

function subkeyBindingSignedPayload(
  binding: Omit<DeviceSubkeyBindingV2, 'signedPayloadDigest' | 'deviceSignature' | 'bindingFingerprint'>
) {
  return binding;
}

function subkeyBindingFingerprintSeed(binding: Omit<DeviceSubkeyBindingV2, 'bindingFingerprint'>) {
  return {
    ...binding,
    bindingFingerprint: undefined
  };
}

async function signIdentityPayload(secretKey: Uint8Array, value: unknown): Promise<string> {
  const signature = await CryptoUtils.Dilithium.sign(secretKey, textEncoder.encode(canonicalIdentityJson(value)));
  return CryptoUtils.Base64.arrayBufferToBase64(signature);
}

async function verifyIdentityPayload(signatureBase64: string, value: unknown, publicKeyBase64: string): Promise<boolean> {
  const signature = CryptoUtils.Base64.base64ToUint8Array(signatureBase64);
  const publicKey = CryptoUtils.Base64.base64ToUint8Array(publicKeyBase64);
  return CryptoUtils.Dilithium.verify(signature, textEncoder.encode(canonicalIdentityJson(value)), publicKey);
}

function bundleFingerprintSeed(bundle: Omit<CertifiedPeerBundleV2, 'bundleFingerprint'>) {
  return {
    ...bundle,
    bundleFingerprint: undefined
  };
}

export async function buildCertifiedPeerBundleV2(input: CertifiedPeerBundleBuildInput): Promise<CertifiedPeerBundleV2> {
  const username = normalizeHandle(input.username);
  const inboxId = normalizeHandle(input.inboxId);
  const cert = normalizePeerCertificateBundle(input.peerCertificate);
  const peerCertificateFingerprint = (input.peerCertificateFingerprint || computePeerCertificateFingerprint(cert)).trim().toLowerCase();
  const signalIdentityX25519PublicKey = extractX25519FromSignalBundle(input.fullBundle) || input.publicKeys.x25519PublicBase64;

  if (!username || !inboxId) {
    throw new Error('Certified peer bundle requires username and inbox id');
  }
  if (!isSelfSignedPeerCertificate(cert)) {
    throw new Error('Certified peer bundle requires a self-signed device certificate');
  }
  if (!isValidDilithiumPublicKeyBase64(input.accountRootPublicKey) || !input.accountRootSecretKey) {
    throw new Error('Certified peer bundle requires an account identity root');
  }
  if (input.accountRootPublicKey === cert.dilithiumPublicKey) {
    throw new Error('Account identity root must be separate from the device signing key');
  }
  if (cert.username !== username || cert.inboxId !== inboxId) {
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
    'qor-peer-certificate-payload-v2',
    encodePeerCertificateSigningPayload(cert)
  );

  const accountRootPayload: Omit<AccountRootCertV2, 'signedPayloadDigest' | 'rootSelfSignature' | 'rootFingerprint'> = {
    version: CERTIFIED_IDENTITY_BUNDLE_VERSION,
    authorityModel,
    username,
    algorithm: 'ML-DSA-87',
    accountRootPublicKey: input.accountRootPublicKey,
    issuedAt: cert.issuedAt,
    expiresAt: cert.expiresAt
  };
  const accountRootSigned = accountRootSignedPayload(accountRootPayload);
  const accountRoot: AccountRootCertV2 = {
    ...accountRootPayload,
    signedPayloadDigest: fingerprintIdentityObject('qor-account-root-payload-v2', accountRootSigned),
    rootSelfSignature: await signIdentityPayload(input.accountRootSecretKey, accountRootSigned),
    rootFingerprint: identityRootFingerprint
  };

  const unsignedDeviceCert: Omit<DeviceCertV2, 'accountRootSignature' | 'signedPayloadDigest' | 'deviceCertificateFingerprint'> = {
    version: CERTIFIED_IDENTITY_BUNDLE_VERSION,
    username,
    deviceId,
    accountRootFingerprint: identityRootFingerprint,
    signedBy: 'account-root',
    signatureAlgorithm: 'ML-DSA-87',
    attestationFormat: 'qor-peer-certificate-v2',
    attestationSignature: cert.signature,
    attestedPayloadDigest,
    deviceDilithiumPublicKey: cert.dilithiumPublicKey,
    deviceKyberPublicKey: cert.kyberPublicKey,
    deviceX25519PublicKey: cert.x25519PublicKey,
    issuedAt: cert.issuedAt,
    expiresAt: cert.expiresAt
  };
  const signedDevicePayload = deviceCertSignedPayload(unsignedDeviceCert);
  const deviceCertSeed: Omit<DeviceCertV2, 'deviceCertificateFingerprint'> = {
    ...unsignedDeviceCert,
    signedPayloadDigest: fingerprintIdentityObject('qor-device-certificate-payload-v2', signedDevicePayload),
    accountRootSignature: await signIdentityPayload(input.accountRootSecretKey, signedDevicePayload)
  };

  const deviceCert: DeviceCertV2 = {
    ...deviceCertSeed,
    deviceCertificateFingerprint: fingerprintIdentityObject(
      'qor-device-certificate-v2',
      deviceCertFingerprintSeed(deviceCertSeed)
    )
  };

  const unsignedBinding: Omit<DeviceSubkeyBindingV2, 'signedPayloadDigest' | 'deviceSignature' | 'bindingFingerprint'> = {
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
    inboxId,
    signalIdentityX25519PublicKey,
    kyberPublicKey: input.publicKeys.kyberPublicBase64,
    dilithiumPublicKey: input.publicKeys.dilithiumPublicBase64,
    x25519PublicKey: input.publicKeys.x25519PublicBase64,
    p2pEndpointUrl: cert.p2pEndpointUrl,
    issuedAt: cert.issuedAt,
    expiresAt: cert.expiresAt
  };
  const signedBindingPayload = subkeyBindingSignedPayload(unsignedBinding);
  const bindingSeed: Omit<DeviceSubkeyBindingV2, 'bindingFingerprint'> = {
    ...unsignedBinding,
    signedPayloadDigest: fingerprintIdentityObject('qor-device-subkey-binding-payload-v2', signedBindingPayload),
    deviceSignature: await signIdentityPayload(input.deviceDilithiumSecretKey, signedBindingPayload)
  };

  const subkeyBinding: DeviceSubkeyBindingV2 = {
    ...bindingSeed,
    bindingFingerprint: fingerprintIdentityObject(
      'qor-device-subkey-binding-v2',
      subkeyBindingFingerprintSeed(bindingSeed)
    )
  };

  const bundleSeed: Omit<CertifiedPeerBundleV2, 'bundleFingerprint'> = {
    version: CERTIFIED_IDENTITY_BUNDLE_VERSION,
    authorityModel,
    username,
    accountRoot,
    deviceCert,
    subkeyBinding,
    peerCertificateFingerprint,
    identityRootFingerprint,
    generatedAt: cert.issuedAt
  };

  return {
    ...bundleSeed,
    bundleFingerprint: fingerprintIdentityObject('qor-certified-peer-bundle-v2', bundleFingerprintSeed(bundleSeed))
  };
}

async function verifyPeerCertificateSignature(cert: PeerCertificateBundle): Promise<boolean> {
  const signature = CryptoUtils.Base64.base64ToUint8Array(cert.signature);
  const publicKey = CryptoUtils.Base64.base64ToUint8Array(cert.proof);
  const payload = encodePeerCertificateSigningPayload(cert);
  return CryptoUtils.Dilithium.verify(signature, payload, publicKey);
}

export async function validateCertifiedPeerBundleV2(
  candidate: unknown,
  context: CertifiedPeerBundleValidationContext = {}
): Promise<CertifiedPeerBundleValidationResult> {
  try {
    if (!candidate || typeof candidate !== 'object') {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_BUNDLE_MISSING' };
    }

    const bundle = candidate as CertifiedPeerBundleV2;
    const now = Number.isFinite(context.now as number) ? Math.trunc(context.now as number) : Date.now();

    if (bundle.version !== CERTIFIED_IDENTITY_BUNDLE_VERSION) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_VERSION_UNSUPPORTED' };
    }
    if (bundle.authorityModel !== 'account-device-chain') {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_AUTHORITY_UNSUPPORTED' };
    }
    if (!bundle.username || typeof bundle.username !== 'string') {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_USERNAME_MISSING' };
    }

    const targetHandle = normalizeHandle(context.targetHandle);
    if (targetHandle && !isHashedHandle(targetHandle) && bundle.username !== targetHandle) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_USERNAME_MISMATCH' };
    }

    const peerCertificate = context.peerCertificate
      ? normalizePeerCertificateBundle(context.peerCertificate)
      : null;
    if (!peerCertificate) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_CERTIFICATE_MISSING' };
    }
    if (!isSelfSignedPeerCertificate(peerCertificate)) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_DEVICE_CERTIFICATE_NOT_SELF_SIGNED' };
    }
    if (peerCertificate.username !== bundle.username) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_CERTIFICATE_USERNAME_MISMATCH' };
    }

    const certificateTimeError = requireValidTimeWindow(peerCertificate.issuedAt, peerCertificate.expiresAt, now);
    if (certificateTimeError) return { valid: false, reason: certificateTimeError };

    const root = bundle.accountRoot;
    const device = bundle.deviceCert;
    const binding = bundle.subkeyBinding;
    if (!root || !device || !binding) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_CHAIN_INCOMPLETE' };
    }

    const rootTimeError = requireValidTimeWindow(root.issuedAt, root.expiresAt, now);
    if (rootTimeError) return { valid: false, reason: rootTimeError };
    const deviceTimeError = requireValidTimeWindow(device.issuedAt, device.expiresAt, now);
    if (deviceTimeError) return { valid: false, reason: deviceTimeError };
    const bindingTimeError = requireValidTimeWindow(binding.issuedAt, binding.expiresAt, now);
    if (bindingTimeError) return { valid: false, reason: bindingTimeError };

    if (root.version !== CERTIFIED_IDENTITY_BUNDLE_VERSION || device.version !== CERTIFIED_IDENTITY_BUNDLE_VERSION || binding.version !== CERTIFIED_IDENTITY_BUNDLE_VERSION) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_CHAIN_VERSION_MISMATCH' };
    }
    if (root.algorithm !== 'ML-DSA-87' || device.signatureAlgorithm !== 'ML-DSA-87') {
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
      !isValidX25519PublicKeyBase64(binding.signalIdentityX25519PublicKey)
    ) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_BOUND_KEYS_INVALID' };
    }

    const expectedPeerCertificateFingerprint = computePeerCertificateFingerprint(peerCertificate);
    const suppliedPeerCertificateFingerprint = (context.peerCertificateFingerprint || bundle.peerCertificateFingerprint || '').trim().toLowerCase();
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

    if (context.inboxId && binding.inboxId !== context.inboxId) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_INBOX_MISMATCH' };
    }
    if (peerCertificate.inboxId && binding.inboxId !== peerCertificate.inboxId) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_CERTIFICATE_INBOX_MISMATCH' };
    }
    if (context.publicKeys) {
      if (
        binding.kyberPublicKey !== context.publicKeys.kyberPublicBase64 ||
        binding.dilithiumPublicKey !== context.publicKeys.dilithiumPublicBase64 ||
        binding.x25519PublicKey !== context.publicKeys.x25519PublicBase64
      ) {
        return { valid: false, reason: 'CERTIFIED_IDENTITY_DISCOVERY_KEY_MISMATCH' };
      }
    }

    const signalBundleX25519 = extractX25519FromSignalBundle(context.fullBundle);
    if (signalBundleX25519 && signalBundleX25519 !== binding.signalIdentityX25519PublicKey) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_SIGNAL_BINDING_MISMATCH' };
    }

    const expectedDeviceId = computeDeviceId(bundle.username, peerCertificate);
    if (device.deviceId !== expectedDeviceId || binding.deviceId !== expectedDeviceId) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_DEVICE_ID_MISMATCH' };
    }

    const expectedAttestedPayloadDigest = fingerprintBytes(
      'qor-peer-certificate-payload-v2',
      encodePeerCertificateSigningPayload(peerCertificate)
    );
    if (
      device.attestationFormat !== 'qor-peer-certificate-v2' ||
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
    const expectedRootPayloadDigest = fingerprintIdentityObject('qor-account-root-payload-v2', rootSignedPayload);
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
    const expectedDevicePayloadDigest = fingerprintIdentityObject('qor-device-certificate-payload-v2', deviceSignedPayload);
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
    const expectedBindingPayloadDigest = fingerprintIdentityObject('qor-device-subkey-binding-payload-v2', bindingSignedPayload);
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

    const signatureValid = await verifyPeerCertificateSignature(peerCertificate);
    if (!signatureValid) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_SIGNATURE_INVALID' };
    }

    const { deviceCertificateFingerprint: _deviceCertificateFingerprint, ...deviceSeed } = device;
    const expectedDeviceCertificateFingerprint = fingerprintIdentityObject(
      'qor-device-certificate-v2',
      deviceCertFingerprintSeed(deviceSeed)
    );
    if (device.deviceCertificateFingerprint !== expectedDeviceCertificateFingerprint) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_DEVICE_FINGERPRINT_MISMATCH' };
    }

    const { bindingFingerprint: _bindingFingerprint, ...bindingSeed } = binding;
    const expectedBindingFingerprint = fingerprintIdentityObject(
      'qor-device-subkey-binding-v2',
      subkeyBindingFingerprintSeed(bindingSeed)
    );
    if (binding.bindingFingerprint !== expectedBindingFingerprint) {
      return { valid: false, reason: 'CERTIFIED_IDENTITY_BINDING_FINGERPRINT_MISMATCH' };
    }

    const { bundleFingerprint: _bundleFingerprint, ...bundleSeed } = bundle;
    const expectedBundleFingerprint = fingerprintIdentityObject(
      'qor-certified-peer-bundle-v2',
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
