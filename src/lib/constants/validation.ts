export const USERNAME_MIN_LENGTH = 3;
export const USERNAME_MAX_LENGTH = 32;
export const MAX_USERNAME_LENGTH = 96;
export const USERNAME_DISPLAY_MAX_LENGTH = 256;
export const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,32}$/;
export const AUTH_USERNAME_REGEX = /^[a-z0-9._-]{3,100}$/;
export const CONVERSATION_USERNAME_PATTERN = /^[a-zA-Z0-9._-]{2,64}$/;

export const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const VALID_EMOJI_PICKER_ID = /^[A-Za-z0-9_-]+$/;
export const HEX_PATTERN = /^[a-f0-9]{32,}$/i;
export const BASE64_STANDARD_REGEX = /^[A-Za-z0-9+/]*={0,2}$/;

export const CONTROL_CHARS_REGEX = /[\u0000-\u001F\u007F]/g;
export const CLIPBOARD_CONTROL_CHARS_REGEX = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;
export const NEWLINE_REGEX = /[\r\n]+/g;
export const WHITESPACE_COLLAPSE_REGEX = /\s+/g;
export const FILENAME_SANITIZE_REGEX = /[^\w.-]/g;
export const UNSAFE_FILENAME_CHARS_REGEX = /[\u0000-\u001F\u007F/\\:*?"<>|]+/g;

export const MAX_CONTENT_LENGTH = 16 * 1024;
export const MAX_SANITIZED_MESSAGE_LENGTH = 10000;

export const DEFAULT_EVENT_PAYLOAD_KEYS = ['username', 'type', 'peer', 'at', 'callId', 'status', 'startTime', 'endTime', 'durationMs', 'direction'] as const;
export const PEER_CERTIFICATE_KEYS = [
  'username',
  'dilithiumPublicKey',
  'kyberPublicKey',
  'x25519PublicKey',
  'proof',
  'issuedAt',
  'expiresAt',
  'signature'
] as const;
export const CERTIFIED_IDENTITY_BUNDLE_VERSION = 3 as const;
export const HEX_64 = /^[a-f0-9]{64}$/i;
export const ACCOUNT_ROOT_KEYS = [
  'version', 'authorityModel', 'username', 'algorithm', 'accountRootPublicKey',
  'issuedAt', 'expiresAt', 'signedPayloadDigest', 'rootSelfSignature', 'rootFingerprint'
] as const;
export const DEVICE_CERT_KEYS = [
  'version', 'username', 'deviceId', 'accountRootFingerprint', 'signedBy',
  'signatureAlgorithm', 'accountRootSignature', 'signedPayloadDigest',
  'attestationFormat', 'attestationSignature', 'attestedPayloadDigest',
  'deviceDilithiumPublicKey', 'deviceKyberPublicKey', 'deviceX25519PublicKey',
  'issuedAt', 'expiresAt', 'deviceCertificateFingerprint'
] as const;
export const SUBKEY_BINDING_KEYS = [
  'version', 'username', 'deviceId', 'accountRootFingerprint',
  'deviceCertificateFingerprint', 'algorithms', 'signalIdentityX25519PublicKey',
  'signalPreKeyBundleDigest', 'kyberPublicKey', 'dilithiumPublicKey',
  'x25519PublicKey', 'issuedAt', 'expiresAt', 'signedPayloadDigest',
  'deviceSignature', 'bindingFingerprint'
] as const;
export const BINDING_ALGORITHM_KEYS = [
  'signature', 'kem', 'classicalKeyAgreement', 'signalIdentity'
] as const;
export const CERTIFIED_BUNDLE_KEYS = [
  'version', 'authorityModel', 'username', 'accountRoot', 'deviceCert',
  'subkeyBinding', 'peerCertificateFingerprint', 'identityRootFingerprint',
  'bundleFingerprint'
] as const;
export const SIGNAL_BUNDLE_KEYS = [
  'registrationId', 'deviceId', 'identityKeyBase64', 'signedPreKey',
  'mlKemPreKey', 'staticMlKem'
] as const;
export const SIGNAL_SIGNED_PREKEY_KEYS = [
  'keyId', 'publicKeyBase64', 'signatureBase64'
] as const;
export const SIGNAL_STATIC_ML_KEM_KEYS = ['publicKeyBase64', 'signatureBase64'] as const;
export const SANITIZERS_MAX_LENGTH = 256;
export const SANITIZERS_SANITIZE_FILENAME_MAX_LENGTH = 128;
export const SANITIZERS_ID_LENGTH_LIMIT = 256;
export const IDENTITY_CHANGE_STORE_PEER_LENGTH_LIMIT = 128;
export const IDENTITY_CHANGE_STORE_NEW_KEY_LENGTH_LIMIT = 4096;
export const IDENTITY_CHANGE_STORE_STABLE_DEDUP_KEY_LENGTH_MINIMUM = 256;
export const IDENTITY_CHANGE_STORE_ENCRYPTED_MESSAGE_MESSAGE_ID_LENGTH_MINIMUM = 256;
export const IDENTITY_CHANGE_STORE_DISPLAY_DEDUP_KEY_LENGTH_MINIMUM = 256;
