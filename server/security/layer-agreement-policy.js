export const REQUIRED_WS_PQ_HANDSHAKE = Object.freeze({
  version: 'pq-ws-1',
  kem: 'ML-KEM-1024',
  signature: 'ML-DSA-87',
  classicalKeyAgreement: 'X25519',
  kdf: 'BLAKE3-HKDF-SHA256-DOMAIN-SEPARATED',
  aead: 'QOR-PQ-AEAD',
});

export const REQUIRED_SIGNAL_PQ_ENVELOPE = Object.freeze({
  version: 'signal-pq-v1',
  kem: 'ML-KEM-1024',
  kdf: 'BLAKE3-SHA3-512-DOMAIN-SEPARATED',
  aead: 'XCHACHA20-POLY1305',
  mac: 'BLAKE3-KEYED',
});

export const RING_DEVICE_PROOF_MIN_RING_SIZE = 128;

const rejectQuietly = (reason) => ({
  valid: false,
  reason,
  action: 'drop-quietly',
  plaintextRelease: false,
  receiptAllowed: false,
  serverVisibleReason: 'generic_delivery_unavailable',
});

export function validatePqHandshakePolicy(payload) {
  if (!payload || typeof payload !== 'object') {
    return { valid: false, reason: 'missing_payload' };
  }

  const algorithms = payload.algorithms || {};
  const requiredFields = [
    ['version', payload.version, REQUIRED_WS_PQ_HANDSHAKE.version],
    ['kem', algorithms.kem, REQUIRED_WS_PQ_HANDSHAKE.kem],
    ['signature', algorithms.signature, REQUIRED_WS_PQ_HANDSHAKE.signature],
    ['classicalKeyAgreement', algorithms.classicalKeyAgreement, REQUIRED_WS_PQ_HANDSHAKE.classicalKeyAgreement],
    ['kdf', algorithms.kdf, REQUIRED_WS_PQ_HANDSHAKE.kdf],
    ['aead', algorithms.aead, REQUIRED_WS_PQ_HANDSHAKE.aead],
  ];

  for (const [name, actual, expected] of requiredFields) {
    if (actual !== expected) {
      return { valid: false, reason: `invalid_${name}` };
    }
  }

  const requiredPayloadFields = [
    'sessionId',
    'timestamp',
    'clientNonce',
    'kemCiphertext',
    'clientX25519PublicKey',
    'clientSigningPublicKey',
    'fingerprint',
  ];
  for (const field of requiredPayloadFields) {
    if (payload[field] === undefined || payload[field] === null || payload[field] === '') {
      return { valid: false, reason: `missing_${field}` };
    }
  }

  return { valid: true, algorithms: REQUIRED_WS_PQ_HANDSHAKE };
}

export function validateFinalSenderIdentity({
  expectedSignalSender,
  decryptedSignalSender,
  outerSenderHint,
  observedOuterDilithiumPublicKey,
  expectedDilithiumPublicKey,
} = {}) {
  if (!expectedSignalSender || !decryptedSignalSender || expectedSignalSender !== decryptedSignalSender) {
    return rejectQuietly('signal_sender_mismatch');
  }
  if (outerSenderHint !== undefined && outerSenderHint !== null && outerSenderHint !== expectedSignalSender) {
    return rejectQuietly('outer_sender_hint_mismatch');
  }
  if (
    expectedDilithiumPublicKey &&
    observedOuterDilithiumPublicKey &&
    observedOuterDilithiumPublicKey !== expectedDilithiumPublicKey
  ) {
    return rejectQuietly('outer_device_key_mismatch');
  }

  return {
    valid: true,
    authority: 'signal',
    outerLayerAuthority: 'transport-capability-only',
    finalSender: decryptedSignalSender,
  };
}

export function validateLayerAgreement({
  outerAccepted,
  signalAccepted,
  envelopeFresh,
  routeFresh,
  bundleFresh,
  duplicate,
} = {}) {
  if (!outerAccepted) return rejectQuietly('outer_rejected');
  if (!signalAccepted) return rejectQuietly('signal_rejected');
  if (!envelopeFresh) return rejectQuietly('stale_envelope');
  if (!routeFresh) return rejectQuietly('stale_route');
  if (!bundleFresh) return rejectQuietly('stale_bundle');
  if (duplicate) return rejectQuietly('duplicate_delivery');

  return {
    valid: true,
    action: 'release-after-local-validation',
    plaintextRelease: true,
    receiptAllowed: true,
  };
}

export function validateP2PServerEquivalence(serverDecision, p2pDecision) {
  if (!serverDecision?.valid || !p2pDecision?.valid) {
    return rejectQuietly('invalid_path_decision');
  }

  const fields = ['finalSender', 'signalIdentity', 'identityRootFingerprint'];
  for (const field of fields) {
    if ((serverDecision[field] || null) !== (p2pDecision[field] || null)) {
      return rejectQuietly(`p2p_server_${field}_mismatch`);
    }
  }

  if (!!serverDecision.plaintextRelease !== !!p2pDecision.plaintextRelease) {
    return rejectQuietly('p2p_server_plaintext_release_mismatch');
  }

  return {
    valid: true,
    action: 'paths-equivalent',
  };
}

export function validateRingDeviceProofPolicy({
  ringSize,
  keyImageSeen,
  keyImageValid,
  proofVersion,
  createsSenderIdentity,
} = {}) {
  if (!Number.isInteger(ringSize) || ringSize < RING_DEVICE_PROOF_MIN_RING_SIZE) {
    return { valid: false, reason: 'ring_anonymity_set_too_small' };
  }
  if (proofVersion !== 2) {
    return { valid: false, reason: 'invalid_ring_proof_version' };
  }
  if (!keyImageValid || keyImageSeen) {
    return { valid: false, reason: 'invalid_or_reused_key_image' };
  }
  if (createsSenderIdentity) {
    return { valid: false, reason: 'ring_proof_identity_ambiguity' };
  }

  return {
    valid: true,
    authority: 'device-capability-only',
    anonymitySet: ringSize,
  };
}
