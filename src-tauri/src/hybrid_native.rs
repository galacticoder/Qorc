//! Native decryption for the application hybrid envelope

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ml_dsa::{KeyInit as _, MlDsa87, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::account_vault::AccountSession;
use crate::crypto::post_quantum;
use crate::error::{QorError, QorResult};
const ML_DSA_PUBLIC_BYTES: usize = 2592;
const ML_DSA_SIGNATURE_BYTES: usize = 4627;
const OUTER_SALT_BYTES: usize = 32;
const OUTER_NONCE_BYTES: usize = 12;
const OUTER_TAG_BYTES: usize = 16;
const INNER_SALT_BYTES: usize = 32;
const INNER_NONCE_BYTES: usize = 36;
const INNER_TAG_BYTES: usize = 32;
const INNER_EPHEMERAL_BYTES: usize = 32;
const MAX_PLAINTEXT_BYTES: usize = 1024 * 1024;
const MAX_OUTER_BYTES: usize = 2 * 1024 * 1024;
const MAX_ENVELOPE_JSON_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoutingHeader {
    pub to: String,
    pub from: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub timestamp: u64,
    pub size: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoutingSignature {
    algorithm: String,
    signature: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Algorithms {
    outer: String,
    inner: String,
    aead: String,
    mac: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OuterLayer {
    salt: String,
    nonce: String,
    ciphertext: String,
    tag: String,
    mac: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HybridEnvelope {
    version: String,
    routing: RoutingHeader,
    routing_signature: RoutingSignature,
    algorithms: Algorithms,
    kem_ciphertext: String,
    outer: OuterLayer,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalPublicHeader<'a> {
    version: &'a str,
    routing: &'a RoutingHeader,
    algorithms: &'a Algorithms,
    kem_ciphertext: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InnerMetadata {
    content_length: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InnerEnvelope {
    version: String,
    salt: String,
    ephemeral_x25519: String,
    nonce: String,
    ciphertext: String,
    tag: String,
    mac: String,
    payload_type: String,
    metadata: InnerMetadata,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeHybridPlaintext {
    pub routing: RoutingHeader,
    pub payload_type: String,
    pub payload_base64: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedEnvelope {
    version: String,
    ciphertext: String,
    ephemeral_key: String,
    nonce: String,
    #[allow(dead_code)]
    tag: String,
    #[allow(dead_code)]
    probe: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SealedPlaintext {
    from: String,
    payload: serde_json::Value,
}

fn invalid_envelope() -> QorError {
    QorError::DecryptionFailed("Invalid authenticated hybrid envelope".to_string())
}

fn decode_exact<const N: usize>(value: &str) -> QorResult<Zeroizing<[u8; N]>> {
    let mut decoded = BASE64.decode(value).map_err(|_| invalid_envelope())?;
    if decoded.len() != N || BASE64.encode(&decoded) != value {
        decoded.zeroize();
        return Err(invalid_envelope());
    }
    let mut output = [0u8; N];
    output.copy_from_slice(&decoded);
    decoded.zeroize();
    Ok(Zeroizing::new(output))
}

fn decode_bounded(value: &str, max: usize) -> QorResult<Zeroizing<Vec<u8>>> {
    if value.is_empty() || value.len() > max.saturating_mul(4).saturating_add(4) / 3 + 4 {
        return Err(invalid_envelope());
    }
    let decoded = Zeroizing::new(BASE64.decode(value).map_err(|_| invalid_envelope())?);
    if decoded.is_empty() || decoded.len() > max || BASE64.encode(decoded.as_slice()) != value {
        return Err(invalid_envelope());
    }
    Ok(decoded)
}

fn concat(parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let length = parts.iter().map(|part| part.len()).sum();
    let mut output = Zeroizing::new(Vec::with_capacity(length));
    for part in parts {
        output.extend_from_slice(part);
    }
    output
}

fn hmac_blake3(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = Zeroizing::new([0u8; BLOCK]);
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(blake3::hash(key).as_bytes());
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = Zeroizing::new([0x36u8; BLOCK]);
    let mut outer_pad = Zeroizing::new([0x5cu8; BLOCK]);
    for index in 0..BLOCK {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let inner_input = concat(&[inner_pad.as_slice(), data]);
    let inner = blake3::hash(inner_input.as_slice());
    let outer_input = concat(&[outer_pad.as_slice(), inner.as_bytes()]);
    *blake3::hash(outer_input.as_slice()).as_bytes()
}

fn hkdf_blake3(
    input: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> QorResult<Zeroizing<Vec<u8>>> {
    if length == 0 || length > 255 * 32 {
        return Err(invalid_envelope());
    }
    let prk = Zeroizing::new(hmac_blake3(salt, input));
    let mut output = Zeroizing::new(Vec::with_capacity(length));
    let mut previous = Zeroizing::new(Vec::<u8>::new());
    let blocks = length.div_ceil(32);
    for counter in 1..=blocks {
        let block_input = concat(&[previous.as_slice(), info, &[counter as u8]]);
        previous = Zeroizing::new(hmac_blake3(prk.as_slice(), block_input.as_slice()).to_vec());
        output.extend_from_slice(previous.as_slice());
    }
    output.truncate(length);
    Ok(output)
}

fn derive_layer_keys(
    secret: &[u8],
    salt: &[u8],
    prefix: &str,
    routing_digest: &[u8; 32],
) -> QorResult<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)> {
    let info = Zeroizing::new(format!("{prefix}:{}", BASE64.encode(routing_digest)));
    let okm = hkdf_blake3(secret, salt, info.as_bytes(), 64)?;
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    first.copy_from_slice(&okm[..32]);
    second.copy_from_slice(&okm[32..]);
    Ok((Zeroizing::new(first), Zeroizing::new(second)))
}

fn keyed_mac(key: &[u8; 32], input: &[u8], expected: &[u8; 32]) -> bool {
    blake3::keyed_hash(key, input)
        .as_bytes()
        .ct_eq(expected)
        .into()
}

fn decrypt_double_aead(
    ciphertext: &[u8],
    nonce: &[u8; INNER_NONCE_BYTES],
    tag: &[u8; INNER_TAG_BYTES],
    key: &[u8; 32],
    aad: &[u8],
) -> QorResult<Zeroizing<Vec<u8>>> {
    let expanded = Zeroizing::new(Sha3_512::digest(key).to_vec());
    let k1: &[u8; 32] = expanded[..32].try_into().map_err(|_| invalid_envelope())?;
    let k2: &[u8; 32] = expanded[32..].try_into().map_err(|_| invalid_envelope())?;
    let mac_input = concat(&[crate::protocol_keys::QUANTUM_SECURE_MAC, key]);
    let mac_key = Zeroizing::new(*blake3::hash(mac_input.as_slice()).as_bytes());
    let authenticated = concat(&[ciphertext, aad, nonce]);
    if !keyed_mac(&mac_key, authenticated.as_slice(), tag) {
        return Err(invalid_envelope());
    }
    let xcipher = XChaCha20Poly1305::new_from_slice(k2).map_err(|_| invalid_envelope())?;
    let layer1 = Zeroizing::new(
        xcipher
            .decrypt(
                XNonce::from_slice(&nonce[12..]),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| invalid_envelope())?,
    );
    let aes = Aes256Gcm::new_from_slice(k1).map_err(|_| invalid_envelope())?;
    Ok(Zeroizing::new(
        aes.decrypt(
            Nonce::from_slice(&nonce[..12]),
            Payload {
                msg: layer1.as_slice(),
                aad,
            },
        )
        .map_err(|_| invalid_envelope())?,
    ))
}

fn validate_header(
    envelope: &HybridEnvelope,
    expected_sender: &str,
    recipient: &str,
) -> QorResult<()> {
    if envelope.version != crate::protocol_keys::HYBRID_ENVELOPE_VERSION
        || envelope.routing_signature.algorithm != "ML-DSA-87"
        || envelope.algorithms.outer != "ML-KEM-1024"
        || envelope.algorithms.inner != "X25519"
        || envelope.algorithms.aead != "AES-256-GCM+XChaCha20-Poly1305"
        || envelope.algorithms.mac != "BLAKE3-256"
        || envelope.routing.from != expected_sender
        || envelope.routing.to != recipient
        || envelope.routing.size > MAX_PLAINTEXT_BYTES
        || !matches!(
            envelope.routing.kind.as_str(),
            "libsignal-message" | "file-message-chunk"
        )
    {
        return Err(invalid_envelope());
    }
    Ok(())
}

pub fn decrypt(
    session: &AccountSession,
    envelope_json: &str,
    expected_sender_public: &str,
) -> QorResult<NativeHybridPlaintext> {
    let result = (|| -> QorResult<NativeHybridPlaintext> {
        if envelope_json.is_empty() || envelope_json.len() > MAX_ENVELOPE_JSON_BYTES {
            return Err(invalid_envelope());
        }
        let envelope: HybridEnvelope =
            serde_json::from_str(envelope_json).map_err(|_| invalid_envelope())?;
        let recipient_public = session.public_keys().dilithium_public_base64;
        validate_header(&envelope, expected_sender_public, &recipient_public)?;

        let sender_public = decode_exact::<ML_DSA_PUBLIC_BYTES>(expected_sender_public)?;
        let signature_bytes =
            decode_exact::<ML_DSA_SIGNATURE_BYTES>(&envelope.routing_signature.signature)?;
        let public_header = CanonicalPublicHeader {
            version: &envelope.version,
            routing: &envelope.routing,
            algorithms: &envelope.algorithms,
            kem_ciphertext: &envelope.kem_ciphertext,
        };
        let canonical =
            Zeroizing::new(serde_json::to_vec(&public_header).map_err(|_| invalid_envelope())?);
        let verifying_key = VerifyingKey::<MlDsa87>::new_from_slice(sender_public.as_slice())
            .map_err(|_| invalid_envelope())?;
        let signature = Signature::<MlDsa87>::try_from(signature_bytes.as_slice())
            .map_err(|_| invalid_envelope())?;
        use ml_dsa::signature::Verifier;
        verifying_key
            .verify(canonical.as_slice(), &signature)
            .map_err(|_| invalid_envelope())?;
        let routing_digest = *blake3::hash(canonical.as_slice()).as_bytes();

        let kem_ciphertext =
            decode_exact::<{ post_quantum::ML_KEM_CIPHERTEXT_SIZE }>(&envelope.kem_ciphertext)?;
        let shared = session.ml_kem_decapsulate(kem_ciphertext.as_slice())?;
        let outer_salt = decode_exact::<OUTER_SALT_BYTES>(&envelope.outer.salt)?;
        let outer_nonce = decode_exact::<OUTER_NONCE_BYTES>(&envelope.outer.nonce)?;
        let outer_tag = decode_exact::<OUTER_TAG_BYTES>(&envelope.outer.tag)?;
        let outer_mac = decode_exact::<32>(&envelope.outer.mac)?;
        let outer_ciphertext = decode_bounded(&envelope.outer.ciphertext, MAX_OUTER_BYTES)?;
        let (outer_key, outer_mac_key) = derive_layer_keys(
            shared.as_slice(),
            outer_salt.as_slice(),
            crate::protocol_keys::HYBRID_OUTER_KDF,
            &routing_digest,
        )?;
        let outer_mac_input = concat(&[
            outer_nonce.as_slice(),
            outer_ciphertext.as_slice(),
            outer_tag.as_slice(),
            &routing_digest,
        ]);
        if !keyed_mac(&outer_mac_key, outer_mac_input.as_slice(), &outer_mac) {
            return Err(invalid_envelope());
        }
        let outer_combined = concat(&[outer_ciphertext.as_slice(), outer_tag.as_slice()]);
        let aes =
            Aes256Gcm::new_from_slice(outer_key.as_slice()).map_err(|_| invalid_envelope())?;
        let inner_json = Zeroizing::new(
            aes.decrypt(
                Nonce::from_slice(outer_nonce.as_slice()),
                Payload {
                    msg: outer_combined.as_slice(),
                    aad: &routing_digest,
                },
            )
            .map_err(|_| invalid_envelope())?,
        );
        let inner: InnerEnvelope =
            serde_json::from_slice(inner_json.as_slice()).map_err(|_| invalid_envelope())?;
        if inner.version != crate::protocol_keys::HYBRID_INNER_VERSION
            || inner.metadata.content_length != envelope.routing.size
            || !matches!(inner.payload_type.as_str(), "text" | "json" | "binary")
        {
            return Err(invalid_envelope());
        }
        let inner_salt = decode_exact::<INNER_SALT_BYTES>(&inner.salt)?;
        let inner_nonce = decode_exact::<INNER_NONCE_BYTES>(&inner.nonce)?;
        let inner_tag = decode_exact::<INNER_TAG_BYTES>(&inner.tag)?;
        let inner_mac = decode_exact::<32>(&inner.mac)?;
        let ephemeral = decode_exact::<INNER_EPHEMERAL_BYTES>(&inner.ephemeral_x25519)?;
        let inner_ciphertext = decode_bounded(&inner.ciphertext, MAX_PLAINTEXT_BYTES + 64)?;
        let classical = session.x25519_shared_secret(&ephemeral)?;
        let combined_secret = concat(&[shared.as_slice(), classical.as_slice()]);
        let (inner_key, inner_mac_key) = derive_layer_keys(
            combined_secret.as_slice(),
            inner_salt.as_slice(),
            crate::protocol_keys::HYBRID_INNER_KDF,
            &routing_digest,
        )?;
        let aad = inner.payload_type.as_bytes();
        let inner_mac_input = concat(&[
            inner_nonce.as_slice(),
            inner_ciphertext.as_slice(),
            inner_tag.as_slice(),
            &routing_digest,
            ephemeral.as_slice(),
            aad,
        ]);
        if !keyed_mac(&inner_mac_key, inner_mac_input.as_slice(), &inner_mac) {
            return Err(invalid_envelope());
        }
        let plaintext = decrypt_double_aead(
            inner_ciphertext.as_slice(),
            &inner_nonce,
            &inner_tag,
            &inner_key,
            aad,
        )?;
        if plaintext.len() != envelope.routing.size
            || plaintext.len() != inner.metadata.content_length
        {
            return Err(invalid_envelope());
        }
        Ok(NativeHybridPlaintext {
            routing: envelope.routing,
            payload_type: inner.payload_type,
            payload_base64: BASE64.encode(plaintext.as_slice()),
        })
    })();
    // Every failure collapses to one error so the caller cannot distinguish
    // which stage rejected the envelope.
    result.map_err(|_| invalid_envelope())
}

pub fn decrypt_sealed(
    session: &AccountSession,
    envelope_json: &str,
) -> QorResult<Option<serde_json::Value>> {
    const STANDARD_FRAME: usize = 131_072;
    const LARGE_FRAME: usize = 262_144;
    const HEADER: usize = 18;
    if envelope_json.is_empty() || envelope_json.len() > 400_000 {
        return Ok(None);
    }
    let envelope: SealedEnvelope = match serde_json::from_str(envelope_json) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if envelope.version != "ss-v2" {
        return Ok(None);
    }
    let kem =
        match decode_exact::<{ post_quantum::ML_KEM_CIPHERTEXT_SIZE }>(&envelope.ephemeral_key) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
    let nonce = match decode_exact::<12>(&envelope.nonce) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let ciphertext = match decode_bounded(&envelope.ciphertext, LARGE_FRAME + 16) {
        Ok(value) if value.len() == STANDARD_FRAME + 16 || value.len() == LARGE_FRAME + 16 => value,
        _ => return Ok(None),
    };
    let shared = match session.ml_kem_decapsulate(kem.as_slice()) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let key_input = concat(&[
        crate::protocol_keys::SEALED_SENDER_KDF,
        &[0],
        shared.as_slice(),
    ]);
    let key = Zeroizing::new(*blake3::hash(key_input.as_slice()).as_bytes());
    let aad = concat(&[
        crate::protocol_keys::SEALED_SENDER_AAD,
        &[0],
        kem.as_slice(),
    ]);
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| invalid_envelope())?;
    let frame = match cipher.decrypt(
        Nonce::from_slice(nonce.as_slice()),
        Payload {
            msg: ciphertext.as_slice(),
            aad: aad.as_slice(),
        },
    ) {
        Ok(value) => Zeroizing::new(value),
        Err(_) => return Ok(None),
    };
    if !matches!(frame.len(), STANDARD_FRAME | LARGE_FRAME)
        || frame[0] != 2
        || frame[1] != 1
        || frame[2..6] != [0, 0, 0, 0]
        || u16::from_be_bytes([frame[6], frame[7]]) != 1
        || u16::from_be_bytes([frame[8], frame[9]]) != 0
    {
        return Ok(None);
    }
    let content_len =
        u32::from_be_bytes(frame[10..14].try_into().map_err(|_| invalid_envelope())?) as usize;
    let padding_len =
        u32::from_be_bytes(frame[14..18].try_into().map_err(|_| invalid_envelope())?) as usize;
    if content_len > frame.len() - HEADER
        || padding_len > frame.len() - HEADER
        || content_len + padding_len != frame.len() - HEADER
    {
        return Ok(None);
    }
    let inner: SealedPlaintext = match serde_json::from_slice(&frame[HEADER..HEADER + content_len])
    {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if inner.from.len() < 3
        || inner.from.len() > 100
        || inner.from != inner.from.trim().to_lowercase()
        || !inner.from.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        || !inner.payload.is_object()
    {
        return Ok(None);
    }
    Ok(Some(
        serde_json::to_value(inner).map_err(|_| invalid_envelope())?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_hkdf_matches_noble_hashes_vector() {
        let input = (0u8..32).collect::<Vec<_>>();
        let salt = (0u8..32).map(|value| 255 - value).collect::<Vec<_>>();
        let output = hkdf_blake3(
            &input,
            &salt,
            crate::protocol_keys::HYBRID_NATIVE_INTEROP,
            64,
        )
        .expect("HKDF vector");
        assert_eq!(
            hex::encode(output.as_slice()),
            "23b4f3ec4b6bce6e54b507a8bf62ab85f731ad795dbd05674100b4641d7ef005aba22e843cab081ab3ceebcda098fb879c79300379287654de6d41f7ae927365"
        );
    }
}
