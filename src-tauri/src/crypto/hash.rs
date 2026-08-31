//! Hash functions

use hkdf::Hkdf;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512, Shake256};

use crate::error::{QorcError, QorcResult};

/// SHA3-512 hash
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    Update::update(&mut hasher, data);
    let result = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(result.as_ref());
    output
}

/// SHAKE256 extendable output
pub fn shake256(data: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    output
}

/// BLAKE3 hash
pub fn blake3(data: &[u8]) -> [u8; 32] {
    let hash = blake3::hash(data);
    let mut output = [0u8; 32];
    output.copy_from_slice(hash.as_bytes());
    output
}

/// HKDF-SHA3-256 key derivation
pub fn hkdf_sha3_derive_32(input_key: &[u8], salt: &[u8], info: &[u8]) -> QorcResult<[u8; 32]> {
    let hk = Hkdf::<Sha3_256>::new(Some(salt), input_key);
    let mut output = [0u8; 32];
    hk.expand(info, &mut output)
        .map_err(|_| QorcError::Internal("HKDF expansion failed".to_string()))?;
    Ok(output)
}
