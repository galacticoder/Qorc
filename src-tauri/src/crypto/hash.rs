//! Hash functions

use blake3::Hasher as Blake3Hasher;
use hkdf::Hkdf;
use sha3::{Digest, Sha3_256, Sha3_512, Shake256};
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// SHA3-256 hash
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Update::update(&mut hasher, data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(result.as_ref());
    output
}

/// SHA-256 hash
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(result.as_ref());
    output
}

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
#[allow(dead_code)]
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

/// BLAKE3 keyed hash (MAC)
pub fn blake3_keyed(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new_keyed(key);
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(result.as_slice());
    output
}

/// HKDF-SHA3-256 key derivation
#[allow(dead_code)]
pub fn hkdf_sha3_derive(input_key: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha3_256>::new(Some(salt), input_key);
    let mut output = vec![0u8; output_len];
    hk.expand(info, &mut output).expect("HKDF expansion failed");
    output
}
