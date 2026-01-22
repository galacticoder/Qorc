//! Post-Quantum Cryptography

use pqcrypto_kyber::kyber1024;
use fips204::ml_dsa_87;
use fips204::traits::{SerDes, Signer};
use pqcrypto_traits::kem::{Ciphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey, SharedSecret};

use crate::error::{QorError, QorResult};

/// ML-KEM-1024 public key size
pub const KYBER_PUBLIC_KEY_SIZE: usize = 1568;
pub const KYBER_SECRET_KEY_SIZE: usize = 3168;
pub const KYBER_CIPHERTEXT_SIZE: usize = 1568;

/// Dilithium-87 public key size
pub const DILITHIUM_SECRET_KEY_SIZE: usize = 4896;

/// ML-KEM-1024 keypair
pub struct KyberKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// Generate ML-KEM-1024 keypair
pub fn kyber_generate_keypair() -> QorResult<KyberKeyPair> {
    let (pk, sk) = kyber1024::keypair();
    Ok(KyberKeyPair {
        public_key: pk.as_bytes().to_vec(),
        secret_key: sk.as_bytes().to_vec(),
    })
}

/// ML-KEM-1024 encapsulation result
pub struct KyberEncapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

/// Encapsulate with ML-KEM-1024
pub fn kyber_encapsulate(public_key: &[u8]) -> QorResult<KyberEncapsulation> {
    if public_key.len() != KYBER_PUBLIC_KEY_SIZE {
        return Err(QorError::InvalidKeyLength {
            expected: KYBER_PUBLIC_KEY_SIZE,
            actual: public_key.len(),
        });
    }

    let pk = kyber1024::PublicKey::from_bytes(public_key)
        .map_err(|_| QorError::KemEncapsulationFailed)?;

    let (ss, ct) = kyber1024::encapsulate(&pk);

    Ok(KyberEncapsulation {
        ciphertext: ct.as_bytes().to_vec(),
        shared_secret: ss.as_bytes().to_vec(),
    })
}

/// Decapsulate with ML-KEM-1024
pub fn kyber_decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> QorResult<Vec<u8>> {
    if ciphertext.len() != KYBER_CIPHERTEXT_SIZE {
        return Err(QorError::InvalidKeyLength {
            expected: KYBER_CIPHERTEXT_SIZE,
            actual: ciphertext.len(),
        });
    }

    if secret_key.len() != KYBER_SECRET_KEY_SIZE {
        return Err(QorError::InvalidKeyLength {
            expected: KYBER_SECRET_KEY_SIZE,
            actual: secret_key.len(),
        });
    }

    let ct = kyber1024::Ciphertext::from_bytes(ciphertext)
        .map_err(|_| QorError::KemDecapsulationFailed)?;
    let sk = kyber1024::SecretKey::from_bytes(secret_key)
        .map_err(|_| QorError::KemDecapsulationFailed)?;

    let ss = kyber1024::decapsulate(&ct, &sk);

    Ok(ss.as_bytes().to_vec())
}

/// Dilithium-87 keypair
pub struct DilithiumKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// Generate Dilithium-87 keypair
pub fn dilithium_generate_keypair() -> QorResult<DilithiumKeyPair> {
    let (pk, sk) = ml_dsa_87::try_keygen()
        .map_err(|_| QorError::KeyGenerationFailed("Failed to generate ML-DSA-87 keypair".to_string()))?;
    Ok(DilithiumKeyPair {
        public_key: pk.into_bytes().to_vec(),
        secret_key: sk.into_bytes().to_vec(),
    })
}

/// Sign with Dilithium-87
pub fn dilithium_sign(message: &[u8], secret_key: &[u8]) -> QorResult<Vec<u8>> {
    if secret_key.len() != DILITHIUM_SECRET_KEY_SIZE {
        return Err(QorError::InvalidKeyLength {
            expected: DILITHIUM_SECRET_KEY_SIZE,
            actual: secret_key.len(),
        });
    }

    let sk_bytes: [u8; DILITHIUM_SECRET_KEY_SIZE] = secret_key.try_into()
        .map_err(|_| QorError::SigningFailed)?;
    let sk = ml_dsa_87::PrivateKey::try_from_bytes(sk_bytes)
        .map_err(|_| QorError::SigningFailed)?;
        
    let signature = sk.try_sign(message, &[])
        .map_err(|_| QorError::SigningFailed)?;

    Ok(signature.to_vec())
}
