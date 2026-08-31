//! Post-Quantum Cryptography

use libcrux_ml_kem::mlkem1024::{
    self, MlKem1024Ciphertext, MlKem1024PrivateKey, MlKem1024PublicKey,
};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{QorcError, QorcResult};

/// ML-KEM-1024 public key size
pub const ML_KEM_PUBLIC_KEY_SIZE: usize = 1568;
pub const ML_KEM_SECRET_KEY_SIZE: usize = 3168;
pub const ML_KEM_CIPHERTEXT_SIZE: usize = 1568;
const ML_KEM_SHARED_SECRET_SIZE: usize = 32;

/// ML-KEM-1024 encapsulation result
pub struct MlKemEncapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Zeroizing<Vec<u8>>,
}

pub fn validate_ml_kem_public_key(public_key: &[u8]) -> QorcResult<()> {
    if public_key.len() != ML_KEM_PUBLIC_KEY_SIZE {
        return Err(QorcError::InvalidKeyLength {
            expected: ML_KEM_PUBLIC_KEY_SIZE,
            actual: public_key.len(),
        });
    }

    let key =
        MlKem1024PublicKey::try_from(public_key).map_err(|_| QorcError::KemEncapsulationFailed)?;
    if !mlkem1024::validate_public_key(&key) {
        return Err(QorcError::KemEncapsulationFailed);
    }
    Ok(())
}

/// Encapsulate with ML-KEM-1024
pub fn ml_kem_encapsulate(public_key: &[u8]) -> QorcResult<MlKemEncapsulation> {
    validate_ml_kem_public_key(public_key)?;
    let pk =
        MlKem1024PublicKey::try_from(public_key).map_err(|_| QorcError::KemEncapsulationFailed)?;

    let mut randomness = Zeroizing::new([0u8; ML_KEM_SHARED_SECRET_SIZE]);
    getrandom::fill(randomness.as_mut()).map_err(|_| QorcError::KemEncapsulationFailed)?;
    let (ct, mut shared_secret) = mlkem1024::encapsulate(&pk, *randomness);
    let output_secret = Zeroizing::new(shared_secret.to_vec());
    shared_secret.zeroize();

    Ok(MlKemEncapsulation {
        ciphertext: ct.as_ref().to_vec(),
        shared_secret: output_secret,
    })
}

/// Decapsulate with ML-KEM-1024
pub fn ml_kem_decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> QorcResult<Zeroizing<Vec<u8>>> {
    if ciphertext.len() != ML_KEM_CIPHERTEXT_SIZE {
        return Err(QorcError::InvalidKeyLength {
            expected: ML_KEM_CIPHERTEXT_SIZE,
            actual: ciphertext.len(),
        });
    }

    if secret_key.len() != ML_KEM_SECRET_KEY_SIZE {
        return Err(QorcError::InvalidKeyLength {
            expected: ML_KEM_SECRET_KEY_SIZE,
            actual: secret_key.len(),
        });
    }

    let ct =
        MlKem1024Ciphertext::try_from(ciphertext).map_err(|_| QorcError::KemDecapsulationFailed)?;
    let sk =
        MlKem1024PrivateKey::try_from(secret_key).map_err(|_| QorcError::KemDecapsulationFailed)?;

    if !mlkem1024::validate_private_key(&sk, &ct) {
        let mut rejected_key: [u8; ML_KEM_SECRET_KEY_SIZE] = sk.into();
        rejected_key.zeroize();
        return Err(QorcError::KemDecapsulationFailed);
    }

    let mut shared_secret = mlkem1024::decapsulate(&sk, &ct);
    let output_secret = Zeroizing::new(shared_secret.to_vec());
    shared_secret.zeroize();

    let mut consumed_key: [u8; ML_KEM_SECRET_KEY_SIZE] = sk.into();
    consumed_key.zeroize();

    Ok(output_secret)
}

pub fn validate_ml_kem_keypair(public_key: &[u8], secret_key: &[u8]) -> QorcResult<()> {
    let encapsulated = ml_kem_encapsulate(public_key)?;
    let decapsulated = ml_kem_decapsulate(&encapsulated.ciphertext, secret_key)?;
    if !crate::crypto::utils::constant_time_eq(
        encapsulated.shared_secret.as_slice(),
        decapsulated.as_slice(),
    ) {
        return Err(QorcError::Verification(
            "ML-KEM public/private key mismatch".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    use zeroize::Zeroize;

    use super::*;

    fn sha256_hex(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    #[test]
    fn ml_kem_1024_matches_noble_fips_203_vector() {
        let key_seed = core::array::from_fn(|index| index as u8);
        let encapsulation_seed = core::array::from_fn(|index| (index + 64) as u8);
        let key_pair = mlkem1024::generate_key_pair(key_seed);

        assert_eq!(
            sha256_hex(key_pair.public_key().as_ref()),
            "c7b8fa0aa471d5ae18922d6ccad5b31e1d84f92ae723abfd13747018740a8530"
        );
        assert_eq!(
            sha256_hex(key_pair.private_key().as_ref()),
            "3a2a676c5a242ee683cb6097c8f3e64fbef4d90267f9250ec2beab8f99621fad"
        );

        let (ciphertext, mut shared_secret) =
            mlkem1024::encapsulate(key_pair.public_key(), encapsulation_seed);
        assert_eq!(
            sha256_hex(ciphertext.as_ref()),
            "7c89743960f7c3d17bb69572e49de14fe0990c9113a0706963a8f4c7b39afcdf"
        );
        assert_eq!(
            hex::encode(shared_secret),
            "0ad8d1ea1b8dd788979b4379581218df9321bdce5567eca42ae6be7d395f1a54"
        );

        let mut decapsulated = mlkem1024::decapsulate(key_pair.private_key(), &ciphertext);
        assert_eq!(decapsulated, shared_secret);
        shared_secret.zeroize();
        decapsulated.zeroize();

        let (private_key, _) = key_pair.into_parts();
        let mut private_key_bytes: [u8; ML_KEM_SECRET_KEY_SIZE] = private_key.into();
        private_key_bytes.zeroize();
    }
}
