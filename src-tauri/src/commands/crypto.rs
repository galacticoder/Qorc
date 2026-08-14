//! Native cryptographic work used by authenticated client protocols.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;

const AUTH_POW_SEED_BYTES: usize = 16;
const AUTH_POW_NONCE_BYTES: usize = 8;
const AUTH_POW_MAX_DIFFICULTY: u8 = 28;
const AUTH_POW_MAX_BATCH_ITERATIONS: u32 = 1_000_000;
static AUTH_POW_WORKER: OnceLock<Arc<Semaphore>> = OnceLock::new();
static AUTH_POW_PENDING: AtomicUsize = AtomicUsize::new(0);
const AUTH_POW_MAX_PENDING: usize = 64;

struct PendingGuard;
impl Drop for PendingGuard {
    fn drop(&mut self) {
        AUTH_POW_PENDING.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthPowBatchResult {
    solution: Option<String>,
    next_nonce: String,
    iterations: u32,
}

fn decode_canonical_base64(value: &str, expected_bytes: usize) -> Result<Vec<u8>, String> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| "Invalid proof-of-work value".to_string())?;
    if decoded.len() != expected_bytes || STANDARD.encode(&decoded) != value {
        return Err("Invalid proof-of-work value".to_string());
    }
    Ok(decoded)
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0;
    for byte in bytes {
        if *byte == 0 {
            count += 8;
            continue;
        }
        return count + byte.leading_zeros();
    }
    count
}

fn increment_big_endian(counter: &mut [u8; AUTH_POW_NONCE_BYTES]) {
    for byte in counter.iter_mut().rev() {
        let (next, overflowed) = byte.overflowing_add(1);
        *byte = next;
        if !overflowed {
            return;
        }
    }
}

fn solve_auth_pow_batch_inner(
    seed_base64: &str,
    difficulty: u8,
    start_nonce_base64: &str,
    max_iterations: u32,
) -> Result<AuthPowBatchResult, String> {
    if !(1..=AUTH_POW_MAX_DIFFICULTY).contains(&difficulty) {
        return Err("Invalid proof-of-work difficulty".to_string());
    }
    if max_iterations == 0 || max_iterations > AUTH_POW_MAX_BATCH_ITERATIONS {
        return Err("Invalid proof-of-work batch size".to_string());
    }

    let seed = decode_canonical_base64(seed_base64, AUTH_POW_SEED_BYTES)?;
    let nonce_bytes = decode_canonical_base64(start_nonce_base64, AUTH_POW_NONCE_BYTES)?;
    let mut nonce = <[u8; AUTH_POW_NONCE_BYTES]>::try_from(nonce_bytes.as_slice())
        .map_err(|_| "Invalid proof-of-work nonce".to_string())?;
    let mut material = [0u8; AUTH_POW_SEED_BYTES + AUTH_POW_NONCE_BYTES];
    material[..AUTH_POW_SEED_BYTES].copy_from_slice(&seed);

    for iteration in 1..=max_iterations {
        material[AUTH_POW_SEED_BYTES..].copy_from_slice(&nonce);
        if leading_zero_bits(blake3::hash(&material).as_bytes()) >= u32::from(difficulty) {
            let solution = STANDARD.encode(nonce);
            material.fill(0);
            nonce.fill(0);
            return Ok(AuthPowBatchResult {
                solution: Some(solution.clone()),
                next_nonce: solution,
                iterations: iteration,
            });
        }
        increment_big_endian(&mut nonce);
    }

    let next_nonce = STANDARD.encode(nonce);
    material.fill(0);
    nonce.fill(0);
    Ok(AuthPowBatchResult {
        solution: None,
        next_nonce,
        iterations: max_iterations,
    })
}

#[tauri::command]
pub async fn auth_pow_solve_batch(
    seed_base64: String,
    difficulty: u8,
    start_nonce_base64: String,
    max_iterations: u32,
) -> Result<AuthPowBatchResult, String> {
    if AUTH_POW_PENDING.fetch_add(1, Ordering::AcqRel) >= AUTH_POW_MAX_PENDING {
        AUTH_POW_PENDING.fetch_sub(1, Ordering::AcqRel);
        return Err("Proof-of-work worker is busy".to_string());
    }
    let _pending = PendingGuard;

    let worker = AUTH_POW_WORKER
        .get_or_init(|| Arc::new(Semaphore::new(1)))
        .clone();
    let permit = worker
        .acquire_owned()
        .await
        .map_err(|_| "Proof-of-work worker is busy".to_string())?;
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        solve_auth_pow_batch_inner(
            &seed_base64,
            difficulty,
            &start_nonce_base64,
            max_iterations,
        )
    })
    .await
    .map_err(|_| "Proof-of-work worker failed".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solves_the_server_wire_convention() {
        let result = solve_auth_pow_batch_inner(
            &STANDARD.encode([0u8; AUTH_POW_SEED_BYTES]),
            1,
            &STANDARD.encode([0u8; AUTH_POW_NONCE_BYTES]),
            3,
        )
        .expect("batch should solve");

        assert_eq!(result.solution.as_deref(), Some("AAAAAAAAAAI="));
        assert_eq!(result.iterations, 3);
    }

    #[test]
    fn rejects_non_canonical_and_unbounded_inputs() {
        let seed = STANDARD.encode([0u8; AUTH_POW_SEED_BYTES]);
        let nonce = STANDARD.encode([0u8; AUTH_POW_NONCE_BYTES]);

        assert!(solve_auth_pow_batch_inner(seed.trim_end_matches('='), 1, &nonce, 1).is_err());
        assert!(solve_auth_pow_batch_inner(&seed, 29, &nonce, 1).is_err());
        assert!(
            solve_auth_pow_batch_inner(&seed, 1, &nonce, AUTH_POW_MAX_BATCH_ITERATIONS + 1)
                .is_err()
        );
    }
}
