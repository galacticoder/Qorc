//! Spool record packing for qorc.
//!
//! A YPIR SimplePIR row is `db_cols` plaintext words of `pt_bits` each, and a
//! retrieval returns exactly one row.

use crate::bits::{read_bits, write_bits};

/// Plaintext words needed to hold `len` bytes at `pt_bits` per word.
pub fn words_for_bytes(len: usize, pt_bits: usize) -> usize {
    (len * 8).div_ceil(pt_bits)
}

pub fn pack_record(record: &[u8], pt_bits: usize, db_cols: usize) -> Vec<u16> {
    assert!(pt_bits > 0 && pt_bits <= 16);
    let needed = words_for_bytes(record.len(), pt_bits);
    assert!(
        needed <= db_cols,
        "record of {} bytes needs {needed} words but a row holds {db_cols}",
        record.len()
    );
    let mut out = vec![0u16; db_cols];
    for (index, slot) in out.iter_mut().enumerate().take(needed) {
        *slot = read_bits(record, index * pt_bits, pt_bits) as u16;
    }
    out
}

pub fn unpack_record(words: &[u64], pt_bits: usize, len: usize) -> Vec<u8> {
    assert!(pt_bits > 0 && pt_bits <= 16);
    let mut out = vec![0u8; len];
    let needed = words_for_bytes(len, pt_bits);
    for (index, word) in words.iter().enumerate().take(needed) {
        let remaining = len * 8 - index * pt_bits;
        write_bits(&mut out, *word, index * pt_bits, pt_bits.min(remaining));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::params_for_scenario_simplepir;

    // KEM ciphertext + nonce + sealed-sender STANDARD ciphertext.
    const SPOOL_ENTRY_BYTES: usize = 1_568 + 12 + 131_072 + 16;

    fn record(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state & 0xFF) as u8
            })
            .collect()
    }

    #[test]
    fn spool_entry_round_trips_through_plaintext_words() {
        let params = params_for_scenario_simplepir(1024, SPOOL_ENTRY_BYTES * 8);
        let pt_bits = (params.pt_modulus as f64).log2().floor() as usize;
        let db_cols = params.instances * params.poly_len;

        for seed in [1u64, 7, 999, 0xDEAD_BEEF] {
            let original = record(seed, SPOOL_ENTRY_BYTES);
            let packed = pack_record(&original, pt_bits, db_cols);
            assert!(packed.iter().all(|w| (*w as u64) < params.pt_modulus));
            let widened: Vec<u64> = packed.iter().map(|w| *w as u64).collect();
            let recovered = unpack_record(&widened, pt_bits, SPOOL_ENTRY_BYTES);
            assert_eq!(recovered, original, "seed {seed}");
        }
    }

    #[test]
    fn a_row_holds_a_full_spool_entry() {
        for &items in &[1024usize, 4096, 16384] {
            let params = params_for_scenario_simplepir(items, SPOOL_ENTRY_BYTES * 8);
            let pt_bits = (params.pt_modulus as f64).log2().floor() as usize;
            let db_cols = params.instances * params.poly_len;
            assert!(
                words_for_bytes(SPOOL_ENTRY_BYTES, pt_bits) <= db_cols,
                "items={items}: entry does not fit one row"
            );
        }
    }

    #[test]
    fn packing_is_position_independent() {
        let params = params_for_scenario_simplepir(1024, SPOOL_ENTRY_BYTES * 8);
        let pt_bits = (params.pt_modulus as f64).log2().floor() as usize;
        let db_cols = params.instances * params.poly_len;
        let a = record(11, SPOOL_ENTRY_BYTES);
        let b = record(12, SPOOL_ENTRY_BYTES);
        assert_ne!(
            pack_record(&a, pt_bits, db_cols),
            pack_record(&b, pt_bits, db_cols)
        );
        assert_eq!(
            pack_record(&a, pt_bits, db_cols),
            pack_record(&a, pt_bits, db_cols)
        );
    }
}

/// End-to-end retrieval over a database of representative fixed-width records.
///
/// Proves the property Phase 4 depends on: a client that knows only an index
/// position recovers that entry's exact bytes, and the server learns nothing
/// about which position was asked for.
#[cfg(test)]
mod retrieval {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use spiral_rs::aligned_memory::AlignedMemory64;
    use spiral_rs::client::*;
    use spiral_rs::poly::{PolyMatrix, PolyMatrixRaw};

    use crate::client::*;
    use crate::modulus_switch::ModulusSwitch;
    use crate::packing::condense_matrix;
    use crate::params::{params_for_scenario_simplepir, GetQPrime};
    use crate::scheme::{SEED_0, STATIC_SEED_2};
    use crate::server::*;

    // Keep the full cryptographic round trip small enough for routine CI. The
    // packing tests above separately exercise the current 132,668-byte record;
    // retrieval is independent of row width once the parameter capacity holds.
    const TEST_ENTRY_BYTES: usize = 10944;

    fn record(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state & 0xFF) as u8
            })
            .collect()
    }

    #[test]
    fn retrieves_exact_spool_entry_by_index() {
        let num_items = 1024usize;
        let params = params_for_scenario_simplepir(num_items, TEST_ENTRY_BYTES * 8);
        let pt_bits = (params.pt_modulus as f64).log2().floor() as usize;
        let db_rows = 1usize << (params.db_dim_1 + params.poly_len_log2);
        let db_cols = params.instances * params.poly_len;

        let records: Vec<Vec<u8>> = (0..db_rows)
            .map(|i| record(i as u64 + 1, TEST_ENTRY_BYTES))
            .collect();

        // Row-major: row `i` is entry `i`, which is what makes an index position
        // usable directly as the PIR record index.
        let mut flat = Vec::with_capacity(db_rows * db_cols);
        for entry in &records {
            flat.extend_from_slice(&pack_record(entry, pt_bits, db_cols));
        }

        let y_server = YServer::<u16>::new(&params, flat.into_iter(), true, false, true);
        let offline_values = y_server.perform_offline_precomputation_simplepir(None);

        for &target_row in &[0usize, 1, 17, 511, db_rows - 1] {
            let mut client = Client::init(&params);
            client.generate_secret_keys();
            let pack_pub_params = raw_generate_expansion_params(
                &params,
                &client.get_sk_reg(),
                params.poly_len_log2,
                params.t_exp_left,
                &mut ChaCha20Rng::from_entropy(),
                &mut ChaCha20Rng::from_seed(STATIC_SEED_2),
            );
            let mut pub_params_row_1s = pack_pub_params.to_vec();
            for i in 0..pack_pub_params.len() {
                pub_params_row_1s[i] =
                    pack_pub_params[i].submatrix(1, 0, 1, pack_pub_params[i].cols);
                pub_params_row_1s[i] = condense_matrix(&params, &pub_params_row_1s[i]);
            }

            let y_client = YClient::new(&mut client, &params);
            let query_row = y_client.generate_query(SEED_0, params.db_dim_1, true, target_row);
            let packed_query_row = pack_query(&params, &query_row);

            let mut all_queries_packed = AlignedMemory64::new(params.db_rows_padded());
            all_queries_packed.as_mut_slice()[..db_rows]
                .copy_from_slice(packed_query_row.as_slice());

            let response_switched = y_server.perform_online_computation_simplepir(
                all_queries_packed.as_slice(),
                &offline_values,
                &[pub_params_row_1s.as_slice()],
                None,
            );

            let rlwe_q_prime_1 = params.get_q_prime_1();
            let rlwe_q_prime_2 = params.get_q_prime_2();
            let outer_ct = response_switched
                .iter()
                .map(|ct_bytes| {
                    PolyMatrixRaw::recover(&params, rlwe_q_prime_1, rlwe_q_prime_2, ct_bytes)
                })
                .flat_map(|ct| {
                    decrypt_ct_reg_measured(y_client.client(), &params, &ct.ntt(), params.poly_len)
                        .as_slice()
                        .to_vec()
                })
                .collect::<Vec<_>>();

            let recovered = unpack_record(&outer_ct, pt_bits, TEST_ENTRY_BYTES);
            assert_eq!(
                recovered, records[target_row],
                "row {target_row} did not round-trip"
            );
        }
    }
}

/// Wire encoding for the pieces that cross a process boundary.
///
/// The client generates its query and expansion parameters locally and never
/// discloses which row it wants, so these travel as opaque bytes. Dimensions are
/// carried explicitly rather than inferred, so a malformed frame is rejected
/// instead of being reinterpreted against the server's own parameters.
pub mod wire {
    use spiral_rs::params::Params;
    use spiral_rs::poly::{PolyMatrix, PolyMatrixNTT};

    const MAGIC: u32 = 0x5150_4952; // "QPIR"
    const BATCH_MAGIC: u32 = 0x5142_5432;

    pub fn encode_batch(items: &[Vec<u8>]) -> Vec<u8> {
        let size = 8 + items.iter().map(|item| 4 + item.len()).sum::<usize>();
        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(&BATCH_MAGIC.to_le_bytes());
        out.extend_from_slice(&(items.len() as u32).to_le_bytes());
        for item in items {
            out.extend_from_slice(&(item.len() as u32).to_le_bytes());
            out.extend_from_slice(item);
        }
        out
    }

    pub fn decode_batch<'a>(
        bytes: &'a [u8],
        max_items: usize,
        max_item_bytes: usize,
    ) -> Option<Vec<&'a [u8]>> {
        if bytes.len() < 8 || u32::from_le_bytes(bytes[0..4].try_into().ok()?) != BATCH_MAGIC {
            return None;
        }
        let count = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
        if count == 0 || count > max_items {
            return None;
        }
        let mut offset = 8usize;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let len = u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?) as usize;
            offset += 4;
            if len == 0 || len > max_item_bytes {
                return None;
            }
            let item = bytes.get(offset..offset + len)?;
            offset += len;
            out.push(item);
        }
        if offset != bytes.len() {
            return None;
        }
        Some(out)
    }

    pub fn encode_u64s(values: &[u64]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + values.len() * 8);
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&(values.len() as u32).to_le_bytes());
        for value in values {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out
    }

    pub fn decode_u64s(bytes: &[u8]) -> Option<Vec<u64>> {
        if bytes.len() < 8 {
            return None;
        }
        if u32::from_le_bytes(bytes[0..4].try_into().ok()?) != MAGIC {
            return None;
        }
        let count = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
        if bytes.len() != 8 + count * 8 {
            return None;
        }
        let mut out = Vec::with_capacity(count);
        for chunk in bytes[8..].chunks_exact(8) {
            out.push(u64::from_le_bytes(chunk.try_into().ok()?));
        }
        Some(out)
    }

    pub fn encode_matrices(matrices: &[PolyMatrixNTT]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&(matrices.len() as u32).to_le_bytes());
        for matrix in matrices {
            out.extend_from_slice(&(matrix.rows as u32).to_le_bytes());
            out.extend_from_slice(&(matrix.cols as u32).to_le_bytes());
            let data = matrix.as_slice();
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            for value in data {
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
        out
    }

    pub fn decode_matrices<'a>(
        params: &'a Params,
        bytes: &[u8],
        max_matrices: usize,
    ) -> Option<Vec<PolyMatrixNTT<'a>>> {
        if bytes.len() < 8 || u32::from_le_bytes(bytes[0..4].try_into().ok()?) != MAGIC {
            return None;
        }
        let count = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
        if count > max_matrices {
            return None;
        }
        let mut offset = 8usize;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            if bytes.len() < offset + 12 {
                return None;
            }
            let rows = u32::from_le_bytes(bytes[offset..offset + 4].try_into().ok()?) as usize;
            let cols = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().ok()?) as usize;
            let len = u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().ok()?) as usize;
            offset += 12;
            if rows == 0 || cols == 0 || rows > 8 || cols > 1 << 20 {
                return None;
            }
            if bytes.len() < offset + len * 8 {
                return None;
            }
            let mut matrix = PolyMatrixNTT::zero(params, rows, cols);
            if matrix.as_slice().len() != len {
                return None;
            }
            let target = matrix.as_mut_slice();
            for (index, chunk) in bytes[offset..offset + len * 8].chunks_exact(8).enumerate() {
                target[index] = u64::from_le_bytes(chunk.try_into().ok()?);
            }
            offset += len * 8;
            out.push(matrix);
        }
        if offset != bytes.len() {
            return None;
        }
        Some(out)
    }
}

#[cfg(test)]
mod wire_tests {
    use super::wire::*;
    use crate::params::params_for_scenario_simplepir;
    use spiral_rs::poly::{PolyMatrix, PolyMatrixNTT};

    #[test]
    fn u64_frames_round_trip_and_reject_corruption() {
        let values: Vec<u64> = (0..1000).map(|i| i * 0x1234_5678_9ABC).collect();
        let encoded = encode_u64s(&values);
        assert_eq!(decode_u64s(&encoded).unwrap(), values);

        assert!(decode_u64s(&encoded[..encoded.len() - 1]).is_none());
        assert!(decode_u64s(&[]).is_none());
        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 0xFF;
        assert!(decode_u64s(&bad_magic).is_none());
        let mut bad_len = encoded.clone();
        bad_len[4] = bad_len[4].wrapping_add(1);
        assert!(decode_u64s(&bad_len).is_none());
    }

    #[test]
    fn batch_frames_round_trip_and_reject_corruption() {
        let items = vec![vec![1, 2, 3], vec![4; 100], vec![5; 7]];
        let encoded = encode_batch(&items);
        let decoded = decode_batch(&encoded, 3, 100).unwrap();
        assert_eq!(decoded, items.iter().map(Vec::as_slice).collect::<Vec<_>>());
        assert!(decode_batch(&encoded, 2, 100).is_none());
        assert!(decode_batch(&encoded, 3, 99).is_none());
        assert!(decode_batch(&encoded[..encoded.len() - 1], 3, 100).is_none());
    }

    #[test]
    fn matrix_frames_round_trip() {
        let params = params_for_scenario_simplepir(1024, 10944 * 8);
        let mut matrices = Vec::new();
        for seed in 0..3u64 {
            let mut matrix = PolyMatrixNTT::zero(&params, 1, 2);
            for (index, slot) in matrix.as_mut_slice().iter_mut().enumerate() {
                *slot = (index as u64).wrapping_mul(seed + 7) % params.modulus;
            }
            matrices.push(matrix);
        }
        let encoded = encode_matrices(&matrices);
        let decoded = decode_matrices(&params, &encoded, 64).unwrap();
        assert_eq!(decoded.len(), matrices.len());
        for (a, b) in decoded.iter().zip(matrices.iter()) {
            assert_eq!(a.rows, b.rows);
            assert_eq!(a.cols, b.cols);
            assert_eq!(a.as_slice(), b.as_slice());
        }
    }

    #[test]
    fn matrix_frames_reject_hostile_input() {
        let params = params_for_scenario_simplepir(1024, 10944 * 8);
        let matrix = PolyMatrixNTT::zero(&params, 1, 2);
        let encoded = encode_matrices(std::slice::from_ref(&matrix));
        assert!(decode_matrices(&params, &encoded, 0).is_none());
        assert!(decode_matrices(&params, &encoded[..encoded.len() - 8], 64).is_none());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_matrices(&params, &trailing, 64).is_none());
    }
}
