//! Tier-2 discovery-blob layer for Qor-Chat.
//!
//! Qor-Chat discovery is two-tier: tier-1 (HintlessPIR, untouched) privately tells the client
//! WHICH slot holds its target's record; tier-2 must fetch the ~16 KB encrypted discovery blob at
//! that slot WITHOUT the server learning which one (the old direct `fetchDiscoveryBlob(handle)`
//! leaked the handle). This module drives YPIR (SimplePIR variant, `params_for_scenario_simplepir`)
//! as that oblivious tier-2: the blob DB is a matrix whose row `i` holds blob `i`, and the client
//! obliviously retrieves a full row.
//!
//! SimplePIR plaintext layout (from `params_for_scenario_simplepir`): `p = 2^14`, so each plaintext
//! element carries 14 bits; `db_rows = num_items` (slot == row), and a row holds
//! `db_cols * poly_len` elements. This file owns the byte<->14-bit-element codec that maps a blob
//! into a row's plaintext elements and back. Retrieval correctness of the row itself is provided by
//! YPIR (`assert_eq!(final_result, corr_result)` in `scheme.rs`); this codec is what makes a "row"
//! equal "a blob".

/// Bits carried by one SimplePIR plaintext element (`p = 1 << 14`).
pub const PT_BITS: usize = 14;
const PT_MASK: u32 = (1u32 << PT_BITS) - 1;

/// Number of 14-bit plaintext elements needed to hold `byte_len` bytes.
pub fn elems_for_bytes(byte_len: usize) -> usize {
    (byte_len * 8 + PT_BITS - 1) / PT_BITS
}

/// Pack a byte blob into exactly `num_elems` 14-bit plaintext elements (little-endian bit order,
/// zero-padded). `num_elems` must be >= `elems_for_bytes(blob.len())`.
pub fn pack_blob_to_pt(blob: &[u8], num_elems: usize) -> Vec<u16> {
    let mut out = Vec::with_capacity(num_elems);
    let mut acc: u32 = 0;
    let mut acc_bits: usize = 0;
    let mut bytes = blob.iter().copied();
    while out.len() < num_elems {
        while acc_bits < PT_BITS {
            match bytes.next() {
                Some(b) => {
                    acc |= (b as u32) << acc_bits;
                    acc_bits += 8;
                }
                None => break, // input exhausted; remaining elements are zero-padding
            }
        }
        out.push((acc & PT_MASK) as u16);
        acc >>= PT_BITS;
        acc_bits = acc_bits.saturating_sub(PT_BITS);
    }
    out
}

/// Reverse of `pack_blob_to_pt`: reconstruct the first `blob_len` bytes from 14-bit plaintext
/// elements (each element's high bits above `PT_BITS` are ignored).
pub fn unpack_pt_to_blob(elems: &[u16], blob_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(blob_len);
    let mut acc: u32 = 0;
    let mut acc_bits: usize = 0;
    let mut it = elems.iter().copied();
    while out.len() < blob_len {
        while acc_bits < 8 {
            match it.next() {
                Some(e) => {
                    acc |= ((e as u32) & PT_MASK) << acc_bits;
                    acc_bits += PT_BITS;
                }
                None => break, // ran out of elements; pad with zero bytes
            }
        }
        out.push((acc & 0xff) as u8);
        acc >>= 8;
        acc_bits = acc_bits.saturating_sub(8);
    }
    out
}

/// Deterministic per-slot test blob (cheap LCG fill, not crypto-random) so a neighbor-row mix-up
/// is detectable: slot `i` produces a distinct byte pattern.
pub fn test_blob_for_slot(i: usize, byte_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; byte_len];
    let mut x = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(0xABCD_1234);
    for b in out.iter_mut() {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *b = (x >> 33) as u8;
    }
    out
}

/// End-to-end tier-2 self-test over REAL blobs (not the benchmark's random DB): build a blob DB
/// where row/slot `i` = `test_blob_for_slot(i)`, then for each `target` slot obliviously retrieve it
/// via the YPIR SimplePIR flow and assert the decoded bytes equal the original blob. This is the
/// proof that "YPIR retrieves a row" + "our codec maps a row to a blob" composes into "obliviously
/// fetch discovery blob N". Mirrors `scheme::run_simple_ypir_on_params` (whose own correctness
/// assert already passes) but adds the blob codec + targeted retrieval. Returns Ok(()) on success.
pub fn tier2_roundtrip_selftest(num_items: usize, blob_len: usize, targets: &[usize]) -> Result<(), String> {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use spiral_rs::aligned_memory::AlignedMemory64;
    use spiral_rs::client::Client;
    use spiral_rs::poly::{PolyMatrix, PolyMatrixRaw};
    use crate::client::{pack_query, raw_generate_expansion_params, decrypt_ct_reg_measured, YClient};
    use crate::modulus_switch::ModulusSwitch;
    use crate::packing::condense_matrix;
    use crate::params::{params_for_scenario_simplepir, GetQPrime};
    use crate::scheme::{SEED_0, STATIC_SEED_2};
    use crate::server::{YServer, DbRowsPadded};

    let params = params_for_scenario_simplepir(num_items, blob_len * 8);
    let db_rows = 1usize << (params.db_dim_1 + params.poly_len_log2);
    let db_cols = params.instances * params.poly_len;
    let rlwe_q_prime_1 = params.get_q_prime_1();
    let rlwe_q_prime_2 = params.get_q_prime_2();
    let num_rlwe_outputs = db_cols / params.poly_len;

    // Row-major fill: YServer::new consumes the iterator as `for i in 0..db_rows { for j in 0..db_cols }`,
    // so slot i's db_cols packed elements must appear contiguously for row i.
    let pt_iter = (0..db_rows).flat_map(move |i| {
        pack_blob_to_pt(&test_blob_for_slot(i, blob_len), db_cols).into_iter()
    });
    let y_server = YServer::<u16>::new(&params, pt_iter, true, false, true);

    let offline_values = y_server.perform_offline_precomputation_simplepir(None);
    let packed_query_row_sz = params.db_rows_padded();

    for &target in targets {
        if target >= db_rows {
            return Err(format!("target slot {target} >= db_rows {db_rows}"));
        }

        let mut client = Client::init(&params);
        client.generate_secret_keys();
        let sk_reg = client.get_sk_reg();
        let pack_pub_params = raw_generate_expansion_params(
            &params,
            sk_reg,
            params.poly_len_log2,
            params.t_exp_left,
            &mut ChaCha20Rng::from_entropy(),
            &mut ChaCha20Rng::from_seed(STATIC_SEED_2),
        );
        let mut pack_pub_params_row_1s = pack_pub_params.to_vec();
        for i in 0..pack_pub_params.len() {
            pack_pub_params_row_1s[i] = pack_pub_params[i].submatrix(1, 0, 1, pack_pub_params[i].cols);
            pack_pub_params_row_1s[i] = condense_matrix(&params, &pack_pub_params_row_1s[i]);
        }

        let y_client = YClient::new(&mut client, &params);
        let query_row = y_client.generate_query(SEED_0, params.db_dim_1, true, target);
        let packed_query_row = pack_query(&params, &query_row);

        let mut all_queries_packed = AlignedMemory64::new(packed_query_row_sz);
        all_queries_packed.as_mut_slice()[..db_rows].copy_from_slice(packed_query_row.as_slice());

        let responses = y_server.perform_online_computation_simplepir(
            all_queries_packed.as_slice(),
            &offline_values,
            &[pack_pub_params_row_1s.as_slice()],
            None,
        );

        let mut recovered_cts = Vec::new();
        for ct_bytes in responses.iter() {
            recovered_cts.push(PolyMatrixRaw::recover(&params, rlwe_q_prime_1, rlwe_q_prime_2, ct_bytes));
        }
        let outer_ct: Vec<u64> = recovered_cts
            .iter()
            .flat_map(|ct| {
                decrypt_ct_reg_measured(y_client.client(), &params, &ct.ntt(), params.poly_len)
                    .as_slice()
                    .to_vec()
            })
            .collect();
        if outer_ct.len() != num_rlwe_outputs * params.poly_len {
            return Err(format!("outer_ct len {} != expected {}", outer_ct.len(), num_rlwe_outputs * params.poly_len));
        }

        let elems: Vec<u16> = outer_ct.iter().map(|&x| x as u16).collect();
        let recovered = unpack_pt_to_blob(&elems, blob_len);
        let expected = test_blob_for_slot(target, blob_len);
        if recovered != expected {
            let first = recovered.iter().zip(expected.iter()).position(|(a, b)| a != b);
            return Err(format!("slot {target}: decoded blob != expected (first mismatch byte {first:?})"));
        }
    }
    Ok(())
}

// ============================================================================================
// M3d — network split: serialize the query (client->server) and response (server->client) so the
// worker and client can be separate processes. The client keeps its secret key LOCAL for decode,
// so the server never sees it; only the query and the response bytes cross the wire. Format is
// length-prefixed little-endian, byte-aligned (correctness first; bit-packing the query u64s by
// modulus_log2 is a later size optimization). Response cts are already `Vec<u8>`.
// ============================================================================================

fn put_u32(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&(v as u32).to_le_bytes());
}
fn get_u32(b: &[u8], c: &mut usize) -> usize {
    let v = u32::from_le_bytes(b[*c..*c + 4].try_into().unwrap()) as usize;
    *c += 4;
    v
}
fn put_u64s(out: &mut Vec<u8>, words: &[u64]) {
    put_u32(out, words.len());
    for &w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
}
fn get_u64s(b: &[u8], c: &mut usize) -> Vec<u64> {
    let n = get_u32(b, c);
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(u64::from_le_bytes(b[*c..*c + 8].try_into().unwrap()));
        *c += 8;
    }
    v
}

/// Serialize the client query: the packed first-dimension query (u64s) + the condensed pub-params
/// NTT matrices (each as rows, cols, raw u64 data).
pub fn tier2_serialize_query(packed_query: &[u64], pub_params: &[spiral_rs::poly::PolyMatrixNTT]) -> Vec<u8> {
    use spiral_rs::poly::PolyMatrix;
    let mut out = Vec::new();
    put_u64s(&mut out, packed_query);
    put_u32(&mut out, pub_params.len());
    for m in pub_params {
        put_u32(&mut out, m.rows);
        put_u32(&mut out, m.cols);
        put_u64s(&mut out, m.as_slice());
    }
    out
}

/// Deserialize the query on the server side. Returns (packed_query u64s, pub-params matrices).
pub fn tier2_deserialize_query<'a>(
    params: &'a spiral_rs::params::Params,
    bytes: &[u8],
) -> (Vec<u64>, Vec<spiral_rs::poly::PolyMatrixNTT<'a>>) {
    use spiral_rs::poly::{PolyMatrix, PolyMatrixNTT};
    let mut c = 0usize;
    let packed_query = get_u64s(bytes, &mut c);
    let n = get_u32(bytes, &mut c);
    let mut mats = Vec::with_capacity(n);
    for _ in 0..n {
        let rows = get_u32(bytes, &mut c);
        let cols = get_u32(bytes, &mut c);
        let words = get_u64s(bytes, &mut c);
        let mut m = PolyMatrixNTT::zero(params, rows, cols);
        m.as_mut_slice().copy_from_slice(&words);
        mats.push(m);
    }
    (packed_query, mats)
}

/// Serialize the server response (a list of already-byte-encoded ciphertexts).
pub fn tier2_serialize_response(resp: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    put_u32(&mut out, resp.len());
    for ct in resp {
        put_u32(&mut out, ct.len());
        out.extend_from_slice(ct);
    }
    out
}

/// Deserialize the server response on the client side.
pub fn tier2_deserialize_response(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut c = 0usize;
    let n = get_u32(bytes, &mut c);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let len = get_u32(bytes, &mut c);
        out.push(bytes[c..c + len].to_vec());
        c += len;
    }
    out
}

/// Like `tier2_roundtrip_selftest`, but the query and response are serialized to bytes and
/// reconstructed across a simulated wire — proving the client/server SPLIT works (the worker only
/// ever sees serialized query bytes, never the client secret; the client decodes locally).
pub fn tier2_wire_roundtrip_selftest(num_items: usize, blob_len: usize, targets: &[usize]) -> Result<(), String> {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use spiral_rs::aligned_memory::AlignedMemory64;
    use spiral_rs::client::Client;
    use spiral_rs::poly::{PolyMatrix, PolyMatrixRaw};
    use crate::client::{pack_query, raw_generate_expansion_params, decrypt_ct_reg_measured, YClient};
    use crate::modulus_switch::ModulusSwitch;
    use crate::packing::condense_matrix;
    use crate::params::{params_for_scenario_simplepir, GetQPrime};
    use crate::scheme::{SEED_0, STATIC_SEED_2};
    use crate::server::{YServer, DbRowsPadded};

    let params = params_for_scenario_simplepir(num_items, blob_len * 8);
    let db_rows = 1usize << (params.db_dim_1 + params.poly_len_log2);
    let db_cols = params.instances * params.poly_len;
    let rlwe_q_prime_1 = params.get_q_prime_1();
    let rlwe_q_prime_2 = params.get_q_prime_2();
    let num_rlwe_outputs = db_cols / params.poly_len;

    let pt_iter = (0..db_rows).flat_map(move |i| {
        pack_blob_to_pt(&test_blob_for_slot(i, blob_len), db_cols).into_iter()
    });
    let y_server = YServer::<u16>::new(&params, pt_iter, true, false, true);
    let offline_values = y_server.perform_offline_precomputation_simplepir(None);
    let packed_query_row_sz = params.db_rows_padded();

    for &target in targets {
        if target >= db_rows {
            return Err(format!("target slot {target} >= db_rows {db_rows}"));
        }

        // ---- CLIENT: build query (keeps `client` secret local) ----
        let mut client = Client::init(&params);
        client.generate_secret_keys();
        let sk_reg = client.get_sk_reg();
        let pack_pub_params = raw_generate_expansion_params(
            &params, sk_reg, params.poly_len_log2, params.t_exp_left,
            &mut ChaCha20Rng::from_entropy(), &mut ChaCha20Rng::from_seed(STATIC_SEED_2),
        );
        let mut pub_params = pack_pub_params.to_vec();
        for i in 0..pack_pub_params.len() {
            pub_params[i] = pack_pub_params[i].submatrix(1, 0, 1, pack_pub_params[i].cols);
            pub_params[i] = condense_matrix(&params, &pub_params[i]);
        }
        let y_client = YClient::new(&mut client, &params);
        let query_row = y_client.generate_query(SEED_0, params.db_dim_1, true, target);
        let packed_query_row = pack_query(&params, &query_row);

        // ---- WIRE: client -> server ----
        let query_bytes = tier2_serialize_query(packed_query_row.as_slice(), &pub_params);

        // ---- SERVER: deserialize, answer, serialize (never sees the client secret) ----
        let (recv_packed_query, recv_pub_params) = tier2_deserialize_query(&params, &query_bytes);
        if recv_packed_query.len() != db_rows {
            return Err(format!("wire packed_query len {} != db_rows {}", recv_packed_query.len(), db_rows));
        }
        let mut all_queries_packed = AlignedMemory64::new(packed_query_row_sz);
        all_queries_packed.as_mut_slice()[..db_rows].copy_from_slice(&recv_packed_query);
        let responses = y_server.perform_online_computation_simplepir(
            all_queries_packed.as_slice(),
            &offline_values,
            &[recv_pub_params.as_slice()],
            None,
        );
        let resp_bytes = tier2_serialize_response(&responses);

        // ---- WIRE: server -> client ----
        let recv_resp = tier2_deserialize_response(&resp_bytes);

        // ---- CLIENT: decode locally with the kept secret ----
        let mut recovered_cts = Vec::new();
        for ct_bytes in recv_resp.iter() {
            recovered_cts.push(PolyMatrixRaw::recover(&params, rlwe_q_prime_1, rlwe_q_prime_2, ct_bytes));
        }
        let outer_ct: Vec<u64> = recovered_cts
            .iter()
            .flat_map(|ct| {
                decrypt_ct_reg_measured(y_client.client(), &params, &ct.ntt(), params.poly_len)
                    .as_slice()
                    .to_vec()
            })
            .collect();
        if outer_ct.len() != num_rlwe_outputs * params.poly_len {
            return Err(format!("outer_ct len {} != expected {}", outer_ct.len(), num_rlwe_outputs * params.poly_len));
        }
        let elems: Vec<u16> = outer_ct.iter().map(|&x| x as u16).collect();
        let recovered = unpack_pt_to_blob(&elems, blob_len);
        let expected = test_blob_for_slot(target, blob_len);
        if recovered != expected {
            let first = recovered.iter().zip(expected.iter()).position(|(a, b)| a != b);
            return Err(format!("slot {target}: WIRE decoded blob != expected (first mismatch byte {first:?}); query {} B, resp {} B", query_bytes.len(), resp_bytes.len()));
        }
    }
    Ok(())
}

// ============================================================================================
// M3d-service — long-lived worker state. `YServer` + `OfflinePrecomputedValues` borrow `Params`, so
// holding them in a struct across HTTP requests is self-referential. We resolve it by leaking the
// `Params` to `&'static` — it's tiny (a few hundred bytes) and depends only on (slot-count, blob-len),
// which are fixed, so it's leaked ONCE and reused across every per-epoch DB rebuild. This struct is
// what a `POST /v1/databases` builds and a `POST /v1/query` answers (mirroring workers/hintless).
// ============================================================================================

pub struct Tier2Worker {
    params: &'static spiral_rs::params::Params,
    y_server: crate::server::YServer<'static, u16>,
    offline: crate::server::OfflinePrecomputedValues<'static>,
    db_rows: usize,
}

impl Tier2Worker {
    /// Leak a `Params` for (num_items, blob_len) and build the first epoch DB. Reuse the returned
    /// `params()` for subsequent `rebuild`s so nothing else leaks.
    pub fn build(num_items: usize, blob_len: usize, blob_for: impl FnMut(usize) -> Vec<u8>) -> Self {
        let params: &'static spiral_rs::params::Params =
            Box::leak(Box::new(crate::params::params_for_scenario_simplepir(num_items, blob_len * 8)));
        Self::build_with_params(params, blob_for)
    }

    /// Build/rebuild the epoch DB from `blob_for(slot)` using an already-leaked `params` (no leak).
    pub fn build_with_params(
        params: &'static spiral_rs::params::Params,
        mut blob_for: impl FnMut(usize) -> Vec<u8>,
    ) -> Self {
        let db_rows = 1usize << (params.db_dim_1 + params.poly_len_log2);
        let db_cols = params.instances * params.poly_len;
        // Materialize the DB row-major (slot i -> row i), each row = blob packed into db_cols elems.
        let mut flat: Vec<u16> = Vec::with_capacity(db_rows * db_cols);
        for i in 0..db_rows {
            flat.extend_from_slice(&pack_blob_to_pt(&blob_for(i), db_cols));
        }
        let y_server = crate::server::YServer::<u16>::new(params, flat.into_iter(), true, false, true);
        let offline = y_server.perform_offline_precomputation_simplepir(None);
        Self { params, y_server, offline, db_rows }
    }

    pub fn params(&self) -> &'static spiral_rs::params::Params {
        self.params
    }

    /// Answer a serialized client query (`POST /v1/query` body) -> serialized response bytes. The
    /// worker never sees the client secret.
    pub fn answer(&self, query_bytes: &[u8]) -> Vec<u8> {
        use spiral_rs::aligned_memory::AlignedMemory64;
        use crate::server::DbRowsPadded;
        let (packed_query, pub_params) = tier2_deserialize_query(self.params, query_bytes);
        let mut all = AlignedMemory64::new(self.params.db_rows_padded());
        let n = self.db_rows.min(packed_query.len());
        all.as_mut_slice()[..n].copy_from_slice(&packed_query[..n]);
        let responses = self.y_server.perform_online_computation_simplepir(
            all.as_slice(),
            &self.offline,
            &[pub_params.as_slice()],
            None,
        );
        tier2_serialize_response(&responses)
    }
}

/// Build a persistent `Tier2Worker` once (leaked `&'static` params + built DB), then serve several
/// independent client queries against it — proving the long-lived service holds the built DB +
/// precompute and answers repeated queries. The client uses its OWN local copy of the (deterministic)
/// params, so its byte-identical query/response interoperate with the worker's leaked params — which
/// also keeps the `Client` borrow short (no `unsafe`, no over-long lifetime).
pub fn tier2_worker_selftest(num_items: usize, blob_len: usize, targets: &[usize]) -> Result<(), String> {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use spiral_rs::client::Client;
    use spiral_rs::poly::{PolyMatrix, PolyMatrixRaw};
    use crate::client::{pack_query, raw_generate_expansion_params, decrypt_ct_reg_measured, YClient};
    use crate::modulus_switch::ModulusSwitch;
    use crate::packing::condense_matrix;
    use crate::params::{params_for_scenario_simplepir, GetQPrime};
    use crate::scheme::{SEED_0, STATIC_SEED_2};

    let worker = Tier2Worker::build(num_items, blob_len, |i| test_blob_for_slot(i, blob_len));

    // Client's own local params (identical values to the worker's leaked &'static params).
    let params = params_for_scenario_simplepir(num_items, blob_len * 8);
    let q1 = params.get_q_prime_1();
    let q2 = params.get_q_prime_2();

    for &target in targets {
        // ---- client builds + serializes a query (secret stays local) ----
        let mut client = Client::init(&params);
        client.generate_secret_keys();
        let pack_pub_params = raw_generate_expansion_params(
            &params, client.get_sk_reg(), params.poly_len_log2, params.t_exp_left,
            &mut ChaCha20Rng::from_entropy(), &mut ChaCha20Rng::from_seed(STATIC_SEED_2),
        );
        let mut pub_params = pack_pub_params.to_vec();
        for i in 0..pack_pub_params.len() {
            pub_params[i] = pack_pub_params[i].submatrix(1, 0, 1, pack_pub_params[i].cols);
            pub_params[i] = condense_matrix(&params, &pub_params[i]);
        }
        let y_client = YClient::new(&mut client, &params);
        let query_row = y_client.generate_query(SEED_0, params.db_dim_1, true, target);
        let packed_query_row = pack_query(&params, &query_row);
        let query_bytes = tier2_serialize_query(packed_query_row.as_slice(), &pub_params);

        // ---- persistent worker answers ----
        let response_bytes = worker.answer(&query_bytes);

        // ---- client decodes locally ----
        let recv = tier2_deserialize_response(&response_bytes);
        let mut cts = Vec::new();
        for ct_bytes in recv.iter() {
            cts.push(PolyMatrixRaw::recover(&params, q1, q2, ct_bytes));
        }
        let outer_ct: Vec<u64> = cts
            .iter()
            .flat_map(|ct| decrypt_ct_reg_measured(y_client.client(), &params, &ct.ntt(), params.poly_len).as_slice().to_vec())
            .collect();
        let elems: Vec<u16> = outer_ct.iter().map(|&x| x as u16).collect();
        let recovered = unpack_pt_to_blob(&elems, blob_len);
        let expected = test_blob_for_slot(target, blob_len);
        if recovered != expected {
            let first = recovered.iter().zip(expected.iter()).position(|(a, b)| a != b);
            return Err(format!("worker slot {target}: decoded blob != expected (first mismatch byte {first:?})"));
        }
    }
    Ok(())
}

// ============================================================================================
// M4 — client daemon API. A client "lookup" is two steps separated by a round-trip to the worker:
// (1) make a query for a slot, keeping the secret; (2) decode the worker's response with that secret.
// `YClient::new(&'a mut Client<'a>, &'a Params)` forbids storing a long-lived `Client`, so instead we
// SERIALIZE the `Client` after query-gen (`Client::serialize` = secret `to_raw()` + seed) and rebuild
// it (`Client::deserialize`) for decode — each step self-contained in one scope with its own local
// (deterministic, identical) params copy, so no lifetime wall and no `unsafe`.
// ============================================================================================

/// Client step 1 (query-record): build a serialized query for `slot`, returning (query_bytes, the
/// `Client` to KEEP for decode). The daemon stores the returned `Client` under a handle and sends
/// `query_bytes` to the worker. `params` must outlive the kept `Client` (the daemon leaks one
/// `&'static` params). Returning the `Client` is what the `YClient` 2-lifetime patch enables.
pub fn tier2_client_make_query<'a>(
    params: &'a spiral_rs::params::Params,
    slot: usize,
) -> (Vec<u8>, spiral_rs::client::Client<'a>) {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use spiral_rs::client::Client;
    use spiral_rs::poly::PolyMatrix;
    use crate::client::{pack_query, raw_generate_expansion_params, YClient};
    use crate::packing::condense_matrix;
    use crate::scheme::{SEED_0, STATIC_SEED_2};

    let mut client = Client::init(params);
    client.generate_secret_keys();
    let pack_pub_params = raw_generate_expansion_params(
        params, client.get_sk_reg(), params.poly_len_log2, params.t_exp_left,
        &mut ChaCha20Rng::from_entropy(), &mut ChaCha20Rng::from_seed(STATIC_SEED_2),
    );
    let mut pub_params = pack_pub_params.to_vec();
    for i in 0..pack_pub_params.len() {
        pub_params[i] = pack_pub_params[i].submatrix(1, 0, 1, pack_pub_params[i].cols);
        pub_params[i] = condense_matrix(params, &pub_params[i]);
    }
    let query_bytes = {
        let y_client = YClient::new(&mut client, params);
        let query_row = y_client.generate_query(SEED_0, params.db_dim_1, true, slot);
        let packed_query_row = pack_query(params, &query_row);
        tier2_serialize_query(packed_query_row.as_slice(), &pub_params)
    }; // y_client's SHORT &mut-client borrow ends here, so `client` can be returned
    (query_bytes, client)
}

/// Client step 2 (recover-record): decode the worker's response using the kept `Client` (immutable
/// borrow — decode needs no `&mut`). Returns the blob bytes.
pub fn tier2_client_decode_response(
    params: &spiral_rs::params::Params,
    client: &spiral_rs::client::Client,
    response_bytes: &[u8],
    blob_len: usize,
) -> Vec<u8> {
    use spiral_rs::poly::{PolyMatrix, PolyMatrixRaw};
    use crate::client::decrypt_ct_reg_measured;
    use crate::modulus_switch::ModulusSwitch;
    use crate::params::GetQPrime;

    let q1 = params.get_q_prime_1();
    let q2 = params.get_q_prime_2();
    let recv = tier2_deserialize_response(response_bytes);
    let mut cts = Vec::new();
    for ct_bytes in recv.iter() {
        cts.push(PolyMatrixRaw::recover(params, q1, q2, ct_bytes));
    }
    let outer_ct: Vec<u64> = cts
        .iter()
        .flat_map(|ct| decrypt_ct_reg_measured(client, params, &ct.ntt(), params.poly_len).as_slice().to_vec())
        .collect();
    let elems: Vec<u16> = outer_ct.iter().map(|&x| x as u16).collect();
    unpack_pt_to_blob(&elems, blob_len)
}

/// Daemon-path self-test: client `make_query` (KEEP the Client) -> persistent worker answers ->
/// client `decode_response` with that kept Client -> exact blob. Proves the stateful
/// query-record/recover-record model — the Client persists across the worker round-trip.
pub fn tier2_daemon_roundtrip_selftest(num_items: usize, blob_len: usize, targets: &[usize]) -> Result<(), String> {
    use crate::params::params_for_scenario_simplepir;
    let worker = Tier2Worker::build(num_items, blob_len, |i| test_blob_for_slot(i, blob_len));
    let params = params_for_scenario_simplepir(num_items, blob_len * 8);
    for &target in targets {
        let (query_bytes, client) = tier2_client_make_query(&params, target);
        let response_bytes = worker.answer(&query_bytes);
        let recovered = tier2_client_decode_response(&params, &client, &response_bytes, blob_len);
        let expected = test_blob_for_slot(target, blob_len);
        if recovered != expected {
            let first = recovered.iter().zip(expected.iter()).position(|(a, b)| a != b);
            return Err(format!("daemon slot {target}: decoded blob != expected (first mismatch byte {first:?})"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn roundtrip(byte_len: usize, seed: u64) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut blob = vec![0u8; byte_len];
        rng.fill_bytes(&mut blob);

        // Exact element count, plus a row-sized over-allocation (decode must ignore padding).
        let exact = elems_for_bytes(byte_len);
        let padded = exact + 777;
        let elems = pack_blob_to_pt(&blob, padded);
        assert_eq!(elems.len(), padded);
        // Every element must fit in 14 bits (so it is a valid plaintext mod 2^14).
        assert!(elems.iter().all(|&e| (e as u32) <= PT_MASK), "element exceeds 14 bits");

        let recovered = unpack_pt_to_blob(&elems, byte_len);
        assert_eq!(recovered, blob, "byte<->14-bit-element roundtrip mismatch (len={byte_len})");
    }

    #[test]
    fn codec_roundtrips_16kb_blob() {
        roundtrip(16 * 1024, 1);
    }

    #[test]
    fn codec_roundtrips_assorted_sizes() {
        for (len, seed) in [(1usize, 2u64), (7, 3), (13, 4), (14, 5), (255, 6), (1024, 7), (17920, 8)] {
            roundtrip(len, seed);
        }
    }

    #[test]
    fn elems_for_bytes_is_ceil_div() {
        assert_eq!(elems_for_bytes(0), 0);
        assert_eq!(elems_for_bytes(1), 1); // 8 bits -> 1 elem
        assert_eq!(elems_for_bytes(2), 2); // 16 bits -> 2 elems (ceil(16/14))
        assert_eq!(elems_for_bytes(16 * 1024), (16 * 1024 * 8 + 13) / 14);
    }
}
