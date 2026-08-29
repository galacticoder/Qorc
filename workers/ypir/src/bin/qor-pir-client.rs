//! Client side PIR helper.
//!
//! Runs as a sidecar rather than being linked into the app so the optimized x86
//! implementation and portable ARM64 implementation stay isolated from the
//! desktop binarys instruction set baseline and memory lifetime.

use std::collections::HashMap;
use std::io::{self, Read, Write};

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use spiral_rs::client::*;
use spiral_rs::params::Params;
use spiral_rs::poly::{PolyMatrix, PolyMatrixRaw};

use ypir::client::*;
use ypir::modulus_switch::ModulusSwitch;
use ypir::packing::condense_matrix;
use ypir::params::{params_for_scenario_simplepir, GetQPrime};
use ypir::qor_spool::{unpack_record, wire};
use ypir::scheme::{SEED_0, STATIC_SEED_2};

const OP_QUERY: u8 = 1;
const OP_DECODE: u8 = 2;
const OP_DISCARD: u8 = 3;
const OP_QUERY_BATCH: u8 = 4;
const OP_DECODE_BATCH: u8 = 5;

const STATUS_OK: u8 = 0;
const STATUS_ERROR: u8 = 1;

const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
const MAX_ACTIVE_SESSIONS: usize = 4;
const MAX_BATCH_QUERIES: usize = 16;

fn read_frame(input: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0u8; 4];
    match input.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut payload = vec![0u8; length];
    input.read_exact(&mut payload)?;
    Ok(Some(payload))
}

fn write_frame(output: &mut impl Write, status: u8, payload: &[u8]) -> io::Result<()> {
    output.write_all(&((payload.len() + 1) as u32).to_le_bytes())?;
    output.write_all(&[status])?;
    output.write_all(payload)?;
    output.flush()
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .and_then(|slice| slice.try_into().ok())
        .map(u32::from_le_bytes)
}

struct Session {
    params: &'static Params,
    y_client: YClient<'static>,
    entry_bytes: usize,
}

/// `YClient` borrows its `Client` for the params' lifetime, which forces both to
/// be `'static`. Params depend only on the database shape, so they are cached
/// and reused; a `Client` is leaked per query because its keys must be fresh —
/// reusing them would let a server link two queries. Each is on the order of
/// tens of kilobytes, and the sidecar is cheap to restart.
fn leak_params(count: usize, entry_bytes: usize) -> &'static Params {
    use std::sync::Mutex;
    use std::sync::OnceLock;
    static CACHE: OnceLock<Mutex<Vec<((usize, usize), &'static Params)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(Vec::new()));
    let mut entries = cache.lock().unwrap();
    if let Some((_, params)) = entries
        .iter()
        .find(|(shape, _)| *shape == (count, entry_bytes))
    {
        return params;
    }
    let params: &'static Params = Box::leak(Box::new(params_for_scenario_simplepir(
        count.next_power_of_two().max(2048),
        entry_bytes * 8,
    )));
    entries.push(((count, entry_bytes), params));
    params
}

/// Generates a query for one row. The row index never leaves this process in
/// any form a server could read: it is encoded into the query ciphertext.
fn generate_queries(
    count: usize,
    entry_bytes: usize,
    target_rows: &[usize],
) -> Result<(Session, Vec<Vec<u8>>, Vec<u8>), String> {
    if count == 0 || count > 1 << 20 || entry_bytes == 0 || entry_bytes > 1 << 20 {
        return Err("unreasonable database shape".to_string());
    }
    if target_rows.is_empty() || target_rows.len() > MAX_BATCH_QUERIES {
        return Err("unreasonable query count".to_string());
    }

    let params = leak_params(count, entry_bytes);
    let db_rows = 1usize << (params.db_dim_1 + params.poly_len_log2);
    if let Some(target_row) = target_rows
        .iter()
        .find(|target_row| **target_row >= db_rows)
    {
        return Err(format!("row {target_row} is outside {db_rows} rows"));
    }

    let client: &'static mut Client<'static> = Box::leak(Box::new(Client::init(params)));
    client.generate_secret_keys();
    let pack_pub_params = raw_generate_expansion_params(
        params,
        &client.get_sk_reg(),
        params.poly_len_log2,
        params.t_exp_left,
        &mut ChaCha20Rng::from_entropy(),
        &mut ChaCha20Rng::from_seed(STATIC_SEED_2),
    );
    let mut rows = pack_pub_params.to_vec();
    for i in 0..pack_pub_params.len() {
        rows[i] = pack_pub_params[i].submatrix(1, 0, 1, pack_pub_params[i].cols);
        rows[i] = condense_matrix(params, &rows[i]);
    }

    let y_client = YClient::new(client, params);
    let query_bytes = target_rows
        .iter()
        .map(|target_row| {
            let raw = y_client.generate_query(SEED_0, params.db_dim_1, true, *target_row);
            wire::encode_u64s(pack_query(params, &raw).as_slice())
        })
        .collect::<Vec<_>>();
    let pub_param_bytes = wire::encode_matrices(&rows);
    Ok((
        Session {
            params,
            y_client,
            entry_bytes,
        },
        query_bytes,
        pub_param_bytes,
    ))
}

fn query(payload: &[u8]) -> Result<(Session, Vec<u8>), String> {
    let count = read_u32(payload, 0).ok_or("missing count")? as usize;
    let entry_bytes = read_u32(payload, 4).ok_or("missing entry size")? as usize;
    let target_row = read_u32(payload, 8).ok_or("missing target row")? as usize;
    let (session, mut queries, pub_param_bytes) =
        generate_queries(count, entry_bytes, &[target_row])?;
    let query_bytes = queries.remove(0);
    let mut out = Vec::with_capacity(8 + query_bytes.len() + pub_param_bytes.len());
    out.extend_from_slice(&(query_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(pub_param_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&query_bytes);
    out.extend_from_slice(&pub_param_bytes);
    Ok((session, out))
}

fn query_batch(payload: &[u8]) -> Result<(Session, Vec<u8>), String> {
    let count = read_u32(payload, 0).ok_or("missing count")? as usize;
    let entry_bytes = read_u32(payload, 4).ok_or("missing entry size")? as usize;
    let target_count = read_u32(payload, 8).ok_or("missing target count")? as usize;
    if target_count == 0
        || target_count > MAX_BATCH_QUERIES
        || payload.len() != 12 + target_count * 4
    {
        return Err("invalid batch query shape".to_string());
    }
    let target_rows = (0..target_count)
        .map(|index| {
            read_u32(payload, 12 + index * 4)
                .map(|value| value as usize)
                .ok_or("missing target row")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (session, queries, pub_param_bytes) = generate_queries(count, entry_bytes, &target_rows)?;
    let query_bytes = wire::encode_batch(&queries);
    let mut out = Vec::with_capacity(8 + query_bytes.len() + pub_param_bytes.len());
    out.extend_from_slice(&(query_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(pub_param_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&query_bytes);
    out.extend_from_slice(&pub_param_bytes);
    Ok((session, out))
}

fn decode(session: &Session, payload: &[u8]) -> Result<Vec<u8>, String> {
    let part_count = read_u32(payload, 0).ok_or("missing part count")? as usize;
    if part_count == 0 || part_count > 4096 {
        return Err("unreasonable response shape".to_string());
    }
    let params = session.params;
    let pt_bits = (params.pt_modulus as f64).log2().floor() as usize;

    let mut offset = 4usize;
    let mut words = Vec::new();
    for _ in 0..part_count {
        let len = read_u32(payload, offset).ok_or("truncated response")? as usize;
        offset += 4;
        let part = payload
            .get(offset..offset + len)
            .ok_or("truncated response")?;
        offset += len;
        let ct =
            PolyMatrixRaw::recover(params, params.get_q_prime_1(), params.get_q_prime_2(), part);
        words.extend_from_slice(
            decrypt_ct_reg_measured(
                session.y_client.client(),
                params,
                &ct.ntt(),
                params.poly_len,
            )
            .as_slice(),
        );
    }
    if offset != payload.len() {
        return Err("response has trailing bytes".to_string());
    }
    Ok(unpack_record(&words, pt_bits, session.entry_bytes))
}

fn decode_batch(session: &Session, payload: &[u8]) -> Result<Vec<u8>, String> {
    let responses = wire::decode_batch(payload, MAX_BATCH_QUERIES, MAX_FRAME_BYTES)
        .ok_or("malformed batch response")?;
    let mut out = Vec::with_capacity(responses.len() * session.entry_bytes);
    for response in responses {
        out.extend_from_slice(&decode(session, response)?);
    }
    Ok(out)
}

fn main() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let mut sessions: HashMap<u32, Session> = HashMap::new();
    let mut next_session_id = 1u32;

    while let Some(frame) = read_frame(&mut input)? {
        let op = frame[0];
        let payload = &frame[1..];
        let result = match op {
            OP_QUERY if sessions.len() >= MAX_ACTIVE_SESSIONS => {
                Err("too many active PIR sessions".to_string())
            }
            OP_QUERY => match query(payload) {
                Ok((new_session, response)) => {
                    while next_session_id == 0 || sessions.contains_key(&next_session_id) {
                        next_session_id = next_session_id.wrapping_add(1);
                    }
                    let session_id = next_session_id;
                    next_session_id = next_session_id.wrapping_add(1);
                    sessions.insert(session_id, new_session);
                    let mut identified = Vec::with_capacity(4 + response.len());
                    identified.extend_from_slice(&session_id.to_le_bytes());
                    identified.extend_from_slice(&response);
                    Ok(identified)
                }
                Err(error) => Err(error),
            },
            OP_QUERY_BATCH if sessions.len() >= MAX_ACTIVE_SESSIONS => {
                Err("too many active PIR sessions".to_string())
            }
            OP_QUERY_BATCH => match query_batch(payload) {
                Ok((new_session, response)) => {
                    while next_session_id == 0 || sessions.contains_key(&next_session_id) {
                        next_session_id = next_session_id.wrapping_add(1);
                    }
                    let session_id = next_session_id;
                    next_session_id = next_session_id.wrapping_add(1);
                    sessions.insert(session_id, new_session);
                    let mut identified = Vec::with_capacity(4 + response.len());
                    identified.extend_from_slice(&session_id.to_le_bytes());
                    identified.extend_from_slice(&response);
                    Ok(identified)
                }
                Err(error) => Err(error),
            },
            OP_DECODE => {
                let session_id = read_u32(payload, 0).ok_or("missing session id");
                match session_id {
                    Ok(session_id) => match sessions.remove(&session_id) {
                        Some(active) => decode(&active, &payload[4..]),
                        None => Err("unknown PIR session".to_string()),
                    },
                    Err(error) => Err(error.to_string()),
                }
            }
            OP_DECODE_BATCH => {
                let session_id = read_u32(payload, 0).ok_or("missing session id");
                match session_id {
                    Ok(session_id) => match sessions.remove(&session_id) {
                        Some(active) => decode_batch(&active, &payload[4..]),
                        None => Err("unknown PIR session".to_string()),
                    },
                    Err(error) => Err(error.to_string()),
                }
            }
            OP_DISCARD => {
                if payload.len() != 4 {
                    Err("invalid discard request".to_string())
                } else {
                    let session_id = read_u32(payload, 0).unwrap();
                    sessions.remove(&session_id);
                    Ok(Vec::new())
                }
            }
            _ => Err(format!("unknown operation {op}")),
        };
        match result {
            Ok(response) => write_frame(&mut output, STATUS_OK, &response)?,
            Err(error) => write_frame(&mut output, STATUS_ERROR, error.as_bytes())?,
        }
    }
    Ok(())
}
