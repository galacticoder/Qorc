//! Long-lived PIR worker.
//!
//! Holds one epoch's database and its offline precomputation, and answers
//! queries against it. The offline phase is expensive and the database is
//! hundreds of megabytes, so this is a persistent process rather than a
//! per-query invocation.
//!
//! Framing is length-prefixed binary on stdin/stdout. Queries and expansion
//! parameters are hundreds of kilobytes, and base64 inside JSON would inflate
//! them for no benefit.
//!
//! The worker never learns which row a query selects. That is the whole point of
//! the scheme, and nothing here inspects or logs a query's contents.

use std::io::{self, Read, Write};

use spiral_rs::aligned_memory::AlignedMemory64;
use spiral_rs::params::Params;
use spiral_rs::poly::PolyMatrixNTT;

use ypir::params::{params_for_scenario_simplepir, GetQPrime};
use ypir::qor_spool::{pack_record, wire};
use ypir::server::{DbRowsPadded, OfflinePrecomputedValues, YServer};

const OP_BUILD: u8 = 1;
const OP_ANSWER: u8 = 2;
const OP_INFO: u8 = 3;
const OP_ANSWER_BATCH: u8 = 4;

const STATUS_OK: u8 = 0;
const STATUS_ERROR: u8 = 1;

const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
const MAX_PUB_PARAM_MATRICES: usize = 64;
const MAX_BATCH_QUERIES: usize = 16;

struct Loaded {
    epoch: u32,
    params: Params,
    db_rows: usize,
    db_cols: usize,
    entry_bytes: usize,
}

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
    let length = (payload.len() + 1) as u32;
    output.write_all(&length.to_le_bytes())?;
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

/// Builds the database for one epoch from a flat file of fixed size records.
fn build(payload: &[u8]) -> Result<(Loaded, OfflinePrecomputedValues<'static>), String> {
    let epoch = read_u32(payload, 0).ok_or("missing epoch")?;
    let count = read_u32(payload, 4).ok_or("missing count")? as usize;
    let entry_bytes = read_u32(payload, 8).ok_or("missing entry size")? as usize;
    let path = std::str::from_utf8(payload.get(12..).ok_or("missing path")?)
        .map_err(|_| "path is not utf-8")?;

    if count == 0 || count > 1 << 20 {
        return Err("unreasonable record count".to_string());
    }
    if entry_bytes == 0 || entry_bytes > 1 << 20 {
        return Err("unreasonable entry size".to_string());
    }

    let raw = std::fs::read(path).map_err(|error| format!("cannot read records: {error}"))?;
    if raw.len() != count * entry_bytes {
        return Err(format!(
            "record file is {} bytes, expected {}",
            raw.len(),
            count * entry_bytes
        ));
    }

    // Leaked deliberately, the server borrows `Params` for its whole lifetime and
    // this process holds exactly one database until it is replaced or exits.
    let params: &'static Params = Box::leak(Box::new(params_for_scenario_simplepir(
        count.next_power_of_two().max(2048),
        entry_bytes * 8,
    )));
    let pt_bits = (params.pt_modulus as f64).log2().floor() as usize;
    let db_rows = 1usize << (params.db_dim_1 + params.poly_len_log2);
    let db_cols = params.instances * params.poly_len;

    if count > db_rows {
        return Err(format!("{count} records exceed {db_rows} rows"));
    }

    let mut flat = Vec::with_capacity(db_rows * db_cols);
    for index in 0..db_rows {
        if index < count {
            let start = index * entry_bytes;
            flat.extend_from_slice(&pack_record(
                &raw[start..start + entry_bytes],
                pt_bits,
                db_cols,
            ));
        } else {
            flat.extend(std::iter::repeat_n(0u16, db_cols));
        }
    }

    let server: &'static YServer<'static, u16> = Box::leak(Box::new(YServer::<u16>::new(
        params,
        flat.into_iter(),
        true,
        false,
        true,
    )));
    let offline = server.perform_offline_precomputation_simplepir(None);

    let loaded = Loaded {
        epoch,
        params: params.clone(),
        db_rows,
        db_cols,
        entry_bytes,
    };
    SERVER.with(|slot| *slot.borrow_mut() = Some(server));
    Ok((loaded, offline))
}

thread_local! {
    static SERVER: std::cell::RefCell<Option<&'static YServer<'static, u16>>> =
        const { std::cell::RefCell::new(None) };
}

fn answer(
    loaded: &Loaded,
    offline: &OfflinePrecomputedValues<'static>,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let epoch = read_u32(payload, 0).ok_or("missing epoch")?;
    if epoch != loaded.epoch {
        return Err(format!("epoch {epoch} is not loaded"));
    }
    let query_len = read_u32(payload, 4).ok_or("missing query length")? as usize;
    let query_bytes = payload.get(8..8 + query_len).ok_or("truncated query")?;
    let pub_param_bytes = payload.get(8 + query_len..).ok_or("truncated parameters")?;

    let pub_params = wire::decode_matrices(&loaded.params, pub_param_bytes, MAX_PUB_PARAM_MATRICES)
        .ok_or("malformed expansion parameters")?;
    answer_query(loaded, offline, query_bytes, &pub_params)
}

fn answer_query(
    loaded: &Loaded,
    offline: &OfflinePrecomputedValues<'static>,
    query_bytes: &[u8],
    pub_params: &[PolyMatrixNTT<'_>],
) -> Result<Vec<u8>, String> {
    let query = wire::decode_u64s(query_bytes).ok_or("malformed query")?;
    if query.len() != loaded.db_rows {
        return Err(format!(
            "query covers {} rows, database has {}",
            query.len(),
            loaded.db_rows
        ));
    }

    let mut packed = AlignedMemory64::new(loaded.params.db_rows_padded());
    packed.as_mut_slice()[..loaded.db_rows].copy_from_slice(&query);

    let server = SERVER
        .with(|slot| *slot.borrow())
        .ok_or("no database loaded")?;
    let response = server.perform_online_computation_simplepir(
        packed.as_slice(),
        offline,
        &[pub_params],
        None,
    );

    let mut out = Vec::new();
    out.extend_from_slice(&(response.len() as u32).to_le_bytes());
    for part in &response {
        out.extend_from_slice(&(part.len() as u32).to_le_bytes());
        out.extend_from_slice(part);
    }
    Ok(out)
}

fn answer_batch(
    loaded: &Loaded,
    offline: &OfflinePrecomputedValues<'static>,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let epoch = read_u32(payload, 0).ok_or("missing epoch")?;
    if epoch != loaded.epoch {
        return Err(format!("epoch {epoch} is not loaded"));
    }
    let query_len = read_u32(payload, 4).ok_or("missing query length")? as usize;
    let query_bytes = payload
        .get(8..8 + query_len)
        .ok_or("truncated query batch")?;
    let pub_param_bytes = payload.get(8 + query_len..).ok_or("truncated parameters")?;
    let queries = wire::decode_batch(query_bytes, MAX_BATCH_QUERIES, MAX_FRAME_BYTES)
        .ok_or("malformed query batch")?;
    let pub_params = wire::decode_matrices(&loaded.params, pub_param_bytes, MAX_PUB_PARAM_MATRICES)
        .ok_or("malformed expansion parameters")?;
    let answers = queries
        .iter()
        .map(|query| answer_query(loaded, offline, query, &pub_params))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(wire::encode_batch(&answers))
}

fn info(loaded: Option<&Loaded>) -> Vec<u8> {
    let mut out = Vec::new();
    match loaded {
        Some(state) => {
            out.extend_from_slice(&state.epoch.to_le_bytes());
            out.extend_from_slice(&(state.db_rows as u32).to_le_bytes());
            out.extend_from_slice(&(state.db_cols as u32).to_le_bytes());
            out.extend_from_slice(&(state.entry_bytes as u32).to_le_bytes());
            out.extend_from_slice(&state.params.get_q_prime_1().to_le_bytes());
            out.extend_from_slice(&state.params.get_q_prime_2().to_le_bytes());
        }
        None => out.extend_from_slice(&u32::MAX.to_le_bytes()),
    }
    out
}

fn main() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();

    let mut loaded: Option<Loaded> = None;
    let mut offline: Option<OfflinePrecomputedValues<'static>> = None;

    while let Some(frame) = read_frame(&mut input)? {
        let op = frame[0];
        let payload = &frame[1..];
        let result = match op {
            OP_BUILD => match build(payload) {
                Ok((state, values)) => {
                    let response = info(Some(&state));
                    loaded = Some(state);
                    offline = Some(values);
                    Ok(response)
                }
                Err(error) => Err(error),
            },
            OP_ANSWER => match (loaded.as_ref(), offline.as_ref()) {
                (Some(state), Some(values)) => answer(state, values, payload),
                _ => Err("no database loaded".to_string()),
            },
            OP_INFO => Ok(info(loaded.as_ref())),
            OP_ANSWER_BATCH => match (loaded.as_ref(), offline.as_ref()) {
                (Some(state), Some(values)) => answer_batch(state, values, payload),
                _ => Err("no database loaded".to_string()),
            },
            _ => Err(format!("unknown operation {op}")),
        };

        match result {
            Ok(response) => write_frame(&mut output, STATUS_OK, &response)?,
            Err(error) => write_frame(&mut output, STATUS_ERROR, error.as_bytes())?,
        }
    }
    Ok(())
}
