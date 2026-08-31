//! Spawns the real worker binary and drives its wire protocol end to end.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use spiral_rs::client::*;
use spiral_rs::params::Params;
use spiral_rs::poly::{PolyMatrix, PolyMatrixRaw};

use ypir::client::*;
use ypir::modulus_switch::ModulusSwitch;
use ypir::packing::condense_matrix;
use ypir::params::{params_for_scenario_simplepir, GetQPrime};
use ypir::qorc_spool::{unpack_record, wire};
use ypir::scheme::{SEED_0, STATIC_SEED_2};

const OP_BUILD: u8 = 1;
const OP_ANSWER: u8 = 2;
const OP_INFO: u8 = 3;
const ENTRY_BYTES: usize = 10944;
const COUNT: usize = 512;

fn record(seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..ENTRY_BYTES)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state & 0xFF) as u8
        })
        .collect()
}

fn send(child: &mut Child, op: u8, payload: &[u8]) -> (u8, Vec<u8>) {
    let stdin = child.stdin.as_mut().unwrap();
    let length = (payload.len() + 1) as u32;
    stdin.write_all(&length.to_le_bytes()).unwrap();
    stdin.write_all(&[op]).unwrap();
    stdin.write_all(payload).unwrap();
    stdin.flush().unwrap();

    let stdout = child.stdout.as_mut().unwrap();
    let mut header = [0u8; 4];
    stdout.read_exact(&mut header).unwrap();
    let mut frame = vec![0u8; u32::from_le_bytes(header) as usize];
    stdout.read_exact(&mut frame).unwrap();
    (frame[0], frame[1..].to_vec())
}

fn worker_path() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("qorc-pir-worker")
}

#[test]
fn worker_answers_a_query_with_the_requested_entry() {
    let records: Vec<Vec<u8>> = (0..COUNT).map(|i| record(i as u64 + 1)).collect();
    let dir = std::env::temp_dir().join(format!("qorc-pir-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("records.bin");
    std::fs::write(&path, records.concat()).unwrap();

    let mut child = Command::new(worker_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("worker binary should be built; run `cargo build --release --bin qorc-pir-worker`");

    let epoch: u32 = 4242;
    let mut build = Vec::new();
    build.extend_from_slice(&epoch.to_le_bytes());
    build.extend_from_slice(&(COUNT as u32).to_le_bytes());
    build.extend_from_slice(&(ENTRY_BYTES as u32).to_le_bytes());
    build.extend_from_slice(path.to_str().unwrap().as_bytes());

    let (status, response) = send(&mut child, OP_BUILD, &build);
    assert_eq!(
        status,
        0,
        "build failed: {}",
        String::from_utf8_lossy(&response)
    );
    let db_rows = u32::from_le_bytes(response[4..8].try_into().unwrap()) as usize;
    assert_eq!(
        u32::from_le_bytes(response[0..4].try_into().unwrap()),
        epoch
    );

    let params: Params =
        params_for_scenario_simplepir(COUNT.next_power_of_two().max(2048), ENTRY_BYTES * 8);
    let pt_bits = (params.pt_modulus as f64).log2().floor() as usize;

    for &target_row in &[0usize, 3, 100, COUNT - 1] {
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
        let mut rows = pack_pub_params.to_vec();
        for i in 0..pack_pub_params.len() {
            rows[i] = pack_pub_params[i].submatrix(1, 0, 1, pack_pub_params[i].cols);
            rows[i] = condense_matrix(&params, &rows[i]);
        }

        let y_client = YClient::new(&mut client, &params);
        let query = y_client.generate_query(SEED_0, params.db_dim_1, true, target_row);
        assert_eq!(query.len(), db_rows);
        let query_bytes = wire::encode_u64s(pack_query(&params, &query).as_slice());
        let pub_param_bytes = wire::encode_matrices(&rows);

        let mut payload = Vec::new();
        payload.extend_from_slice(&epoch.to_le_bytes());
        payload.extend_from_slice(&(query_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(&query_bytes);
        payload.extend_from_slice(&pub_param_bytes);

        let (status, response) = send(&mut child, OP_ANSWER, &payload);
        assert_eq!(
            status,
            0,
            "answer failed: {}",
            String::from_utf8_lossy(&response)
        );

        let part_count = u32::from_le_bytes(response[0..4].try_into().unwrap()) as usize;
        let mut offset = 4usize;
        let mut parts = Vec::with_capacity(part_count);
        for _ in 0..part_count {
            let len = u32::from_le_bytes(response[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            parts.push(response[offset..offset + len].to_vec());
            offset += len;
        }

        let outer_ct = parts
            .iter()
            .map(|bytes| {
                PolyMatrixRaw::recover(
                    &params,
                    params.get_q_prime_1(),
                    params.get_q_prime_2(),
                    bytes,
                )
            })
            .flat_map(|ct| {
                decrypt_ct_reg_measured(y_client.client(), &params, &ct.ntt(), params.poly_len)
                    .as_slice()
                    .to_vec()
            })
            .collect::<Vec<_>>();

        assert_eq!(
            unpack_record(&outer_ct, pt_bits, ENTRY_BYTES),
            records[target_row],
            "row {target_row} did not round-trip through the worker"
        );
    }

    // A query for an epoch the worker is not holding must be refused rather than
    // answered against a different view of the spool.
    let mut stale = Vec::new();
    stale.extend_from_slice(&(epoch + 1).to_le_bytes());
    stale.extend_from_slice(&0u32.to_le_bytes());
    let (status, _) = send(&mut child, OP_ANSWER, &stale);
    assert_eq!(status, 1, "stale epoch was accepted");

    let (status, response) = send(&mut child, OP_INFO, &[]);
    assert_eq!(status, 0);
    assert_eq!(
        u32::from_le_bytes(response[0..4].try_into().unwrap()),
        epoch
    );

    drop(child.stdin.take());
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
