//! Drives the two real binaries against each other

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};

const OP_QUERY: u8 = 1;
const OP_DECODE: u8 = 2;
const OP_DISCARD: u8 = 3;
const OP_QUERY_BATCH: u8 = 4;
const OP_DECODE_BATCH: u8 = 5;
const OP_BUILD: u8 = 1;
const OP_ANSWER: u8 = 2;
const OP_ANSWER_BATCH: u8 = 4;

const ENTRY_BYTES: usize = 8192 + 16;
const COUNT: usize = 256;

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

fn call(child: &mut Child, op: u8, payload: &[u8]) -> (u8, Vec<u8>) {
    let stdin = child.stdin.as_mut().unwrap();
    stdin
        .write_all(&((payload.len() + 1) as u32).to_le_bytes())
        .unwrap();
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

fn binary(name: &str) -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join(name)
}

fn spawn(name: &str) -> Child {
    Command::new(binary(name))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{name} should be built: {e}"))
}

#[test]
fn client_and_worker_complete_a_private_retrieval() {
    let records: Vec<Vec<u8>> = (0..COUNT).map(|i| record(i as u64 + 1)).collect();
    let dir = std::env::temp_dir().join(format!("qorc-pir-sidecar-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("records.bin");
    std::fs::write(&path, records.concat()).unwrap();

    let mut worker = spawn("qorc-pir-worker");
    let mut client = spawn("qorc-pir-client");

    let epoch: u32 = 31337;
    let mut build = Vec::new();
    build.extend_from_slice(&epoch.to_le_bytes());
    build.extend_from_slice(&(COUNT as u32).to_le_bytes());
    build.extend_from_slice(&(ENTRY_BYTES as u32).to_le_bytes());
    build.extend_from_slice(path.to_str().unwrap().as_bytes());
    let (status, _) = call(&mut worker, OP_BUILD, &build);
    assert_eq!(status, 0);

    let mut pending = Vec::new();
    for &target in &[0usize, 5, 200, COUNT - 1] {
        let mut request = Vec::new();
        request.extend_from_slice(&(COUNT as u32).to_le_bytes());
        request.extend_from_slice(&(ENTRY_BYTES as u32).to_le_bytes());
        request.extend_from_slice(&(target as u32).to_le_bytes());
        let (status, generated) = call(&mut client, OP_QUERY, &request);
        assert_eq!(status, 0, "query: {}", String::from_utf8_lossy(&generated));

        let session_id = generated[0..4].to_vec();
        let query_len = u32::from_le_bytes(generated[4..8].try_into().unwrap()) as usize;
        let params_len = u32::from_le_bytes(generated[8..12].try_into().unwrap()) as usize;
        let query = &generated[12..12 + query_len];
        let pub_params = &generated[12 + query_len..12 + query_len + params_len];

        let mut answer = Vec::new();
        answer.extend_from_slice(&epoch.to_le_bytes());
        answer.extend_from_slice(&(query.len() as u32).to_le_bytes());
        answer.extend_from_slice(query);
        answer.extend_from_slice(pub_params);
        let (status, response) = call(&mut worker, OP_ANSWER, &answer);
        assert_eq!(status, 0, "answer: {}", String::from_utf8_lossy(&response));
        pending.push((session_id, response, target));
    }
    // HTTP rows complete out of order when four Tor requests are in flight.
    // Every answer must stay bound to the sidecar keys that made its query.
    for (session_id, response, target) in pending.into_iter().rev() {
        let mut decode = Vec::with_capacity(4 + response.len());
        decode.extend_from_slice(&session_id);
        decode.extend_from_slice(&response);
        let (status, decoded) = call(&mut client, OP_DECODE, &decode);
        assert_eq!(status, 0, "decode: {}", String::from_utf8_lossy(&decoded));
        assert_eq!(decoded, records[target], "row {target} did not round-trip");
    }

    let targets = [3usize, 17, COUNT - 2];
    let mut batch_request = Vec::new();
    batch_request.extend_from_slice(&(COUNT as u32).to_le_bytes());
    batch_request.extend_from_slice(&(ENTRY_BYTES as u32).to_le_bytes());
    batch_request.extend_from_slice(&(targets.len() as u32).to_le_bytes());
    for target in targets {
        batch_request.extend_from_slice(&(target as u32).to_le_bytes());
    }
    let (status, generated) = call(&mut client, OP_QUERY_BATCH, &batch_request);
    assert_eq!(
        status,
        0,
        "batch query: {}",
        String::from_utf8_lossy(&generated)
    );
    let session_id = &generated[0..4];
    let query_len = u32::from_le_bytes(generated[4..8].try_into().unwrap()) as usize;
    let params_len = u32::from_le_bytes(generated[8..12].try_into().unwrap()) as usize;
    let mut answer = Vec::new();
    answer.extend_from_slice(&epoch.to_le_bytes());
    answer.extend_from_slice(&(query_len as u32).to_le_bytes());
    answer.extend_from_slice(&generated[12..12 + query_len]);
    answer.extend_from_slice(&generated[12 + query_len..12 + query_len + params_len]);
    let (status, response) = call(&mut worker, OP_ANSWER_BATCH, &answer);
    assert_eq!(
        status,
        0,
        "batch answer: {}",
        String::from_utf8_lossy(&response)
    );
    let mut decode = Vec::with_capacity(4 + response.len());
    decode.extend_from_slice(session_id);
    decode.extend_from_slice(&response);
    let (status, decoded) = call(&mut client, OP_DECODE_BATCH, &decode);
    assert_eq!(
        status,
        0,
        "batch decode: {}",
        String::from_utf8_lossy(&decoded)
    );
    let expected = targets
        .iter()
        .flat_map(|target| records[*target].iter().copied())
        .collect::<Vec<_>>();
    assert_eq!(decoded, expected);

    let mut request = Vec::new();
    request.extend_from_slice(&(COUNT as u32).to_le_bytes());
    request.extend_from_slice(&(ENTRY_BYTES as u32).to_le_bytes());
    request.extend_from_slice(&7u32.to_le_bytes());
    let (_, first) = call(&mut client, OP_QUERY, &request);
    let (_, second) = call(&mut client, OP_QUERY, &request);
    assert_ne!(
        &first[4..],
        &second[4..],
        "repeated queries for one row were identical"
    );
    assert_eq!(call(&mut client, OP_DISCARD, &first[0..4]).0, 0);
    assert_eq!(call(&mut client, OP_DISCARD, &second[0..4]).0, 0);

    drop(worker.stdin.take());
    drop(client.stdin.take());
    let _ = worker.wait();
    let _ = client.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reports_wire_sizes_for_transport_classes() {
    let mut client = spawn("qorc-pir-client");
    for &count in &[1024usize, 4096, 16384] {
        let mut request = Vec::new();
        request.extend_from_slice(&(count as u32).to_le_bytes());
        request.extend_from_slice(&(ENTRY_BYTES as u32).to_le_bytes());
        request.extend_from_slice(&0u32.to_le_bytes());
        let (status, generated) = call(&mut client, OP_QUERY, &request);
        assert_eq!(status, 0);
        let query_len = u32::from_le_bytes(generated[4..8].try_into().unwrap()) as usize;
        let params_len = u32::from_le_bytes(generated[8..12].try_into().unwrap()) as usize;
        println!(
            "count={count} query={query_len} pub_params={params_len} request_total={}",
            query_len + params_len
        );
    }
    
    let records: Vec<Vec<u8>> = (0..COUNT).map(|i| record(i as u64 + 1)).collect();
    let dir = std::env::temp_dir().join(format!("qorc-pir-size-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("records.bin");
    std::fs::write(&path, records.concat()).unwrap();
    let mut worker = spawn("qorc-pir-worker");
    let epoch: u32 = 5;
    let mut build = Vec::new();
    build.extend_from_slice(&epoch.to_le_bytes());
    build.extend_from_slice(&(COUNT as u32).to_le_bytes());
    build.extend_from_slice(&(ENTRY_BYTES as u32).to_le_bytes());
    build.extend_from_slice(path.to_str().unwrap().as_bytes());
    assert_eq!(call(&mut worker, OP_BUILD, &build).0, 0);

    let mut request = Vec::new();
    request.extend_from_slice(&(COUNT as u32).to_le_bytes());
    request.extend_from_slice(&(ENTRY_BYTES as u32).to_le_bytes());
    request.extend_from_slice(&0u32.to_le_bytes());
    let (_, generated) = call(&mut client, OP_QUERY, &request);
    let query_len = u32::from_le_bytes(generated[4..8].try_into().unwrap()) as usize;
    let params_len = u32::from_le_bytes(generated[8..12].try_into().unwrap()) as usize;
    let mut answer = Vec::new();
    answer.extend_from_slice(&epoch.to_le_bytes());
    answer.extend_from_slice(&(query_len as u32).to_le_bytes());
    answer.extend_from_slice(&generated[12..12 + query_len]);
    answer.extend_from_slice(&generated[12 + query_len..12 + query_len + params_len]);
    let (status, response) = call(&mut worker, OP_ANSWER, &answer);
    assert_eq!(status, 0);
    println!("RESPONSE_BYTES={}", response.len());

    drop(worker.stdin.take());
    let _ = worker.wait();
    let _ = std::fs::remove_dir_all(&dir);
    drop(client.stdin.take());
    let _ = client.wait();
}
