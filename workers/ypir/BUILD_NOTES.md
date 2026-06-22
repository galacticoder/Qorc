# YPIR tier-2 worker — build notes (Qor-Chat)

Vendored from [menonsamir/ypir](https://github.com/menonsamir/ypir) (MIT, USENIX Security 2024),
used as the **oblivious tier-2 discovery-blob layer**: tier-1 HintlessPIR (untouched) tells the
client which slot is its target; YPIR (SimplePIR variant) retrieves the ~16 KB blob at that slot
without the server learning which one. See `src/tier2.rs` for the blob<->plaintext codec and the
end-to-end self-test (`tier2_roundtrip_selftest`).

## Hard requirements
- **Toolchain:** the pinned nightly `nightly-2024-02-07` (`rust-toolchain.toml`) — the crate uses
  `#![feature(stdarch_x86_avx512)]`.
- **Server CPU:** AVX-512 (`avx512f`). The heavy DB matmul (`server.rs`, `kernel.rs`, C++ `matmul.cpp`
  built `-march=native`) needs it. The **client** path (`client.rs` query-gen/decode) is AVX-512-free,
  so end-user clients without AVX-512 still work.

## Building inside this repo (important)
The repo root `/.cargo/config.toml` sets `target.x86_64-unknown-linux-gnu.rustflags` (a linker `-L`
shim). In cargo, a **target-specific** `rustflags` *fully replaces* this crate's `build.rustflags`
(`target-cpu=native`) — so the AVX-512 features get silently dropped and the cfg-gated code fails to
compile (`kernel.rs` E0308, `packing.rs` `multiply_no_reduce` not found). Set the flag explicitly via
the `RUSTFLAGS` env (it beats all config files), including the repo's `-L` shim:

```sh
RUSTFLAGS="-C target-cpu=native -L native=$HOME/.local/lib" \
  cargo build --release --bin tier2_selftest
```

Run the end-to-end blob round-trip self-test (builds a 16 KB-blob DB, obliviously retrieves several
slots, asserts each decodes to the exact original blob):

```sh
RUSTFLAGS="-C target-cpu=native -L native=$HOME/.local/lib" \
  cargo run --release --bin tier2_selftest
# -> [tier2-selftest] PASS — all N target slots decoded to the exact original blob
```

When the worker is built standalone (its own dir / Docker, outside this repo's `.cargo/config`), its
own `.cargo/config.toml` (`target-cpu=native`) applies and no override is needed.

## Note on the crate's own tests
`cargo test` inside the vendored crate does not compile (pre-existing: its internal test modules
reference cfg-gated symbols). Our logic is therefore exercised via the `tier2_selftest` **bin** (which
builds only lib + bin, not the test modules) and the standalone codec check — not `cargo test`.

## Local patch to the vendored crate (one line)
`src/server.rs` `perform_offline_precomputation_simplepir` return type: `OfflinePrecomputedValues`
→ `OfflinePrecomputedValues<'a>`. The returned value's data is owned or borrows **params** (not
`&self`/the DB), so tying it to the elided `&self` lifetime was overly conservative and prevented a
long-lived worker from holding the built `YServer` + its `OfflinePrecomputedValues` together
(`tier2::Tier2Worker`). Re-apply this on any re-vendor. (Search "Qor patch" in server.rs.)

## Running the worker (M3d-http)
`src/bin/ypir_worker.rs` is the HTTP shell around `tier2::Tier2Worker`:
```sh
RUSTFLAGS="-C target-cpu=native -L native=$HOME/.local/lib" cargo build --release --bin ypir_worker
YPIR_WORKER_ADDR=127.0.0.1:8788 YPIR_NUM_ITEMS=2048 YPIR_BLOB_LEN=16384 ./target/release/ypir_worker
```
Endpoints: `GET /health`, `GET /v1/info`, `POST /v1/databases` (body = slot-ordered fixed-size
blobs), `POST /v1/query` (body = serialized client query -> response bytes). Single-threaded; the
full query cycle is exercised once the client daemon (M4) exists.

## Client daemon (M4) + full pipeline
`src/bin/ypir_client.rs` — stdin/stdout JSON daemon (one object per line); ops `info`,
`query-record {slot}` -> `{handle, request:b64}`, `recover-record {handle, response:b64}` -> `{blob:b64}`.
It keeps the per-lookup `Client` under `handle` (the `YClient` 2-lifetime "Qor patch" in src/client.rs
lets `make_query` return the Client); decode needs only `&Client`. The daemon never touches the network
— the app moves request/response (e.g. over the dedicated Tor circuit).

Full end-to-end smoke (worker + daemon + query cycle), `pipeline_smoke.py`:
```sh
RUSTFLAGS="-C target-cpu=native -L native=$HOME/.local/lib" cargo build --release --bin ypir_worker --bin ypir_client
YPIR_WORKER_ADDR=127.0.0.1:8792 ./target/release/ypir_worker &   # then:
python3 pipeline_smoke.py    # -> recover-record blob matches the uploaded blob  (per-lookup ~1.1MB up / 61KB down)
```
