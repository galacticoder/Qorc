# Qor hintless-SimplePIR worker + client

Reviewed PIR-math boundary. The app/server JavaScript and the Tauri client never
implement PIR cryptography — they upload fixed-size records and forward opaque
proto queries to these two binaries, built from the **vendored** Google
[`hintless_pir`](https://github.com/google/hintless_pir) source in
[`upstream/`](./upstream) (pinned commit in
[`hintless.lock.json`](./hintless.lock.json)) plus our thin overlay in `src/`.
The build does **not** clone from GitHub — everything needed is in this directory.
(Bazel still resolves its own module deps on a clean build, pinned by
`upstream/MODULE.bazel.lock` and cached in the Docker layer.)

Layout:
```
workers/hintless/
  upstream/        vendored google/hintless_pir source (pinned)
  src/             our worker + client + shared header
  third_party/     pinned cpp-httplib + nlohmann/json
  BUILD.overlay    Bazel targets, overlaid as //qor
  Dockerfile       COPYs upstream + overlay, bazel build -c opt
  hintless.lock.json
```

Hintless SimplePIR outsources the SimplePIR *hint* to the server's LinPIR work,
so there is **no client hint download** (the old SimplePIR scheme made the client
pull a ~64 MB hint per epoch over Tor). The client downloads only a ~350-byte
hint-free public-params blob per epoch.

## Binaries

- **`qor-pir-worker`** — server-side HTTP service (localhost). Builds and
  preprocesses a hintless-SimplePIR `Server` per `(kind, epoch)` and answers
  opaque queries.
  - `GET  /health`
  - `POST /v1/databases`     upload fixed-size records → build + preprocess; returns hint-free public params
  - `POST /v1/public-params` fetch the public params for an epoch
  - `POST /v1/query`         answer one opaque `HintlessPirRequest`
- **`qor-pir-client`** — client-side helper the Tauri app shells out to.
  Length-prefixed JSON framing (`serve`) or single-shot. Record-major:
  `query-record` (build request, keep the client secret under a handle) and
  `recover-record` (recover using the stored secret).

## Cost model (why records are small)

Built `-c opt`, cost scales with **record size**, not record count:

| record bytes | preprocess | query compute | query download |
|---|---|---|---|
| 8  | ~4 s  | ~0.4 s | ~1.9 MB |
| 16 | ~9 s  | ~0.5 s | ~3.8 MB |
| 32 | ~15 s | ~0.7 s | ~7.7 MB |

Upload is a fixed ~480 KiB/query (the LinPIR query + Galois key, sent every query
so the server keeps no per-client state). Download is ~240 KiB per record-byte.
A 1024×1024 = ~1M-record database answers a query in ~0.43 s — DB size is nearly
free. **Therefore PIR records must be tiny.** Discovery uses a two-tier scheme:
the PIR record is an ~8–16 byte pointer; the large encrypted bundle is fetched
directly by that pointer (a normal fetch, not PIR).

## Build / test

```sh
docker build -t qor-pir-worker workers/hintless        # builds -c opt, ships the worker
# local contract test (needs a built worker + client and node):
node workers/hintless/contract_test.mjs <worker_url> <path/to/qor-pir-client>
```

## Wire format

Opaque `query`/`response` strings are `base64url(proto bytes)` of
`HintlessPirRequest` / `HintlessPirResponse`. Public params are
`base64url(HintlessPirServerPublicParams)`. Database geometry
(`db_rows`, `db_cols`) is a deterministic pure function of `(recordCount,
recordSize)` in `qor_pir_common.h`, so the client and worker agree without
transmitting it.
