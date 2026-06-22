# Qor-Chat

Qor-Chat is a Tauri desktop chat app and Node.js server for private one-to-one
messaging, offline delivery, and calls. It combines Signal Protocol/PQXDH,
post-quantum hybrid envelopes, Tor-routed server traffic, oblivious discovery,
and an optional P2P path.

Current architecture docs:
- [Authentication](docs/app/AUTHENTICATION.md)
- [Discovery](docs/app/DISCOVERY.md)
- [Computational PIR](docs/app/COMPUTATIONAL_PIR.md)
- [Messaging cryptography](docs/app/MESSAGING_CRYPTOGRAPHY.md)
- [Offline messaging](docs/app/OFFLINE_MESSAGING.md)
- [Avatars](docs/app/AVATARS.md)
- [Environment variables](docs/ENVIRONMENT_VARIABLES.md)

## What this project is for

- Privacy-preserving one-to-one messaging with forward secrecy and
  post-quantum protection.
- Anonymous account entry and resume flows using OPAQUE, oblivious lookup, and
  Privacy Pass style tokens.
- Discovery that avoids exact handle lookups through OPRF, HintlessPIR, and
  k-anonymous bucket retrieval.
- Server fallback delivery through a sealed global mix spool, plus direct P2P
  delivery when peers can connect.
- Self-hosted deployment with Redis, Postgres, PIR workers, optional clustering,
  and an HAProxy edge tier.

Qor-Chat is not a metadata-free system. The server can still observe timing,
connection state, traffic volume, rounded database sizes, and some bucketed or
cover-traffic protocol artifacts. Message contents, local history, avatars, and
discovery payloads are encrypted end-to-end.

## Setup

### Prerequisites

- Node.js 18 or newer.
- pnpm, normally through Corepack:

  ```bash
  corepack enable pnpm
  ```

- Rust/Cargo for the Tauri desktop build.
- Docker for Docker deployment and for building the pinned PIR client helper.
- On Linux, WebKitGTK/Tauri system packages are also required by Tauri.

Windows can build and run the desktop client, but local server deployment is not
supported by `scripts/start-server.cjs`; use Docker for the server on Windows.

### Install dependencies

```bash
node scripts/install-deps.cjs --server
node scripts/install-deps.cjs --client
```

The server installer targets Linux/macOS server dependencies such as TLS-capable
Redis, Postgres, OpenSSL, Tailscale, and build tools. The client installer checks
Node, pnpm, Rust, build tools, and Tauri dependencies.

### Configure environment

Create or update `.env` for the server before starting it. Required values depend
on whether you run locally or through Docker, but the important ones are TLS
certificate paths, Redis/Postgres settings, `SERVER_PASSWORD`, and persistent
server secrets. See [docs/ENVIRONMENT_VARIABLES.md](docs/ENVIRONMENT_VARIABLES.md)
for the full list.

For Tailscale TLS certificates, use:

```bash
node scripts/generate_ts_tls.cjs
```

### Run locally

Start the server:

```bash
node scripts/start-server.cjs
```

Start the desktop client:

```bash
node scripts/start-client.cjs
```

`start-client.cjs` builds the pinned HintlessPIR client helper, runs a Tauri
release build, and then launches the built app. To skip rebuilding and launch an
existing binary:

```bash
node scripts/start-client.cjs --run-only
```

### Docker deployment

Start the server stack:

```bash
node scripts/start-docker.cjs server
```

The server profile starts Postgres, Redis, the HintlessPIR worker, and the Node
server. Add `--build` to rebuild images:

```bash
node scripts/start-docker.cjs server --build
```

Start the load balancer:

```bash
node scripts/start-docker.cjs loadbalancer
```

Useful Docker helper commands:

```bash
node scripts/start-docker.cjs logs server
node scripts/start-docker.cjs stop server
node scripts/start-docker.cjs stop all
node scripts/start-docker.cjs reset
```

## Security model at a glance

- Authentication uses OPAQUE with oblivious record lookup, connection-bound login
  nonces, anonymous sessions, and one-time Privacy Pass style resume/server-entry
  tokens.
- Message content is protected by libsignal's Double Ratchet with PQXDH/Kyber
  pre-keys.
- Messages are wrapped in a hybrid ML-KEM-1024 + X25519 envelope, with ML-DSA-87
  signatures for sender and routing-header authentication.
- P2P delivery uses iroh QUIC with a mutually authenticated PQ-Noise session.
- Server fallback delivery uses sealed-sender envelopes written to a shared
  global mix spool. Recipients trial-decrypt candidates locally.
- Server-bound traffic goes through Tor. Discovery, PIR, OPRF, avatar upload, and
  avatar fetch paths use isolated Tor circuits where supported.
- Local history, queues, block lists, profile data, and file metadata are stored
  in the encrypted local database.

## Discovery and avatars

Discovery resolves a user's current encrypted key material without sending a
plaintext handle to the server.

- The client derives an OPRF token for the handle and epoch.
- Tier 1 uses Google HintlessPIR through the pinned worker in
  `workers/hintless/`.
- Larger encrypted key blobs are fetched by k-anonymous bucket retrieval and
  decrypt-filtered locally.
- Avatars are not embedded in discovery records. They are stored as encrypted,
  uniform-size blobs in an unlinkable content store and fetched with cover
  traffic.

## Offline delivery

There is no per-user offline mailbox. Server-routed messages enter a shared global
mix spool as sealed encrypted envelopes. Offline clients fetch the same padded,
gzipped spool snapshot as every other client, verify it locally, and try to
decrypt every candidate.

Local retry queues are only for messages the sender cannot encrypt yet, usually
because recipient discovery material is not available locally.

## Development commands

```bash
pnpm run build
pnpm run lint
pnpm run test:security
pnpm run test:pir-worker
```

Server package commands are in [server/package.json](server/package.json), and
Docker orchestration lives in [docker/docker-compose.yml](docker/docker-compose.yml).

## Contributing and reporting issues

Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) before contributing and use
the project issue templates when reporting bugs. Security reports should follow
[SECURITY.md](docs/SECURITY.md).

## License

[![License: qorc Non-Commercial Copyleft v1.0](https://img.shields.io/badge/License-qorc%20Non--Commercial%20Copyleft%20v1.0-6d4aff.svg)](LICENSE)
