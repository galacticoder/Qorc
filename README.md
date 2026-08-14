# Qor-Chat

Qor-Chat is a Tauri desktop chat app and Node.js server for private one-to-one
messaging, offline delivery, and calls. It combines Signal Protocol PQXDH/SPQR,
hybrid post-quantum application envelopes, Tor-routed server traffic, encrypted
discovery, and a direct P2P path.

Current architecture docs:
- [Authentication](docs/app/AUTHENTICATION.md)
- [Discovery](docs/app/DISCOVERY.md)
- [Key transparency](docs/app/KEY_TRANSPARENCY.md)
- [Messaging](docs/app/MESSAGING.md)
- [Messaging cryptography](docs/app/MESSAGING_CRYPTOGRAPHY.md)
- [Offline messaging](docs/app/OFFLINE_MESSAGING.md)
- [Calling](docs/app/CALLING.md)
- [Avatars](docs/app/AVATARS.md)
- [Environment variables](docs/ENVIRONMENT_VARIABLES.md)
- [Security audit and fix ledger](SECURITY_AUDIT_FIXES.txt)

## What this project is for

- Privacy-preserving one-to-one messaging with forward secrecy and mandatory
  hybrid post-quantum application-layer protection.
- Anonymous account entry and resume flows using OPAQUE, oblivious lookup, and
  Privacy Pass style tokens.
- Discovery that avoids sending plaintext handles through a VOPRF and
  fixed-shape k-anonymous bucket retrieval.
- Private append-only key transparency that authorizes discovered account roots,
  monitors contacts, and gossips signed tree heads inside encrypted messages.
- Server fallback delivery through a sealed global mix spool, plus direct P2P
  delivery when peers can connect.
- Self-hosted deployment with Redis, Postgres, optional clustering,
  and an HAProxy edge tier.

Qor-Chat is not a metadata-free system. The server can still observe timing,
connection state, traffic volume, rounded database sizes, and some bucketed or
cover-traffic protocol artifacts.

## Setup

### Prerequisites

- Node.js 18 or newer.
- pnpm, normally through Corepack:

  ```bash
  corepack enable pnpm
  ```

- Rust/Cargo for the Tauri desktop build.
- Docker for Docker deployment.
- On Linux, WebKitGTK/Tauri system packages are also required by Tauri.

Windows can build and run the desktop client, but local server deployment is not
supported by `scripts/start-server.cjs`; use Docker for the server on Windows.

### Install dependencies

```bash
node scripts/install-deps.cjs --server
node scripts/install-deps.cjs --client
```

The server installer targets Linux/macOS server dependencies such as TLS-capable
Redis, Postgres, OpenSSL, and build tools. The client installer checks
Node, pnpm, Rust, build tools, and Tauri dependencies.

### Configure environment

Create or update `.env` for the server before starting it. Required values depend
on whether you run locally or through Docker, but the important ones are TLS
certificate paths, Redis/Postgres settings, `SERVER_PASSWORD`, and persistent
server secrets. See [docs/ENVIRONMENT_VARIABLES.md](docs/ENVIRONMENT_VARIABLES.md)
for the full list.

To generate the server's TLS certificate (self-signed), use:

```bash
node scripts/generate_tls.cjs
```

Clients reach the server through its Tor onion service, so the onion address is
the cryptographic root of trust and a self-signed certificate is sufficient. Pass
`--force` to regenerate, or set `TLS_CERT_CN` to override the certificate CN.

### Run locally

Start the desktop client:

```bash
node scripts/start-client.cjs
```

### Docker deployment

Start the server stack:

```bash
node scripts/start-docker.cjs server
```

The server profile starts Postgres, Redis, and the Node server. Add `--build` to
rebuild images:

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

- Authentication uses OPAQUE with fixed-set oblivious record transfer,
  connection-bound login nonces, and one-time Privacy Pass style
  resume/server-entry tokens.
- Message content is protected by libsignal's Double Ratchet, PQXDH ML-KEM
  prekeys, mandatory SPQR v1 state, and an additional required ML-KEM envelope
  around every Signal ciphertext.
- Messages are wrapped in a hybrid ML-KEM-1024 + X25519 envelope, with ML-DSA-87
  signatures for sender and routing-header authentication.
- P2P delivery uses ephemeral Tor v3 onion services over TCP with a mutually
  authenticated hybrid PQ-Noise application session.
- Server fallback delivery uses sealed-sender envelopes written to a shared
  global mix spool. Recipients trial-decrypt candidates locally.
- Server-bound traffic goes through Tor. Discovery buckets, OPRF evaluation,
  key-transparency operations, avatar operations, and offline spool retrieval use
  one padded hybrid-PQ HTTP route and a fresh Tor-isolated connection for every
  request.
- Discovery keys are accepted only when their account root matches the verified
  append-only transparency state. Root changes revoke Signal and P2P trust before
  the local checkpoint advances.
- Local history, queues, block lists, profile data, and file metadata are stored
  in the encrypted, account-bound native database. The random account master,
  persistent identity keys, Signal state, database keys, and token-vault keys
  stay in Rust; the renderer receives public keys and purpose-bound operations.
  Decrypted conversation state is limited to 50 messages per conversation.
  Account transitions invalidate pending async work before slow key cleanup
  begins. See [Local data security](docs/app/LOCAL_DATA_SECURITY.md).

### Quantum-resistance boundary

Qor-Chat is a hybrid system, not a claim that every dependency and network layer
is post-quantum. Current message payloads require ML-KEM-1024 confidentiality and
ML-DSA-87 authentication layers, and Signal sessions require PQXDH plus SPQR v1.
The classical X25519 contributions remain in the hybrid derivations so security
does not depend on only one primitive family.

Qor-controlled client-facing TLS key establishment allows only the hybrid
`X25519MLKEM768` group; TLS resumption and early data are disabled on the
client/server path. OPAQUE/VOPRF, Ristretto-based discovery and Privacy Pass,
Signal identity keys, Tor path establishment, and TLS certificate signatures
still contain classical public-key cryptography.
Application-layer hybrid encryption protects message bytes carried over those
channels, but does not make availability, traffic analysis, discovery, or the
whole transport stack post-quantum. The protocol has not received an independent
formal cryptographic audit; see the detailed limitations in
[Messaging cryptography](docs/app/MESSAGING_CRYPTOGRAPHY.md).

## Discovery and avatars

Discovery resolves a user's current encrypted key material without sending a
plaintext handle to the server.

- The client blinds a normalized handle for a verifiable OPRF evaluation, then
  derives an epoch token locally.
- Each lookup fetches four fixed-size buckets: one token-derived bucket and three
  random cover buckets. Every bucket is padded to a fixed entry count.
- Encrypted fixed-size identity blobs are decrypt-filtered and identity-validated
  locally, then authorized against the append-only key-transparency map. The
  server sees the requested bucket set, timing, and volume, so discovery remains
  k-anonymous retrieval rather than oblivious retrieval.
- Avatars are not embedded in discovery records. They are stored as encrypted,
  uniform-size blobs in an ownerless opaque content store and fetched with cover
  traffic. Timing and the server-visible ten-ID candidate batch remain
  correlatable metadata.

## Offline delivery

There is no per-user offline mailbox. Server-routed messages enter a shared global
mix spool as sealed encrypted envelopes, all of one fixed size. Offline clients
fetch a compact tag index — identical for every client — recognise their own
entries from a trapdoor only they can compute, and retrieve each one by private
information retrieval, so the server never learns which entry was taken. File
transfers are live/peer-to-peer only and are not retrievable while offline.

Local retry queues are only for messages the sender cannot encrypt yet, usually
because recipient discovery material is not available locally. Local retries,
the server mix-recovery pool, and the encrypted global spool all expire after at
most one hour.

Call signaling is live-only and never enters reconnect recovery or the offline
spool. Incoming ringing also requires current key-transparency authorization
and prior deliberate local contact with that peer. The complete signaling,
admission, direct-media, cryptography, retry, and cleanup architecture is in
[Calling](docs/app/CALLING.md).

## Development commands

```bash
pnpm run build
node scripts/start-client.cjs --bundle-only
pnpm run lint
pnpm run test:security
```

`start-client.cjs` builds the Tauri application for the current OS. Run it on
Windows to produce the Windows `.msi` and NSIS `.exe` installers under
`src-tauri/target/release/bundle`.

Linux and Windows desktop releases are self-contained: the target-matched Tor
Expert Bundle and PIR client are authenticated and embedded into `qor` or
`qor.exe`. Tor is materialized into the private app-data directory during native
startup, so end users do not install Tor separately and the app never downloads
Tor executable code at runtime. Vendored Tor provenance and update instructions
are in [src-tauri/vendor/tor/README.md](src-tauri/vendor/tor/README.md).

Server package commands are in [server/package.json](server/package.json), and
Docker orchestration lives in [docker/docker-compose.yml](docker/docker-compose.yml).

## Contributing and reporting issues

Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) before contributing and use
the project issue templates when reporting bugs. Security reports should follow
[SECURITY.md](docs/SECURITY.md).

## License

[![License: qorc Non-Commercial Copyleft v1.0](https://img.shields.io/badge/License-qorc%20Non--Commercial%20Copyleft%20v1.0-6d4aff.svg)](LICENSE)
