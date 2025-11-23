# Endtoend — End‑to‑End Encrypted Messaging/Calling

Endtoend is a desktop chat client and Node.js server designed for end2end quantum secure messaging. It uses the Signal Protocol for forward secrecy with an additional post‑quantum (PQ) envelope including others too long to explain here.

For exact details of the Server/Client cryptography, read [`docs/Server-Cryptography.md`](https://github.com/galacticoder/end2end-chat-site/blob/main/docs/Server-Cryptography.md) and [`docs/Client-Cryptography.md`](https://github.com/galacticoder/end2end-chat-site/blob/main/docs/Client-Cryptography.md)

## Setup

If you are using Windows, run this in PowerShell (Admin) **BEFORE THE SETUP**:

```powershell
wsl --install -d Ubuntu
winget install OpenJS.NodeJS Rustlang.Rustup -e --accept-source-agreements --accept-package-agreements
winget install Microsoft.VisualStudio.2022.BuildTools -e --accept-source-agreements --accept-package-agreements
```

*Note: If you already have these installed, you can skip them. If WSL2 was just installed, you must **restart your computer**.*

1. Clone the repository
2. Install dependencies:
   - **Server:** `node scripts/install-deps.cjs --server`
   - **Client:** `node scripts/install-deps.cjs --client`
3. Configure environment variables (**YOU DO NOT HAVE TO CONFIGURE ANYTHING TO START THE SERVER WITH ALL FEATURES! EVERYTHING IS ALREADY SETUP IN THE PROVIDED ENV FILE!** See [`docs/ENVIRONMENT_VARIABLES.md`](https://github.com/galacticoder/end2end-chat-site/blob/main/docs/ENVIRONMENT_VARIABLES.md) for configuration if interested.)
4. Generate TLS certificates: `node scripts/generate_ts_tls.cjs` (required)
5. Start the server: `node scripts/start-server.cjs`
6. Start the desktop client: `node scripts/start-client.cjs`

Requirements enforced by the application:
- Certificate pinning is required for all TLS endpoints used by the desktop client; a valid certificate chain is required (self‑signed is rejected).
- All traffic is routed through a verified Tor SOCKS proxy that the desktop bootstraps and checks before use.

## What this project is for
- Privacy‑preserving one‑to‑one messaging with forward secrecy and PQ protection
- Operating in adversarial networks (interception, replay, future decryption attempts)
- Running as a self‑hosted service with optional clustering and a Linux‑based edge tier

This is not a metadata‑free system. The service retains the minimal routing data required to deliver messages; message contents and most user artifacts are encrypted end‑to‑end.

## Security model at a glance
- Inner layer: Signal Protocol (libsignal‑client) provides double‑ratchet forward secrecy, break‑in recovery, and authenticated key exchange. Native Kyber pre‑keys are used where supported.
- Outer layer: a PQ envelope wraps Signal ciphertext using ML‑KEM‑1024 (Kyber) for key encapsulation, AES‑256‑GCM and XChaCha20‑Poly1305 for confidentiality, and BLAKE3 for authentication.
- Device‑bound auth: refresh flows require a signed device proof (Ed25519) tied to a stable device identifier; stolen tokens alone are not sufficient.
- Local secrecy: the desktop stores history in an encrypted local database using a PQ AEAD construction; raw plaintext is not kept on disk.
- Tor: the desktop downloads and runs a bundled Tor client, configures transports (obfs4/snowflake), and verifies connectivity before use. Tor routing is required.

## Cryptography details
- Public‑key primitives
  - ML‑KEM‑1024 (Kyber) via @noble/post‑quantum for PQ KEM
  - ML‑DSA‑87 (Dilithium) via @noble/post‑quantum for signatures
  - X25519 for classical ECDH where needed
- Symmetric primitives
  - AES‑256‑GCM
  - XChaCha20‑Poly1305
  - BLAKE3 for keyed MACs and KDF contexts
- Signal layer
  - libsignal‑client for Double Ratchet and PreKeys
  - Uses native Kyber pre‑keys where available; sessions are created/rotated through standard Signal flows
- PQ envelope
  - Encapsulation: ML‑KEM‑1024 → shared secret
  - Derivation: BLAKE3/HKDF contexts
  - Encryption: AES‑GCM(inner) + XChaCha20‑Poly1305(outer) with BLAKE3 MAC

## Authentication, sessions, and tokens
- Device keys: on first run, the desktop generates an Ed25519 keypair and a stable device identifier stored in encrypted local storage.
- Refresh protocol: server issues a short challenge; client returns a signed proof binding the challenge, token ID (jti), and device ID. Server validates the signature before issuing new tokens.
- Token storage: the server persists refresh tokens and token families, supports generation counters and revocation, and maintains a blacklist. Audit entries record token events and connection risk signals.
- Session reset: when Signal session state becomes invalid, the client can request a fresh bundle and re‑establish secure channels without user intervention.

## Message storage and data handling
- On the client
  - All conversation history, username mappings, block lists, queued messages, and file metadata are stored in an encrypted SQLite database using a PQ AEAD (AES‑GCM + XChaCha20 with BLAKE3 MAC). Ephemeral stores support TTL and automatic cleanup.
- On the server
  - Messages are stored only as encrypted payloads. The server never needs plaintext to route or persist messages.
  - Offline messages are queued encrypted and delivered on reconnection.
  - User records hold password/parameter metadata and Signal key material necessary to distribute pre‑keys and bundles; sensitive values are stored as encoded hashes or ciphertext.

## Transport and delivery
- Primary channel: WebSockets over TLS with certificate pinning enforced by the desktop.
- P2P path: a minimal WebRTC signaling path allows peer‑to‑peer messaging when available; the app automatically falls back to the server path when P2P is unavailable.
- Tor: the desktop bootstraps its own Tor instance, verifies a working SOCKS proxy, and routes traffic through it. Bridge transports (obfs4 or snowflake) are supported. Bundle signature verification is performed when possible (see [`docs/ENVIRONMENT_VARIABLES.md`](https://github.com/galacticoder/end2end-chat-site/blob/main/docs/ENVIRONMENT_VARIABLES.md) for verification controls).

## Server architecture
- WebSocket gateway: authenticates clients, distributes server public keys, relays encrypted messages, and handles chunking for large key exchanges.
- Presence and session state: Redis is used to track connection state, username session ownership, and to clean up stale session mappings with TTLs.
- Rate limiting and abuse controls: distributed limiters enforce per‑user and per‑connection policies for authentication, messaging, and connection attempts. Stats can be collected to spot abuse.
- Database layer: SQLite and PostgreSQL supported. Tables include users, messages, offline queues, token families/blacklist, device sessions, and audit logs.
- Clustering: optional Redis‑coordinated cluster with server approval flow, health monitoring, queue‑based leader election, and periodic key rotation for inter‑server authentication.
- Edge tier (optional, Linux): an auto‑configurable HAProxy layer can be generated and hot‑reloaded when cluster membership changes. An optional tunnel helper can expose a public URL for development. These automation scripts target Linux.

## Desktop hardening
- Electron main process guards:
  - Strict IPC validation and per‑channel size/rate limits
  - CSP and security headers injected at runtime
  - Window navigation and external link handling locked down
- Certificate pinning enforced for WebSocket TLS endpoints
- Secure storage handler: structured input validation, bounded sizes, and path sanitation for file operations.

## Privacy characteristics and limitations
- The server sees: pseudonymous user identifiers, timing data, and minimal routing metadata required to deliver messages. Contents remain encrypted end‑to‑end.
- The desktop keeps local plaintext only in memory during use. Disk persistence is encrypted.
- Optional Tor reduces network observability but does not eliminate all metadata or timing correlations.
- Export controls, platform crypto backends, and OS trust stores can impact guarantees; pinning and Tor help but do not replace operational security.

## Threat model and coverage
- Passive network monitoring: contents confidential (Signal + PQ envelope); routing metadata still observable.
- Message harvesting for future decryption: mitigated by PQ envelope (ML‑KEM‑1024 + AES‑GCM/XChaCha20 + BLAKE3) and Signal forward secrecy.
- Stolen refresh token: requires device‑bound proof (Ed25519); token alone is insufficient.
- Server compromise: server stores only encrypted payloads; no plaintext message recovery. Keys are not present server‑side.
- Local disk theft (desktop): SQLite contents are encrypted with PQ AEAD; plaintext exists only in memory during use.
- Network path manipulation: TLS with certificate pinning; Tor path required.

## Platform support
- Desktop: Electron app runs natively on Linux, macOS, and Windows. The Tor bootstrapper and PQ stack are bundled in the desktop app.
- Server: Node.js on Linux, macOS, and Windows (via WSL2). Full cross-platform support with automatic WSL2 forwarding on Windows. The HAProxy/systemd/tunnel automation targets Linux/macOS.

## Future Goals

All goals/to-dos are in the [issues tab](https://github.com/galacticoder/end2end-chat-site/issues). I am a solo developer working on making the safest app for users looking for an app where privacy and security truly matters for every small detail leaving their device. I plan on adding more user features and making huge ui improvements on my next update.

## Contributing and reporting of issues

Please reference the [`CONTRIBUTING.md`](https://github.com/galacticoder/end2end-chat-site/blob/main/docs/CONTRIBUTING.md) file for contributing to the project. Please reference the [`ISSUE_TEMPLATE.md`](https://github.com/galacticoder/end2end-chat-site/blob/main/docs/ISSUE_TEMPLATE.md) file for reporting issues.

## License
[![License: qorc Non-Commercial Copyleft v1.0](https://img.shields.io/badge/License-qorc%20Non--Commercial%20Copyleft%20v1.0-6d4aff.svg)](LICENSE)
