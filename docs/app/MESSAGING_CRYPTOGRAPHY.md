# Qor-Chat P2P & Messaging Cryptography

This document describes, in detail, the exact cryptography used to protect messages
in Qor-Chat: the primitives, how the P2P transport is secured, how end-to-end message
encryption works, the nested envelope layers, and how it compares to other messengers.

> Scope: message confidentiality/integrity/authentication and transport security.
> Discovery (OPRF + PIR) and authentication (OPAQUE/ZK) are covered in
> [DISCOVERY.md](DISCOVERY.md), [PRIVATE_DISCOVERY_DEEP_DIVE.md](PRIVATE_DISCOVERY_DEEP_DIVE.md)
> and [AUTHENTICATION.md](AUTHENTICATION.md).

---

## 1. Primitives

Every asymmetric primitive is **post-quantum at the maximum NIST security level**, used
in a **hybrid** construction with a classical primitive so the system is secure as long
as *either* the PQ or the classical primitive holds.

| Role | Algorithm | Standard / level | Notes |
|---|---|---|---|
| Key encapsulation (KEM) | **ML-KEM-1024** ("Kyber-1024") | FIPS 203, NIST **Level 5** | Used for every KEM: noise handshake, hybrid envelope, sealed sender, libsignal Kyber pre-keys |
| Classical key exchange | **X25519** | RFC 7748 | Hybrid partner to ML-KEM (defense in depth) |
| Digital signatures | **ML-DSA-87** ("Dilithium5") | FIPS 204, NIST **Level 5** | Identity, routing-header auth, handshake auth |
| AEAD (symmetric) | **AES-256-GCM** and **XChaCha20-Poly1305** | NIST SP 800-38D / RFC 8439 | 256-bit keys. XChaCha for large random-nonce frames |
| KDF / hashing | **BLAKE3** and **HKDF** | — | Key derivation from shared secrets |
| E2E ratchet | **libsignal** (Signal Protocol) with **ML-KEM Kyber pre-keys** | Signal **PQXDH** ("PQ3") | Upstream `signalapp/libsignal`, Double Ratchet |

Source of truth:
[post_quantum.rs](../../src-tauri/src/crypto/post_quantum.rs) (`kyber1024`, `ml_dsa_87`),
[aead.rs](../../src-tauri/src/crypto/aead.rs) (`Aes256Gcm`, `XChaCha20Poly1305`),
[hybrid.ts](../../src/lib/cryptography/hybrid.ts) (ML-KEM + X25519 + Dilithium),
[store.rs](../../src-tauri/src/signal_protocol/store.rs) (`KyberPreKeyRecord`).

---

## 2. End-to-end message encryption (the inner core)

The *content* of a message is protected by the **Signal Double Ratchet** with a
**post-quantum X3DH (PQXDH)** key agreement — the same family Signal calls **PQ3** and
Apple ships in iMessage, but here keyed at the **maximum** parameter set.

**Session establishment (first message):**
1. The sender fetches the recipient's pre-key bundle, which includes a classical signed
   pre-key **and an ML-KEM-1024 Kyber pre-key** (`KyberPreKeyRecord`).
2. PQXDH derives the initial root key from **both** the X25519 DH agreements **and** the
   ML-KEM encapsulation — quantum-safe initial secrecy.
3. The first message is a **`PreKeyWhisperMessage`** (type 3). It is large (~50 KB here)
   because it carries the KEM ciphertext and pre-key material. Subsequent messages are
   small.

**Ongoing messages:** the Double Ratchet advances a symmetric-key ratchet on every
message and a DH ratchet on replies, giving:
- **Forward secrecy** — compromising today's keys does not reveal past messages.
- **Post-compromise security ("self-healing")** — a future ratchet step locks an
  attacker back out.

The ratchet output (the `signalCiphertext`) is what the outer layers carry.

---

## 3. The envelope layers (defense in depth)

A sent message is wrapped in **three nested cryptographic layers**, then a fourth
transport layer. Each layer is independently post-quantum.

```
  plaintext
    └─►(1) libsignal Double Ratchet (PQXDH)         ── E2E content, forward secrecy
         └─►(2) Hybrid envelope                       ── E2E confidentiality + sender auth
              ML-KEM-1024 + X25519 → HKDF → AEAD
              routing header signed with ML-DSA-87
              └─►(3a) Sealed-sender "ss-v1" (server path)   ── hides who↔who from server
                     ML-KEM-1024 → BLAKE3 → AEAD
                 (3b) PQ-Noise session (P2P path)            ── transport for direct delivery
                     ML-KEM-1024 + X25519 + ML-DSA-87 handshake → AEAD frames
                   └─►(4) Tor (SOCKS5h) for server traffic   ── network-level anonymity
```

**Layer 2 — Hybrid envelope** ([hybrid.ts](../../src/lib/cryptography/hybrid.ts)):
the ratchet ciphertext is sealed to the recipient by encapsulating to **both** their
ML-KEM-1024 key **and** their X25519 key. The two shared secrets are combined via HKDF
into an AES-256-GCM key. A **routing header** (who it's for, sequence) is signed with the
sender's **ML-DSA-87** key so the recipient can pin and verify the sender. `version:
hybrid-envelope-v1`.

**Layer 3a — Sealed sender (server path)** ([blind-routing-client.ts](../../src/lib/transport/blind-routing-client.ts)):
to deliver via the server without revealing sender or recipient, the whole hybrid
envelope is encapsulated **again** to the recipient's ML-KEM-1024 key — an ephemeral KEM
ciphertext + BLAKE3-derived AES key. The server sees only an opaque blob with no `from`
and no recipient identity. `version: ss-v1`. The server writes it to a **global mix
spool** broadcast to everyone. Only the intended recipient's KEM decapsulation succeeds
([spool-snapshot-service.js](../../server/routing/spool-snapshot-service.js)).

**Layer 3b — PQ-Noise session (P2P path)** ([pq-noise-session.ts](../../src/lib/transport/pq-noise-session.ts),
[p2p-transport.ts](../../src/lib/transport/p2p-transport.ts)):
when peers are directly connected (iroh **QUIC**), the hybrid envelope is sent over a
mutually-authenticated PQ-Noise session. The handshake performs an **ML-KEM-1024
encapsulation + X25519 ECDH**, mixes both into the session keys, and authenticates each
side with an **ML-DSA-87** signature (the peer's signing key is pinned). Frames are then
AEAD-encrypted. The server is **not involved at all** on this path.

**Layer 4 — Tor:** all server-bound traffic runs over Tor (SOCKS5h). The PQ handshake —
not the TLS certificate — authenticates the server, so a self-signed cert is fine.

---

## 4. Send / receive walkthrough

**Send** ([unified-signal-transport.ts](../../src/lib/transport/unified-signal-transport.ts)):
1. Encrypt content with the libsignal ratchet → hybrid envelope (layers 1–2).
2. **Prefer P2P:** if a PQ-Noise session to the peer exists, send the hybrid envelope
   directly over it (layer 3b). The server sees nothing.
3. **Fallback to server:** otherwise wrap in sealed-sender `ss-v1` (layer 3a) and
   `BLIND_ROUTE` it to the global mix spool over Tor (layer 4).

**Receive** ([useEncryptedMessageHandler.ts](../../src/hooks/message-handling/useEncryptedMessageHandler.ts)):
1. P2P envelopes (`hybrid-envelope-v1`) skip sealed-sender. Server envelopes (`ss-v1`)
   are KEM-decapsulated first (trial-decryption of the global mix — only ours succeed).
2. Pin/verify the sender's ML-DSA-87 identity from the signed routing header.
3. Hybrid-decrypt (ML-KEM-1024 + X25519) → ratchet-decrypt (PQXDH) → plaintext.
4. Render. Send a sealed delivery receipt back the same way.

---

## 6. Summary

Content is protected by a post-quantum Double Ratchet (PQXDH) and then wrapped in a
hybrid ML-KEM-1024 + X25519 envelope authenticated with ML-DSA-87, then delivered either
**peer-to-peer over a PQ-Noise session (server sees nothing)** or **server-side via a
sealed-sender blind route through a global mix over Tor**. Every asymmetric step is
post-quantum at NIST Level 5, in a classical hybrid.