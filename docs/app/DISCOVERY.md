# Discovery

## Scope

Discovery maps a user handle to an encrypted, certified peer bundle without
sending the plaintext handle or peer bundle to the server. It uses a verifiable
OPRF, fixed-size encrypted records, fixed-count bucket requests, Tor circuit
isolation, delayed publication, and local identity verification.
The account root inside a candidate must also match Qor's append-only private
key-transparency state before any Signal, Hybrid, or P2P key is installed.

This is not fully oblivious retrieval. The server sees publication bucket sets,
lookup bucket sets, request timing, and traffic volume. The server also operates
both the OPRF service and the billboard in the default deployment. The exact
limits are documented below and in
`docs/app/USERNAME_ENUMERATION_RESISTANCE.md`.

## Cryptographic Inputs

The client normalizes a valid handle and hashes it with BLAKE3 to a 32-byte
pseudonym. It blinds that pseudonym with RFC 9497 VOPRF over Ristretto255 and
sends only the blinded point as the encrypted `oprf/evaluate` operation inside
`POST /api/anonymous`. The outer request is a 64 KiB hybrid-PQ envelope sent on
a fresh Tor SOCKS-isolated connection.

The response includes a DLEQ proof and public key. The client verifies both and
derives:

- a stable discovery encryption key from the VOPRF output,
- a different 32-byte token for each six-hour discovery epoch.

The OPRF HTTP request requires an epoch-bound proof of work. Redis rejects reuse
of the same blinded-point proof. A process-local HTTP rate cap, concurrency cap,
and server-wide OPRF evaluation ceiling bound anonymous CPU use.

Ristretto255 VOPRF and its proof are classical cryptography. The anonymous HTTP
tunnel protects their captured wire bytes with ML-KEM-1024 + X25519 and a
responder ML-KEM contribution, but it does not remove the VOPRF's discrete-log
assumption. Discovery records can contain post-quantum identity and prekey
material without making the complete lookup construction post-quantum-secure.

Code:

- `src/lib/utils/auth-utils.ts`
- `src/lib/crypto/oprf-discovery-crypto.ts`
- `server/crypto/oprf-discovery.js`
- `server/routes/api-routes.js`
- `server/routes/pq-anonymous-http.js`

## Encrypted Record

The discovery plaintext contains only the peer's Signal prekey bundle, certified
identity chain, and optional encrypted-avatar reference. Routing identifiers and
avatar bytes are not part of the record.

The client pads this plaintext to a fixed capacity and encrypts it with the
OPRF-derived key. Every wire record is exactly 64 KiB of canonical base64 text.
The encrypted true length is inside the ciphertext. A server cannot decrypt the
bundle or distinguish valid records from random cover records by shape.

On lookup, the client decrypts candidate records locally and rejects any record
that fails exact schema validation, certified identity validation, handle
binding, key binding, or key-transparency authorization. The client derives the
handle's stable opaque transparency label from the same VOPRF-derived discovery
key, verifies the signed map and append-log proofs anonymously, and requires the
record's account-root commitment to match the current verified state.

This prevents the current server from silently returning one account root to
one established client and an attacker root to another without producing a
detectable inconsistent history. It does not prove real-world identity: the
first valid account that registers a transparency label controls that Qor
handle. A fresh install also pins the first server ML-DSA signer it sees for the
configured endpoint. See `docs/app/KEY_TRANSPARENCY.md`.

Code:

- `src/lib/crypto/oprf-discovery-crypto.ts`
- `src/lib/utils/certified-identity-utils.ts`
- `src/lib/security/identity-change-store.ts`
- `src/lib/key-transparency/client.ts`
- `src/hooks/discovery/useDiscovery.ts`

## Publication

The authenticated account opens a separate unlinked WebSocket session before
publishing. A publication has one exact wire shape:

```json
{
  "type": "publish-discovery",
  "requestId": "pub-<uuid>",
  "publication": {
    "epochId": "<manifest start time>",
    "publishId": "<64 lowercase hex characters>",
    "bucketIds": [0, 1, 2, 3, 4, 5]
  },
  "encryptedBlob": "<exactly 65536 canonical base64 characters>"
}
```

The six distinct bucket IDs contain token-derived buckets for the current and
next three six-hour epochs, then deterministic filler buckets until the fixed
count is reached. This lets one accepted publication remain discoverable for a
24-hour offline window. `publishId` is derived from the device publication key
and the 24-hour publication window, so it rotates between windows and is not
derived from the handle.

The server validates the current manifest epoch and exact shape, then queues the
publication in Redis. It acknowledges only after durable queue admission. A
relay delays and shuffles accepted writes, injects same-shape cover writes, and
stores a coarse expiry. A publication accepted just before an epoch boundary is
still committed after the boundary, the epoch check is deliberately performed
only at ingress.

The database stores only:

```text
publishId, bucketIds[6], encryptedBlob, expiresAt
```

It stores no plaintext handle, OPRF token, account ID, connection ID, exact
publication time, or discovery epoch. The row and its opaque publish ID remain
stable for the lease, so they are ephemeral metadata, not a claim of zero
metadata.

Code:

- `server/server.js`
- `server/discovery/publication-privacy.js`
- `server/database/discovery-db.js`
- `server/database/schema.js`

## Bucket Lookup

The client obtains a strict manifest through the encrypted
`discovery/manifest` operation and derives one real bucket from the current
epoch token. It adds three cryptographically random, distinct cover buckets and
sends exactly four IDs through the encrypted `discovery/bucket` operation. Both
use the same outer `/api/anonymous` route but a fresh Tor isolation credential
and connection for every call.

The server returns all four requested buckets in request order. Each bucket has
the configured target count, 64 by default. Real records are selected with a
secret-keyed deterministic rank when a bucket is overloaded, remaining entries
are fixed-size deterministic decoys. Ordering is also deterministic and
secret-keyed for the manifest epoch. Responses have strict schema and byte
limits.

Only one token-derived bucket is requested. Looking up both current and previous
epoch buckets in the same request would let the server intersect the two sets
and identify the matching publication much more easily.

The bucket index is built from bounded active database rows, single-flighted,
revision-checked, and cached. A small LRU caches fully padded buckets to avoid
recomputing megabytes of deterministic cover data on repeated requests.

Code:

- `src/lib/discovery/bucket-client.ts`
- `src-tauri/src/commands/discovery.rs`
- `server/discovery/bucket-layout.js`
- `server/discovery/bucket-index.js`
- `server/routes/api-routes.js`

## Avoiding The Lookup

A lookup is expensive , four buckets of 64 blobs each, 60-100s over Tor in
practice , so the result is saved per peer and reused when it is provably
still current.

`src/lib/discovery/saved-discovery-material.ts` stores the validated material
in the same account-scoped native secure store the P2P dial path uses for peer
certificates. Two rules make that safe:

- **A saved record is never authoritative.** It is replayed through
  `resolveTrustedPeerHybridPublicKeys` exactly as freshly fetched material is, so
  a stale or tampered record fails the same certificate, fingerprint, and
  transparency checks and falls through to the lookup that would have happened
  anyway.
- **Revocation clears it.** Dropping only the in-memory copies would let a
  revoked peer's keys return from disk on the next start , precisely the state
  revocation exists to prevent.

Verifying an inbound peer's Signal bundle used to force a full lookup
unconditionally, most often triggered by nothing more meaningful than a failed
P2P dial. A refetch is a blunt way to answer a narrow question , *is what I
already hold still current?* , and key transparency answers that directly from
data already synced. `validateSignalBundleForPeerIdentity` now reuses the
saved record only when all of the following hold:

1. the record carries the transparency state it was accepted under,
2. that root commitment and version still match the peer's live authorized state,
   and
3. its key set and all three fingerprints still match the live authorization.

Any drift, any missing piece, and it falls through to the forced lookup. The
check is therefore never weaker , only cheaper when the answer is already known.

A deliberately rejected alternative: publishing a per-record hash alongside the
blob and fetching it by PIR as a version check. It would have worked, but a
plaintext per-user hash is a stable identifier until the user rotates keys, a PIR
query costs ~1.2 MB uploaded regardless of how small the record is, and a
server-asserted hash is a freshness oracle the operator can freeze. Key
transparency already provides the same signal, is anchored to a rolling
hash-chain root the operator cannot forge, and is already being fetched , a
second source of truth about identity freshness would only give an attacker a
choice of which one to make stale.

## Server Visibility

The service does not receive a plaintext handle, unblinded OPRF token,
decryption key, decrypted record, or local match result. It does observe:

- the six buckets associated with each delayed publication row,
- the four buckets in each lookup request,
- the opaque publication ID for the row's lease,
- request and connection timing, traffic volume, and coarse expiry,
- the number of active rows up to configured capacity classes.

Before decryption, the outer route exposes only request timing and a 64 KiB
request class for discovery operations. The destination server decrypts the
operation and therefore still learns whether it is evaluating OPRF, serving a
manifest, or serving a bucket, plus the operation body described above. A bucket
response is always 18 MiB and a manifest/OPRF response is always 64 KiB, so the
response class remains observable to the network path.

The three cover lookup buckets hide which single requested bucket is real from
an observer that cannot derive the token. They do not protect against an
operator that uses the co-located OPRF secret to evaluate candidate handles.
Because a publication links four forward token buckets, a malicious operator
that guesses a handle can often match that combination to a specific row. This
protocol therefore limits passive and database-only disclosure, but it does not
provide private information retrieval or malicious-server username-enumeration
resistance.

Key transparency does not remove that enumeration boundary. The combined VOPRF
operator can derive a guessed handle's discovery key and stable transparency
label, then inspect that label's public map history. Transparency limits silent
key substitution after the signer/handle history is established, it is not a
private-membership protocol against the authority that computes the label.

Every anonymous HTTP call uses a new random Tor SOCKS authentication identity,
which prevents deliberate circuit reuse across OPRF, discovery, avatar, and
spool calls. It reduces direct request linkage but cannot eliminate timing,
volume, fixed size-class, endpoint, or global-observer correlation.

## Availability And Capacity

- Epochs are six hours and publication leases are 24 hours.
- The previous manifest index is retained for ten minutes for in-flight bucket
  requests, clients do not perform previous-epoch target lookups.
- Active source rows and source bytes are bounded before index construction.
- A bucket contains at most the configured target count. Secret-keyed ranking
  makes overload selection deterministic, but records that lose the rank are
  temporarily undiscoverable. Capacity must be sized for expected occupancy.
- The fixed anonymous route and each decrypted operation are globally rate
  limited. An abusive client can
  consume shared capacity or churn anonymous storage, proof of work and fixed
  global caps limit cost but cannot provide fair per-user quotas without adding
  identity metadata.
