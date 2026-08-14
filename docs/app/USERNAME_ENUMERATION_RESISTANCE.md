# Username Enumeration Resistance

## Threat Model

Discovery uses a VOPRF so an ordinary network observer does not see the queried
handle or unblinded token. The default server deployment, however, holds both
the VOPRF secret and the discovery database. A malicious operator can evaluate
candidate handles offline and derive their epoch bucket IDs.

The protocol must therefore not claim that the server cannot enumerate users.
It provides narrower protections:

- a database dump without the OPRF authority contains no plaintext handle or
  exact token column,
- an external client must spend proof of work and is subject to global online
  evaluation limits,
- records are fixed-size ciphertexts and cannot be confirmed by decryption at
  the server,
- ordinary lookups reveal four candidate buckets rather than a plaintext target.

## Stored Data

Each active billboard row contains an opaque daily publication ID, six bucket
IDs, one fixed-size encrypted record, and a coarse expiry. It has no account ID,
username, OPRF token, IP address, connection ID, exact publication timestamp, or
decrypted identity material.

The publication ID is derived from the device publication key and publication
window, not the handle. It rotates between windows. This prevents a database
reader from using the ID itself as a permanent account identifier, although the
ID remains stable during its lease.

Key transparency stores a separate stable 512-bit opaque label for each claimed
handle, together with versioned root/recovery commitments, public transition
kind, coarse recovery state, encrypted fixed-size event history, and Merkle
nodes. The label is not a readable username, but it is deliberately persistent
and linkable within that server's transparency history. Because the same server
controls the VOPRF authority, its operator can derive labels for guessed
handles. This state is described separately because it has a different privacy
and retention boundary from the rotating discovery billboard.

## What Candidate Testing Reveals

For an observer without the OPRF secret, one real publication bucket is hidden
among filler buckets and one real lookup bucket is hidden among three random
cover buckets. A database-only attacker cannot derive which bucket belongs to a
guessed handle.

The server operator can derive all token buckets for a guessed handle. A real
publication links the current and next three epoch buckets in one row to provide
24-hour offline discovery. Matching several derived buckets against that row can
make a candidate handle highly distinguishable from cover and unrelated rows,
especially in a small deployment. This can amount to practical username
enumeration.

Even if only one derived bucket were available, bucket occupancy and repeated
observations would make the anonymity set depend on deployment size, cover-row
quality, and traffic patterns. K-anonymity is not a cryptographic proof that a
candidate exists or does not exist.

## Online Abuse Controls

The anonymous OPRF endpoint requires an epoch-bound proof of work, records each
blinded-point proof nullifier in Redis, limits concurrent requests, limits
per-process request rate, and enforces a server-wide rolling evaluation ceiling.
These controls bound external CPU abuse and online dictionary speed. They do not
restrict an operator that already possesses the OPRF secret.

## Key Protection

The OPRF key is deterministically derived from the server authentication root
and held in memory only while the process runs. The root is protected by the
server's configured key-encryption material at rest. At-rest encryption helps
against storage-only theft, but a live server compromise or operator has access
to the effective authority and discovery database.

## Username Semantics

The server does not maintain a plaintext username index. Authentication records
are addressed by password-dependent opaque values, while discovery treats the
normalized username as a human-facing handle. Key transparency does enforce
cryptographic uniqueness of the handle-derived opaque label: the first valid
registration claims that label, and later account-root changes require an
authorized rotation or delayed recovery transition.

This prevents the operator from silently returning unrelated roots for one
claimed handle to different established clients. It does not prove that the
first claimant is the real-world person a user intended to find, and it does not
hide a guessed handle from the combined VOPRF/transparency operator. A fresh
install also trusts the first ML-DSA server signer observed for its configured
endpoint. See `docs/app/KEY_TRANSPARENCY.md` for the exact consistency and
bootstrap guarantees.


Code:

- `server/crypto/oprf-discovery.js`
- `server/discovery/bucket-layout.js`
- `server/database/discovery-db.js`
- `server/database/key-transparency-db.js`
- `src/hooks/discovery/useDiscovery.ts`
- `src/lib/discovery/bucket-client.ts`
- `src/lib/key-transparency/client.ts`
