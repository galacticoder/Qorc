# Discovery OPRF — Username-Enumeration Resistance

## Overview

Discovery lets users find each other by username. The privacy of *who looks up whom* is covered in
`DISCOVERY.md` and `PRIVATE_DISCOVERY_DEEP_DIVE.md`. This document covers a narrower property: limiting
what a server operator can learn about *which usernames are registered*.

The discovery OPRF key lives on the server, so the operator can compute `token(username)` for any
candidate username. To keep a database dump or server compromise from yielding the exact set of
registered usernames, three controls apply:

1. K-anonymous discovery storage (the store holds no exact per-user marker).
2. A global OPRF evaluation rate cap.
3. The OPRF key encrypted at rest.

The resulting guarantee is stated in §4: a server-side view narrows a username to a bucket of K users,
never to one, and online probing is rate-limited.

---

## 1. Threat model

- **Adversary:** the server operator, and anyone who obtains a database dump, compromises the server, or
  compels disclosure.
- **What the operator can do:** the discovery OPRF secret key is a single Ristretto255 scalar held on
  the server (`server/crypto/oprf-discovery.js`), so the operator can evaluate the OPRF on any candidate
  username and compute its discovery token offline.
- **What stays protected regardless of this document:** message content and metadata unlinkability
  (blind routing plus rotating inboxes) and the privacy of who looks up whom (PIR plus k-anonymous
  bucket retrieval). The property addressed here is username *existence*.

---

## 2. K-anonymous discovery storage

The discovery billboard stores no exact per-user marker.

- The client derives its own `bucketId` from its OPRF-token slot key, the manifest epoch, and a fixed
  `bucketCount`, and publishes only `{ epochId, bucketId, publishId }`. The raw token is never sent.
- The server stores `(epochId, bucketId, publishId, encryptedBlob, expiresAt, publishedAt)` with primary
  key `(epochId, publishId)`. There is no exact `token` or `pirSlotKey` column.
- `publishId = sha256(dilithiumPub || epochId || bucketId)` is random-looking, is not derived from the
  username, and rotates each epoch (so a username's bucket trajectory cannot be fingerprinted across
  epochs). It is the per-`(epoch, bucket)` upsert key.
- Cover publications (client-side and the server relay) emit indistinguishable random bucket entries.
- Lookup fetches a whole bucket and the client decrypt-filters locally (`DISCOVERY.md` §6.5), so no
  exact per-user slot-key column is needed for retrieval.

A database dump therefore reveals only "bucket *b* holds *N* blobs," never "username *X* is registered."

Code references:
- Schema: `server/database/schema.js`
- Storage: `server/database/discovery-db.js` (`storeBucketEntry`)
- Bucket layout / fixed bucket count: `server/pir/page-layout.js` (`DISCOVERY_FIXED_BUCKET_COUNT`)
- Source records: `server/pir/opaque-discovery-source-records.js`
- Publication relay + cover: `server/discovery/publication-privacy.js`
- Publish handler: `server/server.js`
- Client publish: `src/hooks/discovery/useDiscovery.ts` (`buildDiscoveryBucketBatch`), `src/lib/pir/pir-client.ts`

---

## 3. Global OPRF rate cap

The OPRF server enforces a global evaluations-per-minute cap (`OPRF_GLOBAL_MAX_PER_MIN`, default 1200)
in addition to the per-session limit. The per-session limit does not bind an attacker who holds many
anonymous tokens. The global cap bounds an external attacker's dictionary attack against the live OPRF
regardless of how many tokens they hold.

Code reference: `server/crypto/oprf-discovery.js`.

---

## 4. OPRF key at rest

The OPRF secret key is encrypted at rest:
- AES-256-GCM, with the key-encryption key derived from `KEY_ENCRYPTION_SECRET` or `DB_FIELD_KEY`.
- AAD label `oprf-discovery-v1`.
- Key file written with mode `0600`. The in-memory key is zeroized on shutdown.

Code reference: `server/crypto/oprf-discovery.js`.

---

## 5. Guarantee and limits

- **Against the operator (holds the OPRF key):** computing `token(username)` offline and matching it
  against a database dump reveals only the username's *bucket* — one of K users — never the exact user.
  K scales with the user base. With very few registered users K is effectively small, because a user
  cannot be hidden among fewer than K others.
- **Against an external attacker (no key):** a database dump yields no exact enumeration, and online
  probing through the live OPRF is bounded by the global rate cap.
- **Inherent limit:** usernames are human-chosen and low-entropy. A find-by-name service cannot make
  existence impossible to probe. These controls limit and rate-bound enumeration rather than eliminating
  it.

---

## 6. Username uniqueness

The server does not enforce strict username uniqueness. Detecting a duplicate username would require an
exact per-username marker on the server, which is precisely the enumerable marker that §2 removes.
Server-enforced uniqueness and k-anonymous-at-rest storage are mutually exclusive.

As a result, the account key is `credentialId = HKDF(OPRF(username, password))`: two registrations with
the same username but different passwords produce different `credentialId` values and are distinct
accounts. The username is a discovery handle, not a unique server-side identifier.
