# Key Transparency

qorc authorizes the account root behind discovered Signal, Hybrid, and P2P
keys against an append-only log. A discovery record is not trusted merely
because it decrypts correctly: its certified account root must match a root the
log shows was published, chained forward from the handle's earliest
registration.

The log is **unindexed and never queried by account**. Its only read is "the
records appended during epoch E", which returns identical bytes to every client.
The server therefore holds no per-account row, answers no question about a
person, and cannot read or forge a key transition. Divergent committed histories
are detected through signed-head verification and peer gossip.

This prevents undetected server key substitution against established contacts.
It does not prove that a handle belongs to a particular real-world person.

## What The Server Stores

The append-only log table stores these protocol fields for each entry:

| Field | Meaning |
| --- | --- |
| `epoch` | the one-hour epoch it was published in |
| `epochLabel` | `PRF(discoveryKey, epoch)`, unlinkable across epochs |
| `version` | monotonic per account |
| `recordHash` | SHA3-512 over the full signed transition |

The database also stores the entry's sequential log index and resulting folded
root. Labels and hashes are encoded as 128 lowercase hexadecimal characters.
The label is not a username and is not stable: it is derived client-side from
the handle VOPRF result and re-derived every epoch, so two records for one
account in different epochs cannot be linked without the discovery key.

A second one-row table holds the running fold so an append does not rescan.

## What The Server Never Sees

The signed transition, commitments, transition kind, and the ML-DSA-87
signatures authorizing it never reach the server. They travel inside the
peer's discovery publication, which the operator relays as a fixed-size opaque
blob. The log stores only the commitment needed to verify that transition, so
the operator cannot construct or alter its signed contents.

A sync request carries an epoch range and a proof of work. It contains no label,
stored client position, or gossip witness parameter, so requests do not identify
a contact or distinguish a first lookup from a routine re-check.

Code:

- `shared/key-transparency-protocol.js`
- `server/database/key-transparency-db.js`
- `server/key-transparency/service.js`

## The Log Root

The root is a rolling SHA3-512 hash chain. At each epoch boundary the server
signs a head over it with its pinned ML-DSA-87 key:

```
head = { epoch, genesisEpoch, entryCount, rootHash, signerKeyId, signature }
```

A client holds every record and recomputes the root by folding. The protocol
does not store or serve separate inclusion, consistency, or absence proofs. The
signed head is accepted only when the client independently reproduces its root.
A mismatch means the log was rewritten or forked.

Because the head carries no per-account state and is identical for every client
at a given epoch, comparing heads with a peer is a **complete** equivocation
check: if the roots agree, every record agrees.

Epoch numbers are also the protocol's clock. They are server-asserted but
publicly consistent and monotonic, so a delay counted in epochs cannot be
selectively accelerated for one victim without forking the log.

## Client Sync

A client stores its last verified epoch, entry count, and root. On sync it
fetches deltas since that epoch, folds them, and compares against the signed
head. A client with no local state syncs **from the log's genesis epoch**, which
the signed head reports, not from epoch 0, which would mean walking every hour
since 1970. There is no trusted-recent-head shortcut: the fold begins at
the fixed genesis root with entry count 0, so a server that understates its
genesis to hide early registrations fails, because the records it then serves
cannot reproduce the root it signed.

Records are held locally in 720-epoch chunks (30 days), so a sync appends to one
key rather than rewriting the log, and a scan reads a bounded number of keys.

To check a contact the client computes `PRF(discoveryKey, epoch)` for each epoch
and scans locally. The server is never told which account is being examined, and
because the client holds the complete committed set under a verified head,
finding no record proves absence from that committed log.

Code:

- `src/lib/key-transparency/client.ts`
- `src/lib/key-transparency/verifier.ts`
- `src/lib/key-transparency/record-store.ts`

## First-Registration-Wins

Uniqueness does not depend on a server-side index. A client holds every record
and knows the handle's discovery key—that is how discovery locates anyone—so it
computes the epoch label for every epoch from genesis and finds every record
ever published under that handle. The earliest `register` transition is the
legitimate owner.

Clients enforce this rule locally rather than relying on a server-side identity
index. An adversary must register a handle before its real owner does.

Retention therefore runs from genesis: pruning early epochs would destroy the
evidence this check rests on.

## Registration, Rotation, And Recovery

Registration version 1 must be signed by both the new account-root ML-DSA-87 key
and an independent random recovery ML-DSA-87 key. Both signing seeds live in the
credential-wrapped native account vault and never enter the renderer. A normal
rotation requires signatures from both the currently authorized and proposed
account roots, which prevents the operator from replacing an active root, and it
is verified by contacts, not by the server.

Lost-key recovery is intentionally slower:

1. The request is authorized by the pending new root and the existing native
   recovery key.
2. The record enters `recovery-pending` and exposes the pending commitment and
   activation epoch to existing contacts.
3. The currently authorized root can cancel before activation.
4. Activation occurs no earlier than 168 epochs (seven days) after the request's
   epoch, and is published as another transition.

Recovery activation is published by the client. Every contact derives the
activation epoch from the request's epoch, so verification does not depend on a
device wall clock.

Appends require proof of work, a blind-issued Privacy Pass `account-auth`
redemption, and server-entry authorization when that gate is enabled. Both
redemptions are unlinkable, so entitlement is proven without identifying the
account.

## Contact Monitoring And Gossip

After a contact is accepted, the encrypted account-bound monitor store retains
the label, discovery key, accepted root commitment, version, and last check. The
client periodically re-syncs and re-scans the oldest monitored contact.

The accepted identity authorization does not expire on a wall-clock deadline.
Its `verifiedAt` timestamp schedules a silent background freshness check after
18 hours, while the last verified identity remains available to messaging and
calling if that check is delayed or temporarily fails. A successful check
updates freshness without changing the authorization generation when the root,
keys, and fingerprints are identical. A verified root change, explicit
revocation, or server-scoped security incident removes the authorization.

Every real encrypted Signal plaintext may carry the latest signed head. The peer
validates that head **against the log it already holds**; no witness request is
made, so nothing on the wire reveals that this client just spoke to someone.
Conflicting heads at the same entry count, or a later epoch serving a smaller
log, create a persistent server-scoped security incident. Gossip is protected by
the conversation encryption, it piggybacks real messages and is not an
independent constant-rate cover channel.

## Fail-Closed Behavior

A discovered peer root must be transparency-authorized before its Signal,
Hybrid, or P2P keys are installed. If a monitored root changes, authorization is
revoked immediately, queued peer work is stopped, and native Signal identities,
sessions, and peer ML-KEM state are removed before the monitor checkpoint can
advance. Pending recoveries produce durable in-app warnings.

A record whose transition has not arrived stops verification at the last
provable point rather than skipping ahead: an unverifiable transition never
advances contact state.

A global inconsistency persists a server-scoped incident marker, clears verified
material, stops monitoring, and quarantines identity-dependent messaging until
user review. Corrupt local checkpoint, record, monitor, or warning state also
fails closed.

Incoming call offers require a currently transparency-authorized sender before
the calling service can admit them. The remaining call schema, blocking, rate,
and active-call checks are documented in `docs/app/CALLING.md`.

## Remaining Boundaries

**First contact is not verified identity.** The log proves a record was
published, that it chains correctly, and that everyone sees the same list. It
does not prove the handle belongs to a particular person. The remaining attack
is an adversary who registers a handle before its legitimate owner ever does, a
one-shot that must precede the account's existence and cannot be mounted
retroactively. Closing it deterministically requires out-of-band verification.

**The operator still learns aggregates.** It knows how many records exist and
when they arrive. Epoch batching blurs the second, the first is irreducible.

**Local rollback.** Encrypted local files can detect malformed or internally
inconsistent state, but one local file cannot prove that an attacker restored an
older complete snapshot. A hardware monotonic counter, secure-enclave/TPM
witness, or independent external witness is required to close that.

**Bandwidth scales with population**, not with one client's usage, because every
client downloads every record. Sync and local scanning become more expensive as
the global log grows.
