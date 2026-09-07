# Local Blocking System

## Overview

Blocking is an account-bound client safety control. The active implementation does not upload, synchronize, or query a block list through the server. The encrypted local database stores the list, and the authenticated client enforces it after a peer identity is known.

This design keeps block-list membership and the user's social graph out of the server protocol. It also means block state is local to the device/account database and is not a cross-device synchronization feature.

## 1. Stored Data

The list is stored through `SecureDB` in store `blockListData` under key `blocklist:__global__`. SecureDB encrypts and authenticates values with the current account key before they reach the native SQLite key/value store.

The accepted plaintext shape is exact:

```json
{
  "version": 4,
  "blockList": [
    { "username": "canonical.peer", "blockedAt": 1710000000000 }
  ]
}
```

Validation rejects unknown fields, prototype-pollution keys, non-canonical usernames, duplicate peers, unsafe timestamps, future timestamps beyond five minutes, and lists above 10,000 entries. Corrupt or unreadable stored data is preserved and surfaced as an error, it is not silently replaced with an empty list.

Code:

- `src/lib/blocking/blocking-system.ts`
- `src/lib/database/secureDB.ts`
- `src/lib/blocking/rate-limiter.ts`

## 2. Account And Mutation Isolation

`BlockingSystem` binds every read or mutation to one initialized `SecureDB` instance and a binding generation. An account transition clears the in-memory list, status cache, rate limiter, and mutation chain. A stale operation that resumes after rebinding is rejected.

Block and unblock operations run through one serialized mutation chain. This prevents overlapping read-modify-write operations from losing entries or allowing an unblock to pass a still-running block cleanup.

## 3. Blocking A Peer

A successful block performs the following work:

1. Canonicalize and validate the username.
2. Persist the updated encrypted list.
3. Mark the peer blocked in the authoritative runtime cache.
4. emit `USER_BLOCKED` for synchronous transport, file, and call cancellation.
5. Remove all peer-scoped unacknowledged plaintext recovery records.
6. Await registered durable retry cleanup before completing the mutation.

If list persistence fails, the requested peer is still marked blocked for the current account runtime and `USER_BLOCKED` is still emitted. The caller receives an error because that block is not known to survive restart.

If retry cleanup fails after a durable block, the block remains active and the operation reports the failure. Repeating the block retries cleanup. The user cannot successfully unblock that peer until cleanup succeeds.

## 4. Outgoing Enforcement

The unified Signal transport is the final outbound policy boundary for text, edits, reactions, deletes, files, receipts, typing state, session-reset controls, and call signals.

- A send is denied before discovery or encryption when block enforcement is unavailable.
- A blocked recipient is denied before discovery or encryption.
- Every accepted send captures the account generation and recipient policy epoch.
- Blocking a peer advances that epoch, so work already awaiting discovery, encryption, a concurrency permit, or a native write remains canceled even after a quick unblock.
- Queued sends, P2P redelivery ciphertext, delivery-ack timers, sealed-server queues, durable ack journals, retry timers, and recovery cooldowns are removed for the peer.
- Sealed-server delivery and P2P recovery re-check policy immediately before later writes.

The message sender also checks the authoritative block list before creating durable send intent. Its registered cleanup removes the peer's in-memory and encrypted retry entries, releases retry pins, and clears exact unacknowledged operation records. Login-time retry restoration discards blocked-peer entries before any session prefetch or replay.

Code:

- `src/lib/transport/unified-signal-transport.ts`
- `src/hooks/message-sending/useMessageSender.ts`
- `src/hooks/message-sending/handlers.ts`
- `src/hooks/message-sending/retry-queue.ts`

## 5. Incoming Enforcement

The relay cannot apply username-based blocks because blind-routed ciphertext does not expose the authenticated Signal sender to that layer. Incoming enforcement therefore occurs after sealed-envelope, hybrid-envelope, and Signal authentication reveal the peer locally.

The message handler checks blocking before passive discovery, content processing, file handling, call alerts, notifications, unread updates, or delivery receipts. A blocked message is consumed by deduplication but is not displayed or acknowledged to the peer.

This ordering prevents a blocked sender from using authenticated content to trigger discovery work or visible UI. It cannot prevent that sender from placing opaque traffic into a server spool, so the recipient may still incur bounded routing, decryption, and rejection work.

Code:

- `src/hooks/message-handling/useEncryptedMessageHandler.ts`
- `src/lib/blocking/blocking-system.ts`

## 6. P2P, Files, And Calls

The P2P service treats unavailable block enforcement as denied. It rejects blocked outbound connections, closes blocked inbound connections, drops blocked frames, and disconnects an existing peer when `USER_BLOCKED` fires. Unblocking does not automatically reconnect, a later explicit operation may establish a new connection.

An active file operation is canceled when its recipient is blocked. Retained retransmission contexts, recovery probes, session freshness state, timers, and MAC material for that peer are released. The unified transport remains the final check for each chunk.

The calling service denies blocked outgoing calls, answers, incoming call signals, and later call-control signals. Blocking the active call peer marks the call ended, releases local and remote media resources first, and suppresses the best-effort end signal at the unified transport boundary.

See `docs/app/CALLING.md` for the full call admission, signaling, media, and cleanup lifecycle.

Code:

- `src/lib/transport/secure-p2p-service.ts`
- `src/components/chat/ChatInput/useFileSender.ts`
- `src/lib/transport/secure-calling-service.ts`

## 7. Unblocking

Unblock remains inside the serialized mutation chain. While the peer is still blocked, the system repeats peer-wide unacknowledged-record deletion and waits for every registered retry cleanup handler. Only then does it persist the list without that peer, update the runtime cache, and emit `USER_UNBLOCKED`.

This ordering prevents old retries or session-reset records created before the block from being revived by a rapid unblock. It does not send an unblock signal to the peer or server.

## 8. Privacy And Trust Limits

- The application server receives no block list, per-contact block token, or block/unblock protocol message.
- Local encrypted storage still contains usernames and block timestamps, compromise of the unlocked client/account can expose them.
- A blocked P2P peer can infer that its direct connection was closed or refused.
- Relay traffic can still reveal coarse timing, volume, size buckets, and network-level observations described in the privacy policy even though the relay cannot read the authenticated peer identity from message content.
- Blocking does not retract ciphertext already accepted by a relay or bytes already written before the local block event occurred.
- Device-local blocking does not claim cross-device consistency.

## 9. Verification

Security tests cover fail-closed transport policy, cancellation of delayed sends, peer-scoped ACK/recovery purge, retry cleanup ownership, blocked incoming ordering, file cancellation, and P2P block gates.

Relevant suites:

- `server/test/messaging-crypto-retry.test.js`
- `server/test/file-lifecycle-security.test.js`
- `server/test/routing-privacy.test.js`
