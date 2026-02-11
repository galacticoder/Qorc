# Offline Messaging (Long-Term Storage + Local Queue)

## Overview

Offline messaging covers two distinct "message can't be delivered right now" scenarios:
1. **Recipient inbox is offline** -> the sender stores a long-term encrypted envelope on the server.
2. **Recipient keys or inbox are unavailable locally** -> the sender queues the message locally until keys become available.

The server never receives plaintext message contents and does not use usernames for routing. All offline storage is indexed by **inboxId**.

Code references:
- Server offline handlers: `server/handlers/offline-handlers.js`
- Server storage: `server/database/message-db.js`
- Client offline handler: `src/lib/websocket/offline-message-handler.ts`
- Client long-term crypto: `src/lib/cryptography/long-term-encryption.ts`
- Local queue: `src/lib/database/secure-message-queue.ts`
- Offline event wiring: `src/lib/signals/session-handlers.ts`, `src/hooks/message-sending/useMessageSender.ts`

---

## 1. Terminology

### 1.1 InboxId (Blind Routing)
The server routes offline messages by `inboxId`, not by username. `inboxId` is treated as an anonymous routing identifier.

Code references:
- Schema: `server/database/schema.js`
- Offline storage: `server/database/message-db.js`

### 1.2 Long-Term Envelope (`lt-v1`)
A long-term envelope is a Kyber KEM + PQ AEAD encrypted blob that can be decrypted later on any device holding the Kyber secret key.

Code references:
- Envelope format: `src/lib/cryptography/long-term-encryption.ts`
- Version constant: `src/lib/constants.ts` (`LONG_TERM_ENVELOPE_VERSION`)

### 1.3 Local Secure Queue
If the client cannot encrypt a message due to missing keys or inbox metadata, it stores the message locally in SecureDB and retries after keys are available.

Code references:
- Queue: `src/lib/database/secure-message-queue.ts`
- Retry on keys available: `src/hooks/useEventHandlers.ts`

---

## 2. Offline Long-Term Storage Flow (Recipient Offline)

### 2.1 Trigger: Live delivery fails
When the server cannot deliver a blind-routed sealed envelope to a destination inbox, it replies with an error:

```json
{ "type": "error", "code": "OFFLINE_LONGTERM_REQUIRED" }
```

Code references:
- Error emit: `server/handlers/message-handlers.js`

### 2.2 Client signal -> event
`handleError` dispatches `EventType.OFFLINE_LONGTERM_REQUIRED` so the sender can attempt long-term storage.

Code references:
- Event dispatch: `src/lib/signals/session-handlers.ts`

### 2.3 Sender constructs a long-term envelope
The message sender listens for `OFFLINE_LONGTERM_REQUIRED` and:
1. Pulls the encrypted payload from `globalEncryptedPayloadCache`.
2. Resolves `destinationInbox` and recipient Kyber public key.
3. Encrypts `{ messageId, encryptedPayload, timestamp }` into a `lt-v1` envelope.
4. Sends `store-offline-message` to the server.

Code references:
- Offline event listener: `src/hooks/message-sending/useMessageSender.ts`
- Long-term encryption: `src/lib/cryptography/long-term-encryption.ts`

### 2.4 Server stores the offline payload
`handleStoreOfflineMessage`:
- Requires authenticated or unlinked session.
- Optionally checks blocking if `senderIdentityKeyHash` and `recipientIdentityKeyHash` are provided.
- Stores a server payload that includes the `longTermEnvelope`.

Code references:
- Store handler: `server/handlers/offline-handlers.js`
- Blocking check: `server/handlers/offline-handlers.js` -> `checkBlockingByIdentityKeys`
- Database insert: `server/database/message-db.js`

### 2.5 Server ACK
The server replies with an ACK payload indicating success or failure.

Code references:
- ACK send: `server/handlers/offline-handlers.js`

---

## 3. Retrieval and Delivery

### 3.1 Retrieval on login
After authentication succeeds, the client calls `retrieveOfflineMessages()` which sends:

```json
{ "type": "retrieve-offline-messages" }
```

Code references:
- Trigger after auth: `src/hooks/auth/authSuccess.ts`
- Client request: `src/lib/websocket/offline-message-handler.ts`

### 3.2 Server response
The server retrieves up to 500 queued messages for the inbox and returns:

```json
{ "type": "offline-messages-response", "messages": [ ... ], "count": 3 }
```

Code references:
- Retrieve handler: `server/handlers/offline-handlers.js`
- DB delete-on-read: `server/database/message-db.js`

### 3.3 Immediate delivery after inbox claim
When a client claims an inbox, the server attempts to deliver any queued offline messages immediately. On send failure, it re-queues the payload.

Code references:
- Claim handler: `server/handlers/inbox-handlers.js`

### 3.4 Client decryption and injection into message pipeline
The offline handler:
1. Decrypts `longTermEnvelope` using the recipient's Kyber secret key.
2. Extracts `encryptedPayload` and wraps it as `SignalType.ENCRYPTED_MESSAGE`.
3. Marks the message `__isRecursive: true` and forwards it to the encrypted message handler.

Code references:
- Decrypt + inject: `src/lib/websocket/offline-message-handler.ts`
- Recursive decrypt path: `src/hooks/message-handling/useEncryptedMessageHandler.ts`

---

## 4. Local Secure Queue (Keys/Inbox Missing)

When the sender cannot encrypt (missing keys/inbox), it queues locally:
- Stored in SecureDB (no plaintext message in memory queue).
- Message content is placed in the `messageVault` and referenced by ID.
- On `EventType.USER_KEYS_AVAILABLE`, the queue is flushed for that user.

Limits and TTLs:
- Max per user: `SECURE_QUEUE_MAX_MESSAGES_PER_USER` = 50
- Expiry: `SECURE_QUEUE_MESSAGE_EXPIRY_MS` = 4 hours
- Cleanup interval: `SECURE_QUEUE_CLEANUP_INTERVAL_MS` = 5 minutes

Code references:
- Queue store: `src/lib/database/secure-message-queue.ts`
- Flush on keys: `src/hooks/useEventHandlers.ts`
- Constants: `src/lib/constants.ts`

---

## 5. Data Formats

### 5.1 `store-offline-message` request
```json
{
  "type": "store-offline-message",
  "messageId": "<uuid>",
  "destinationInbox": "<inboxId>",
  "longTermEnvelope": { "version": "lt-v1", "kemCiphertext": "...", "nonce": "...", "ciphertext": "...", "tag": "...", "timestamp": 1730000000000 },
  "version": "lt-v1",
  "senderIdentityKeyHash": "<optional>",
  "recipientIdentityKeyHash": "<optional>"
}
```

Code references:
- Client send: `src/hooks/message-sending/useMessageSender.ts`
- Server handler: `server/handlers/offline-handlers.js`

### 5.2 Stored server payload
```json
{
  "type": "offline-message-delivery",
  "messageId": "<uuid>",
  "longTermEnvelope": { "version": "lt-v1", "kemCiphertext": "...", "nonce": "...", "ciphertext": "...", "tag": "...", "timestamp": 1730000000000 },
  "version": 1,
  "timestamp": 1730000000000
}
```

Code references:
- Payload creation: `server/handlers/offline-handlers.js`

### 5.3 `offline-messages-response`
```json
{ "type": "offline-messages-response", "messages": [ ... ], "count": 3 }
```

Code references:
- Server response: `server/handlers/offline-handlers.js`
- Client handler dispatch: `src/lib/signals/user-handlers.ts`

---

## 6. Cryptography Details

### 6.1 Envelope construction
- **KEM**: Kyber (encapsulate -> shared secret)
- **KDF**: `PostQuantumHash.deriveKey(sharedSecret, "long-term-encryption-v1", "long-term-aead-key-v1", 32)`
- **AEAD**: `PostQuantumAEAD` with nonce length 36 bytes
- **AAD**: `"lt-v1:<timestamp>"`

Code references:
- Long-term encrypt/decrypt: `src/lib/cryptography/long-term-encryption.ts`
- Sizes: `src/lib/constants.ts` (`PQ_KEM_PUBLIC_KEY_SIZE`, `PQ_KEM_SECRET_KEY_SIZE`, `PQ_AEAD_NONCE_SIZE`)

### 6.2 Payload contents
The encrypted plaintext is a JSON object containing:
```json
{ "messageId": "<uuid>", "encryptedPayload": { ... }, "timestamp": 1730000000000 }
```
`encryptedPayload` is the LibSignal ciphertext that feeds the recursive `SignalType.ENCRYPTED_MESSAGE` path.

Code references:
- Payload creation: `src/hooks/message-sending/useMessageSender.ts`
- Recursive decrypt path: `src/hooks/message-handling/useEncryptedMessageHandler.ts`

---

## 7. Storage & Retention

### 7.1 Database schema
`offline_messages` table:
- `toInboxId` (TEXT)
- `payload` (TEXT)
- `queuedAt` (BIGINT)

Code references:
- Schema: `server/database/schema.js`

### 7.2 Limits
- Payload size limit: **1 MB** (`MessageDatabase.queueOfflineMessage`)
- Retrieval limit: **up to 500** per call
- Cleanup: messages older than **30 days** removed

Code references:
- Storage/limits: `server/database/message-db.js`

---

## 8. Security and Privacy Properties

- Server does not store usernames or plaintext message bodies.
- Offline storage is indexed by anonymous inbox IDs.
- Blocking is enforced at store time if identity key hashes are supplied.
- Long-term envelopes are sealed with Kyber + PQ AEAD; the server cannot decrypt.

Code references:
- Blocking check: `server/handlers/offline-handlers.js`
- Envelope crypto: `src/lib/cryptography/long-term-encryption.ts`

---

## 10. Implementation Reference

### Server
- `server/handlers/message-handlers.js` -> emits `OFFLINE_LONGTERM_REQUIRED`
- `server/handlers/offline-handlers.js` -> store/retrieve logic
- `server/database/message-db.js` -> offline queue persistence
- `server/handlers/inbox-handlers.js` -> deliver queued messages on claim

### Client
- `src/lib/signals/session-handlers.ts` -> dispatch `OFFLINE_LONGTERM_REQUIRED`
- `src/hooks/message-sending/useMessageSender.ts` -> build long-term envelope
- `src/lib/websocket/offline-message-handler.ts` -> decrypt and forward
- `src/lib/cryptography/long-term-encryption.ts` -> long-term crypto
- `src/lib/database/secure-message-queue.ts` -> local queue
