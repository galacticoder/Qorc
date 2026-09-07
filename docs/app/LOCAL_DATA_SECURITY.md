# Local Data Security

Qorc keeps the persistent account master, account identity keys, Signal
state, database keys, and credential-cache encryption keys in the native Rust
process. The web renderer receives public keys and narrowly scoped operation
results. It does not receive the persistent private keys or a general-purpose
master key.

This boundary is intended to make copied application files useless without the
account credentials and to reduce the value of a renderer compromise. It does
not make a fully compromised operating system safe. Malware that can inject
into the native process, read process memory as the same user, record keyboard
input, replace the application binary, or control the display can still defeat
the local boundary.

## Security Goals

The native local-security design has the following goals:

- copied database, secure-store, configuration, and account-vault files do not
  contain an unwrapped account master or persistent account private key,
- persistent account keys never cross Tauri IPC into JavaScript,
- Signal state is initialized, mutated, encrypted, and persisted by Rust,
- SQLCipher keys and authenticated row-encryption keys remain native,
- the renderer receives no complete decrypted message history,
- anonymous authentication credentials are encrypted at rest with a key derived
  from the native account master, not with a renderer-held key,
- a renderer restart can reuse an account session while the native process is
  still alive,
- a full native-process restart requires the account password and local
  encryption passphrase before persistent local secrets are usable again.

The design deliberately does not use an OS keychain, desktop secret service,
TPM-only unlock policy, or authorization from a second device. Under those
constraints, a full process restart cannot be both unattended and protected
from someone who copied all local files. Automatically recovering the account
master from those files would place the effective unlock secret beside the data
it protects.

## Native Account Vault

Persistent account vaults use the `native-account-vault-v1` format.

When an account vault is first created, Rust generates independent random
material for:

- a 32-byte account master,
- the ML-KEM-1024 key seed,
- the device ML-DSA-87 signing seed,
- the static X25519 secret,
- the account-root ML-DSA-87 signing seed,
- the key-transparency recovery ML-DSA-87 signing seed.

Only compact seeds and the account master are placed in the wrapped payload.
Expanded ML-KEM and ML-DSA private keys are derived temporarily inside Rust when
an operation requires them and are dropped afterward.

### Credential Wrapping

The wrapping key is derived from a length-prefixed transcript containing the
canonical username, account password, and local encryption passphrase. Length
prefixing prevents ambiguous concatenations such as two different credential
tuples producing the same byte string.

The current Argon2id parameters are:

- version: Argon2 v1.3,
- memory: 512 MiB,
- iterations: 6,
- lanes: 4,
- output: 32 bytes,
- salt: 32 random bytes per account vault.

The payload is authenticated and encrypted with XChaCha20-Poly1305 using a
24-byte random nonce. The authenticated data binds the format domain, canonical
account owner, username, and published public-key bundle. Replacing public keys,
moving ciphertext between account scopes, changing the username, or modifying
the encrypted payload causes unlock to fail.

The persisted record contains the version, account scope, username, salt,
nonce, ciphertext, and public keys. It does not contain the password,
passphrase, wrapping key, account master, or private-key seeds in plaintext.

### Unlock Lifetime

Successful unlock creates an in-memory `AccountSession` owned by Rust. The type
is intentionally not serializable and not cloneable. Locking the account drops
the database manager, clears Signal state, and removes the native account
session.

A renderer reload does not necessarily terminate the Tauri process. If the
native session is still alive, the renderer can ask whether the expected
account scope is unlocked and can recover only the public-key view. A complete
application/native-process restart destroys the session and shows the standard
**Sign in** form in local-unlock mode. That form requires both the account
password and the local encryption passphrase.

After unlock, Qorc attempts a one-time anonymous resume credential. If the
resume pool is empty, it continues through normal private account
authentication. The expensive local account unlock is not repeated during that
authentication step.

## Renderer IPC Boundary

The renderer may request the following persistent-account operations:

- open or lock the exact account scope,
- read the public ML-KEM, device ML-DSA, X25519, account-root, and recovery keys,
- sign an already domain-separated transcript for an allowlisted purpose,
- derive a deterministic discovery publication value for the current server
  scope and publication window,
- decrypt one bounded authenticated Hybrid envelope,
- open one bounded sealed-sender envelope,
- complete the persistent half of one P2P Noise handshake,
- load, store, or remove one account-bound anonymous-token pool.

There is no command that exports the account master, private-key seeds, expanded
private keys, database keys, Signal state keys, token-vault keys, or token-vault
storage identifiers.

Signing is restricted to named purposes. The current allowlist separates device
envelopes, device certificates, P2P transcripts, account-root certificates,
key-transparency updates, and key-transparency recovery updates. A renderer
caller cannot choose an arbitrary native signing algorithm or request a private
key serialization.

P2P Noise is the one deliberate shared-secret exception. The renderer owns the
short-lived Noise session and therefore receives the 32-byte ML-KEM and X25519
shared secrets for one handshake. It never receives the static ML-KEM or X25519
private keys that produced them. Noise cleanup zeroes the returned
handshake secrets after session-key derivation.

## Native Database

Opening an account activates `DatabaseManager` with keys derived directly from
the native account master. Database initialization and key installation remain
inside Rust.

The database has independent native layers:

- SQLCipher page encryption with a key derived under `QDBv3/DISK`,
- XChaCha20-Poly1305 authenticated row encryption with a key derived under
  `QDBv3/SYM`,
- an independent SHAKE256 row-masking key derived under `QDBv3/QUANT`,
- row associated data bound to the account namespace, store, and key under
  `QDBv3/ROW`,
- a secret-keyed database filename that does not expose the account handle.

The native database validates file type, ownership, permissions, size quotas,
store namespace, row shapes, and transaction limits. Dropping the native account
session drops the live database manager and its keys.

Application metadata still crosses IPC. Private message records contain a blank
`content` field plus an opaque `secureContentId`. Reply metadata carries only
the target ID, optional sender, a blank content field, and—when the referenced
message is locally available—its opaque content identifier. Quoted message
bodies are neither persisted in renderer retry/history rows nor copied onto the
wire. The corresponding text is stored in a versioned native-only database
store. Generic renderer get, set, mutate, enumerate, scan, and delete commands
reject that store even when its name is guessed.

### Message History Window

Conversation metadata uses 50-message encrypted segments. A renderer request
may load at most one 50-message page. Scrolling upward loads successive pages
while preserving the current viewport. Opening a conversation loads only its
newest 50-message page. Pages explicitly loaded while scrolling upward remain
available during that browsing session without replacing the newest page. Once
the view returns to the bottom and remains there for three minutes, those extra
older pages are released and the newest 50 messages remain. Inactive
conversations retain at most 50 records each and 2,048 in total. Private text is
not part of those segments, and the renderer has no raw text history retrieval
API.

On receive, Rust first commits the authenticated Signal ratchet and complete
plaintext to the native pending-decrypt record. For `message` and
`edit-message`, the result returned through IPC has `content: ""` and an opaque
pending reference. After the renderer validates ownership and operation
metadata, a native command binds the pending record to the durable local message
identifier. The command reads the staged plaintext internally, it never returns
the text.

Viewing calls a native render command with an opaque content identifier,
bounded width, font size, and RGB color. Rust decrypts one record, shapes the
text with system font fallback, rasterizes it into a transparent RGBA image, and
PNG-encodes it. IPC returns only the PNG Base64 and dimensions. The webview uses
an empty-alt, accessibility-hidden image and drops its source when it leaves the
viewport. There is no DOM text node, JavaScript message string, canvas text
call, or renderer decryption key.

This boundary does not make visible pixels secret. The Rust
process necessarily holds one plaintext while shaping and Signal work run, and
the webview necessarily holds pixels while a message is visible. Renderer code,
screen capture, OCR, display-control malware, or an attacker able to read the
Rust process can still recover what the user can see. A renderer compromise has
no raw-text API or bulk plaintext history to dump.

Newly composed text still exists in the web input because the user is typing it.
Existing text is never loaded to prefill that input: editing is replacement
based and asks the user to type the complete new value. Copying is performed by
Rust only after a trusted native confirmation explains that the system
clipboard exposes plaintext to other applications. Attachments likewise exist
as decrypted bytes while displayed or played.

Private send-retry snapshots contain operation metadata only. The native
content record binds an outgoing body to the exact account, recipient,
application type, and wire operation ID. Rust refuses mismatched encryption.
The binding is revoked after a successful text send, edit-operation staging is
deleted after success or cancellation.

## Signal State And Message Decryption

Native account activation derives the persistent ML-KEM key pair and initializes
the Signal store without renderer key injection. Signal identity keys, signed
prekeys, one-time prekeys, sessions, sender keys, SPQR state, and the static
ML-KEM material are serialized through the native encrypted database.

Private Signal encryption accepts an opaque content reference and authenticated
metadata template. Rust verifies the record's recipient, type, account, and
operation binding before inserting the content and advancing the send ratchet.
Private Signal decryption returns redacted metadata plus an opaque staged
reference. Other bounded protocol controls may still cross IPC as their current
single payload. No Signal command returns identity keys, ratchet keys,
serialized stores, static ML-KEM secrets, or stored private message text.
Lifecycle locks prevent an operation from committing state across an account
transition.

The outer Hybrid and sealed-sender receive paths are also native. Rust performs
canonical Base64 and exact-shape parsing, ML-DSA verification, ML-KEM
decapsulation, X25519 agreement, key derivation, MAC verification, authenticated
decryption, fixed-frame parsing, sender-handle validation, and size checks before
returning one plaintext result.

## Anonymous Credential Storage

The OPAQUE export key is temporary protocol output. It is not persisted and is
zeroed by the authentication flow.

Rust derives separate token-vault keys and opaque storage identifiers for:

- `working`: the fixed 250-token account-auth pool,
- `resume`: the fixed 32-token one-time restart pool.

The derivation binds the account master, server scope, and pool kind. Each pool
is independently encrypted with XChaCha20-Poly1305 and then stored through the
native machine-bound secure store. Moving a pool between accounts, servers, or
pool kinds fails authentication.

The renderer receives token plaintext only because it must blind, unblind, and
redeem the current anonymous credential. It does not receive the persistent
token-vault encryption key. Pool mutations remain generation-serialized, and a
lock invalidates in-flight loads or writes before they can repopulate secrets.

The working token vault cannot be opened before the native account is active.
Registration therefore waits for the server's staged-registration receipt and
its “not already committed” decision, then creates or unlocks the native account
before preparing the confirmation token batch. Cold login first validates the
OPAQUE record, then unlocks the native account before loading or replacing the
same batch. A failed current authentication attempt locks any native session it
opened instead of leaving local keys available behind a rejected login screen.

## Logout And Deletion

Ordinary logout locks the native account, clears in-memory keys and session
state, clears renderer message state, deletes the working account-auth and
resume-token pools, and preserves the wrapped account vault and encrypted
database for the next login. A process restart does not delete those pools, but
they remain unreadable until the native account vault is unlocked again.

There is no server-visible account deletion mechanism. The server knows only
its opaque authentication records and anonymous protocol state.

## Threat Boundaries

### Copied Files While Locked

An attacker who copies the application database, account-vault record,
secure-store directory, configuration, and other disk files still lacks the
credential-derived account-vault wrapping key. The random account master and
persistent private-key seeds are inside authenticated ciphertext. Database and
token-vault keys derive from that account master.

Security then depends on the entropy of both user-entered secrets, the Argon2id
cost, the correctness of the native cryptography, and the attacker not already
having captured the credentials or unlocked process memory.

### Renderer Compromise While Unlocked

A renderer compromise can act as the logged-in UI. It may request allowed
signatures, request pixel rendering for known message identifiers, capture
visible pixels, observe new drafts, send newly supplied text, or use current
anonymous credentials. It cannot request stored private text or encrypt an
inbound/history record to an attacker-selected recipient. Copying requires a
separate trusted native confirmation. The boundary still cannot make an
actively controlled display harmless.

Purpose allowlists, input bounds, account-generation checks, the 50-message
window, and the absence of generic private-key export reduce persistence and
bulk exfiltration opportunities.

### Native Process Or Operating-System Compromise

Code execution inside the Rust process, debugging access to its memory, root or
kernel compromise, binary replacement, keylogging, screen capture outside the
application policy, and malicious accessibility/input infrastructure are outside
this boundary. No software-only vault can keep using a secret while
simultaneously hiding it from an attacker with equivalent control over the
process and operating system.

## Implementation Map

- Native vault and account session: `src-tauri/src/account_vault.rs`
- Purpose-bound account commands: `src-tauri/src/commands/account.rs`
- Native database: `src-tauri/src/database.rs`
- Native Hybrid and sealed-sender receive: `src-tauri/src/hybrid_native.rs`
- Native Signal lifecycle: `src-tauri/src/commands/signal.rs` and
  `src-tauri/src/signal_protocol/`
- Native private-message records and rasterization:
  `src-tauri/src/message_content.rs` and
  `src-tauri/src/commands/message_content.rs`
- Public-only renderer identity: `src/lib/types/auth-types.ts`
- Native account bindings: `src/lib/tauri-bindings.ts`
- P2P native-operation adapters: `src/hooks/p2p/useP2PKeys.ts`
- Native token pools: `src/lib/database/token-vault.ts` and
  `src/lib/signals/resume-tokens.ts`
- Pixel-only message display: `src/components/chat/messaging/SecureCanvasText.tsx`
- Metadata-only message projection and retry state:
  `src/hooks/database/message-persistence.ts`,
  `src/lib/utils/message-state-limits.ts`, and
  `src/hooks/message-sending/retry-queue.ts`

## Verification Invariants

The source and tests enforce the following invariants:

- renderer account types contain public keys only,
- generic renderer storage cannot access native account-vault or private-message
  namespaces,
- database and Signal key initialization remain native,
- P2P service objects contain no persistent private key copies,
- sealed-sender and Hybrid receive call native account commands,
- private Signal decrypt results are redacted before IPC,
- generic renderer database commands reject the native message-content store,
- private-message display returns PNG pixels rather than text,
- retry encryption is recipient-, type-, account-, and operation-bound,
- token-vault lock races cannot repopulate token secrets,
- account-vault credential tuples use unambiguous length-prefix encoding,
- canonical account owners and usernames are required,
- TypeScript and Rust compile without launching the application.

These checks establish implementation properties, not a formal proof. The
Argon2, ML-KEM, ML-DSA, X25519, Signal, SQLCipher, AEAD, and composition choices
still require independent security review. In particular, the RustCrypto
`ml-dsa` crate used for native account signatures documents that it has not had
an independent third-party audit, Qorc must not describe this boundary as an
audited hardware-grade vault.
