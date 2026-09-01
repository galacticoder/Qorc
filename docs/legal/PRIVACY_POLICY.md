# Qorc Privacy Policy

Effective Date: June 21, 2026  
Last Updated: August 6, 2026

This policy describes the default Qorc app and server operated by galacticoder.

Qorc is built to be blind by design. The server is not a place where readable user profiles, readable usernames, messages, files, calls, contacts, passwords, passphrases, or keys are kept. In normal use, readable information stays on your device or with the people you choose to communicate with.

## Core Promise

Qorc does not require a real world identity for the core app. The default
server does not use a stable readable user ID, per user messaging mailbox,
recipient route, or readable contact graph. It does retain one stable,
fixed-size opaque authentication record and slot for each registered account.
It also retains one stable opaque key-transparency label and append only
cryptographic identity history for each claimed handle. These values are not
readable identities, but their persistence and linkability are disclosed because
opaque data is not the same thing as absolutely no data.

The default server does not receive or store:

- email addresses or phone numbers for core messaging
- stable readable user IDs, readable account records, peruser mailboxes, or
  reusable messaging route identifiers
- readable usernames, display names, or profile text
- readable messages, files, voice messages, calls, video, or screen share
- contact lists or a readable contact graph
- plaintext passwords or local database passphrases
- decryption keys.

The server does not have the keys needed to read message, file, call, profile, or
avatar content. A normal blind-route send and offline snapshot request contain no
recipient selector. The service can still observe and correlate timing, volume,
connection lifetime, encrypted size classes, authentication work, discovery
bucket sets, and other protocol metadata. The combined discovery operator can
also test guessed handles using its OPRF authority. Direct P2P peers learn each
other's network addresses.

Anonymous discovery, avatar, OPRF, key-transparency, and spool calls share one
externally visible `/api/anonymous` path, use a fresh Tor-isolated connection per
call, and encrypt the operation name and body with hybrid post-quantum key
establishment. The destination server decrypts the operation to perform it and
therefore knows its operation type and body. The network path can observe timing
plus the fixed 64 KiB/512 KiB request and 64 KiB/512 KiB/4 MiB/18 MiB response
classes.

## What The Server Handles

The server only handles protocol material needed to make the system work:

- one persistent fixed-size opaque authentication record, slot, and keyed
  credential lookup per registered account
- encrypted blobs for fallback/offline delivery and delayed-mix recovery
- encrypted discovery bundles, opaque publication IDs, bucket sets, and
  encrypted profile/avatar references
- stable opaque key-transparency labels, versioned root and recovery
  commitments, public transition kinds and coarse recovery state, fixed-size
  encrypted event history, Merkle map/log nodes, and signed tree heads
- one-time or per-session anonymous authentication material
- blinded OPRF inputs, encrypted OPAQUE login material, Privacy Pass nullifier
  hashes, proof-of-work values, and similar anti-abuse material
- timing, encrypted size classes, rate-limit counters, and live connection state
- coarse server-health and abuse-prevention logs that do not contain readable identities, recipients, contact graphs, or message content.

This material does not give the service readable messages, profiles, contacts, or
decryption keys. Some values are one-time, rotated, or short-lived, the opaque
authentication record is stable, a discovery publication ID is stable for its
lease, and a transparency label and its append-only history are stable for the
claimed handle. The combined VOPRF operator can derive the stable transparency
label for a guessed handle. Operational timing may correlate otherwise separate
requests. A malicious or compelled operator can instrument the service
differently from the default logging policy.

## Local And Peer Data

Readable app data is local to your device. That includes your message history, files, local profile information, settings, keys, block lists, and app state.

People you communicate with can read, save, copy, or share what you send them. Qorc cannot prevent a recipient from doing that.

## Discovery

Discovery requests do not send the readable username, unblinded token,
decryption key, local match result, or a stable account identifier for the
searcher. The operation and bucket body travel inside the padded anonymous
tunnel. The server decrypts and receives four requested bucket IDs and can
observe the fresh isolated Tor request's timing and volume, an intermediary sees
the common route and fixed outer size class instead of the operation name.

Discovery is k-anonymous bucket retrieval, not private information retrieval. The
default deployment operates both the VOPRF and the encrypted-record database, so
an operator with the OPRF secret can evaluate guessed handles and compare their
forward bucket pattern with stored publication rows. Fresh per-call Tor isolation,
cover buckets, fixed record sizes, and delayed publication reduce passive
linkage, they do not prevent malicious-server enumeration or global timing
correlation.

Key transparency makes discovered account-root changes append-only and
detectable to clients that share a trusted server-signer history. Its queries do
not send a readable handle, but they do send the stable opaque label to the
destination server. The first valid registration controls that label. Key
transparency does not prove real-world ownership, prevent the operator from
testing guessed handles, or eliminate first-install trust in the configured
server signer.

## Retention

Readable app data is mainly on your device until you delete it.

Default server-side retention is:

- opaque account authentication records and slots: persistent in the account
  database until operator-side database maintenance or deletion
- opaque key-transparency labels, map state, commitments, encrypted event
  history, Merkle nodes, and signed append-only history: persistent for the life
  of the transparency database, ordinary protocol operation does not delete or
  rewrite prior events
- encrypted global spool blobs: up to one hour
- encrypted delayed-mix recovery entries: up to one hour if processing cannot
  complete, normally released within seconds
- live-only call signaling: never written to the delayed-mix recovery pool or
  global catch-up spool, bounded live publication buffers may retain an
  encrypted frame for up to 30 seconds during transport pressure
- live authorization and transport state: held on the WebSocket and removed when
  that connection closes
- encrypted discovery publications: 24 hours, an unprocessed delayed-publication
  queue has a 7-day recovery TTL by default
- server-generated discovery cover rows: 30 minutes by default
- encrypted avatar blobs: about 7 days plus at most one six-hour expiry-rounding
  interval
- keyed one-use Privacy Pass nullifier hashes: retained only through the token's
  coarse UTC-day expiry (at most the current and previous token epoch), precise
  redemption timestamps are not stored
- proof-of-work, challenge, rate-limit, and registration-receipt state: bounded
  by the short windows documented in the protocol and environment documentation
- coarse server-health or abuse-prevention material: as needed for operation,
  security, legal needs, or abuse prevention.

Even while retained, this material is not readable user data. Self-hosted, third-party, modified, backed-up, or legally restricted deployments may behave differently.

## Legal Requests

We can only provide what exists.

For core communications, the default server does not have readable messages,
files, calls, profiles, contact graphs, plaintext passwords, local passphrases,
or decryption keys. It may have the persistent opaque authentication record and
the limited-retention encrypted and metadata records described above.

Any response is limited to material that exists, such as opaque credential
records, transparency labels and cryptographic history, encrypted blobs,
bucket/publication metadata, nullifier hashes, connection or request timing,
and operational logs. These are not readable message content or anything useful thats linkable to a user, but they can
still be classified as evidence.

## Your Controls

You can clear local app data, log out, delete local encrypted storage, change local settings, block users, change device permissions, and choose which server to connect to.

Because the server does not keep a readable user record, there is no readable server side profile for us to access, export, correct, or delete.

## Other Notes

Qorc is not directed to children under 13.

We may update this policy by changing the date above and, where appropriate, providing notice.

## Contact

galacticoderr@gmail.com
