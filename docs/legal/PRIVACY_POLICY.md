# Qor-Chat Privacy Policy

Effective Date: June 21, 2026  
Last Updated: June 21, 2026

This policy describes the default Qor-Chat app and server operated by galacticoder.

Qor-Chat is built to be blind by design. The server is not a place where readable user profiles, readable usernames, messages, files, calls, contacts, passwords, passphrases, or keys are kept. In normal use, readable information stays on your device or with the people you choose to communicate with.

## Core Promise

Qor-Chat does not require a real-world identity for the core app, and the default server is not given a stable user identity. There is no server side identity and data that follows a person around.

The default server does not receive or store:

- email addresses or phone numbers for core messaging
- stable user IDs, readable account records, or reusable session identifiers
- readable usernames, display names, or profile text
- readable messages, files, voice messages, calls, video, or screen share
- contact lists or a readable contact graph
- plaintext passwords or local database passphrases
- decryption keys.

The server cannot read what you say, who you talk to, who you search for, or attach activity to a stable identity for you.

## What The Server Handles

The server only handles protocol material needed to make the system work:

- encrypted blobs for fallback/offline delivery
- encrypted discovery bundles and encrypted profile/avatar references
- one-time or per-session anonymous authentication material
- encrypted OPAQUE login material, Privacy Pass nullifiers, and similar anti-abuse proofs
- bucket numbers, timing, rate-limit counters, and short-lived session state
- coarse server-health and abuse-prevention logs that do not contain readable identities, recipients, contact graphs, or message content.

This material is not a readable account record and is not a stable user identity. It is opaque, encrypted, random-looking, one-time, per-session, rotated, temporary, or limited-retention. It does not give us readable messages, readable profiles, readable usernames, contacts, or keys.

## Local And Peer Data

Readable app data is local to your device. That includes your message history, files, local profile information, settings, keys, block lists, and app state.

People you communicate with can read, save, copy, or share what you send them. Qor-Chat cannot prevent a recipient from doing that.

## Discovery

Discovery is private lookup. The server does not receive the readable username being searched, does not learn who is searching for whom, and does not get a stable identifier for the person searching.

The server may handle encrypted discovery records, bucket counts, timing, and cover traffic. Those are protocol artifacts, not readable identities.

## Retention

Readable app data is mainly on your device until you delete it.

Server-side protocol material is short-lived or limited-retention by default:

- encrypted relay/spool blobs: commonly about 24 hours
- per-connection transport state: commonly about 1 hour
- per-session anonymous state: commonly about 7 days
- encrypted discovery material: commonly up to about 30 days plus an epoch
- encrypted avatar blobs: commonly up to about 7 days
- one-use Privacy Pass nullifiers and anti-replay markers: commonly about 60 days
- coarse server-health or abuse-prevention material: as needed for operation, security, legal needs, or abuse prevention.

Even while retained, this material is not readable user data. Self-hosted, third-party, modified, backed-up, or legally restricted deployments may behave differently.

## Legal Requests

We can only provide what exists.

For core communications, the default server does not have readable messages, readable files, readable calls, readable usernames, readable profiles, contact graphs, stable user identities, passwords, passphrases, or decryption keys.

The only possible response is opaque protocol material, if any. It is not readable content, not a user profile, and not an identity.

## Your Controls

You can clear local app data, log out, delete local encrypted storage, change local settings, block users, change device permissions, and choose which server to connect to.

Because the server does not keep a readable user record, there is no readable server-side profile for us to access, export, correct, or delete.

## Other Notes

Qor-Chat is not directed to children under 13.

We may update this policy by changing the date above and, where appropriate, providing notice.

## Contact

galacticoderr@gmail.com
