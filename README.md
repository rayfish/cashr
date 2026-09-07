# Byrgi

A macOS menu bar app that signs Nostr events without sharing your private keys
with clients. *Byrgi* is Icelandic for a shelter or enclosed place—a bunker.

- Create or import accounts in **Settings**.
- Pair clients using `bunker://` or `nostrconnect://` links.
- Scan QR codes from a screen selection or clipboard image using **Scan QR**.
  Decoding stays on your Mac; choose **Connect** to pair a scanned client link.
- Approve requests in the app or through notifications, with optional saved
  permissions per client, method, and event kind.
- Manage connected clients, relays, and request history.

## NIP support

| NIP | Implemented scope |
| --- | --- |
| NIP-01 | Event signing and basic relay subscriptions and publishing. |
| NIP-04 | Encrypt/decrypt methods and fallback decryption for incoming NIP-46 messages. |
| NIP-19 | `npub` display and `nsec` private-key import; hex import is also supported. |
| NIP-42 | Relay authentication using each account’s transport key, with retries for authentication-blocked requests. |
| NIP-44 | Encrypt/decrypt methods and encryption for NIP-46 messages. |
| NIP-46 | Remote signing, with both `bunker://` and `nostrconnect://` pairing. |
| NIP-49 | Passphrase-encrypted `ncryptsec` storage for account keys. |

Supported NIP-46 methods: `connect`, `get_public_key`, `sign_event`, `ping`,
`nip04_encrypt`, `nip04_decrypt`, `nip44_encrypt`, and `nip44_decrypt`.

This lists the features used by Byrgi, not full conformance to every listed NIP.
Signing an event kind does not imply support for the entire NIP that defines it.

## Build and run

Requires macOS, Rust, and `just`.

```sh
just tools    # Install the Tauri CLI once
just cert     # Create a local signing identity once per Mac
just release  # Build, sign, and verify the app and DMG
just dev      # Run from source
```

Bundles are written to `src-tauri/target/release/bundle`. Install the app in
`/Applications` and open it from the menu bar. Use a signed bundle for
notification approval buttons.

Builds use a self-signed certificate by default. Public distribution requires
a Developer ID certificate and notarization; `APPLE_SIGNING_IDENTITY` overrides
the local signing identity.

Run `just check` for formatting, linting, and tests, or `just --list` for all tasks.
Scanner UI tests run with `node --test ui/tests/qr.test.cjs`.

Opening **Scan QR** requests Screen Recording permission if needed.
Clipboard image scanning does not need screen access. Lightning and Cashu QR
codes can be read and copied; payments and wallet connections are not implemented.

## Key storage

Each account has separate identity and transport keys. Both are encrypted with
your passphrase and stored under
`~/Library/Application Support/com.dgrr.byrgi/keys`. The database stores account,
client, permission, and activity metadata, not private keys.

**Touch ID unlock is a convenience with a storage tradeoff:** enabling it saves
the passphrase in plaintext in `unlock.passphrase` alongside the database.
Touch ID gates access inside the app; anyone able to read that file and the key
files can decrypt the keys. Disabling Touch ID deletes the saved passphrase.

## Project layout

- `crates/signer-core`: accounts, signing sessions, permissions, and storage.
- `crates/relay-transport`: relay WebSocket connections.
- `crates/macos-native`: macOS authentication, notifications, and legacy Keychain access.
- `src-tauri`: desktop app, tray, and commands.
- `ui`: HTML, CSS, and JavaScript frontend.
