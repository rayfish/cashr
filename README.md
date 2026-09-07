# Byrgi

A macOS menu bar Nostr signer and Cashu wallet. *Byrgi* is Icelandic for a
shelter or enclosed place—a bunker.

- Create or import accounts in **Settings**.
- Pair clients using `bunker://` or `nostrconnect://` links.
- Scan QR codes from a screen selection or clipboard image using **Scan QR**.
  Decoding stays on your Mac; choose **Connect** to pair a scanned client link.
- Approve requests in the app or through notifications, with optional saved
  permissions per client, method, and event kind.
- Manage connected clients, relays, and request history.
- Use **Wallet** to fund a Cashu balance, receive tokens, pay Lightning invoices,
  and zap a Nostr account or note. Payments have a separate amount/fee approval.

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
| NIP-57 | Create signed zap requests, validate invoice amount/description hash, and pay through Cashu. Receipts are published by the recipient’s provider. |

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
UI tests run with `node --test ui/tests/*.test.cjs`.

Opening **Scan QR** requests Screen Recording permission if needed.
Clipboard image scanning does not need screen access. Scanned Lightning invoices
can be opened in Wallet for review.

## Wallet

The default wallet uses `https://btc.aleafnd.org/cashu`, whose advertised deposit/payment
limit is 10,000 sats. The mint holds the bitcoin backing your Cashu tokens.
Pay funding invoices from another wallet, then **Refresh** to claim tokens.
Refresh also reconciles pending payments after interruptions; a timeout does
not mean a payment failed.

Wallet databases are encrypted with SQLCipher under the app’s `wallets` folder.
Back up the entire application data directory and retain your passphrase.
Original wallet seeds are derived from each Nostr identity. **Import wallet**
accepts a BIP-39 seed phrase, original mint URL, and optional BIP-39 passphrase
for wallets using Cashu's standard NUT-13 derivation. Imported wallets stay
separate and can be selected using the wallet picker. Recovery requires the
original mint to be available and support restoration; repeat the import for
each mint used by the source wallet. Backup-file and NIP-60 imports are not supported.
Seed recovery does not replace a database backup or recover every pending
operation. Account deletion is blocked once it has a wallet.

Nostr Wallet Connect (NIP-47), NIP-60 wallet synchronization, and hosted Lightning
address registration are not implemented yet. The existing-address setting only
saves a receiving address locally.

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
