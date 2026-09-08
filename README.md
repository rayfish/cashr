# Cashr

A macOS menu bar Cashu wallet with Nostr signing and zaps.

- Create a 12-word Cashu wallet or restore one in **Settings**.
  The same recovery phrase derives its Nostr identity.
- In **Wallet → Nostr**, paste a `nostrconnect://` link, copy a bunker URL,
  or connect using QR codes.
- Scan QR codes from a screen selection or clipboard image using **Scan QR**.
  Decoding stays on your Mac; choose **Connect** to pair a scanned client link.
- Approve requests in the app or through notifications, with optional saved
  permissions per client, method, and event kind.
- Manage connected clients, relays, and request history.
- Use **Wallet** to fund a Cashu balance, receive tokens, pay Lightning invoices,
  and zap a Nostr account or note using your selected Nostr identity.
  Payments spend the selected Cashu balance after a separate amount/fee approval.

## NIP support

| NIP | Implemented scope |
| --- | --- |
| NIP-01 | Event signing and basic relay subscriptions and publishing. |
| NIP-04 | Encrypt/decrypt methods and fallback decryption for incoming NIP-46 messages. |
| NIP-06 | Nostr identity derived from the wallet’s BIP-39 phrase at `m/44'/1237'/0'/0/0`. |
| NIP-19 | `npub` display and Nostr identifier parsing. |
| NIP-42 | Relay authentication using each account’s transport key, with retries for authentication-blocked requests. |
| NIP-44 | Encrypt/decrypt methods and encryption for NIP-46 messages. |
| NIP-46 | Remote signing, with both `bunker://` and `nostrconnect://` pairing. |
| NIP-49 | Passphrase-encrypted `ncryptsec` storage for account keys. |
| NIP-57 | Create signed zap requests, validate invoice amount/description hash, and pay through Cashu. Receipts are published by the recipient’s provider. |

Supported NIP-46 methods: `connect`, `get_public_key`, `sign_event`, `ping`,
`nip04_encrypt`, `nip04_decrypt`, `nip44_encrypt`, and `nip44_decrypt`.

This lists the features used by Cashr, not full conformance to every listed NIP.
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

New wallets start with a random 12-word BIP-39 phrase and Minibits at
`https://mint.minibits.cash/Bitcoin`. The phrase supplies the Cashu seed (NUT-13)
and derives the Nostr identity using NIP-06, account 0. There is no separate
Nostr private-key import.

Use **Choose mint** to enter another HTTPS mint URL or return to a saved mint.
Each mint keeps its own balance, history, and pending payments, using the same
wallet seed. Changing mints does not move funds. The mint holds the bitcoin
backing your tokens. Deposits and Lightning payments are limited to 10,000 sats.
Pay funding invoices from another wallet, then **Refresh** to claim tokens.
Refresh also reconciles pending payments after interruptions; a timeout does
not mean a payment failed.

**Backup and recovery → Show recovery phrase** reveals the words only while
unlocked. They disappear when you leave, switch accounts, lock, lose window
focus, or after one minute. Save the words and every mint URL. If you restored
with a BIP-39 passphrase, keep that too; it affects both funds and identity.
Cashr uses Touch ID with the macOS login password as a fallback. It has no
separate wallet password.

**Restore wallet** accepts the phrase, original mint URL and optional BIP-39
passphrase. It restores the same Nostr identity and automatically scans for
unspent tokens as the wallet loads. Interrupted scans retry automatically and
resume after reopening. Choosing another mint also discovers its funds.
Restoring the same phrase reuses the existing account and preserves its proofs,
counters and history. A phrase from another Cashu wallet derives a Nostr identity
here; it only matches an identity elsewhere if that app uses the same NIP-06 path.

Wallet databases and recovery words are encrypted with SQLCipher in the app’s
`wallets` directory. Back up the entire application data directory and retain
the local device key too. Seed recovery requires the original mint to be
available and support restoration, and may not recover every pending operation.
Settings includes Rename and Delete. Deletion removes the account and its active
keys; encrypted wallet files remain available for recovery with the same phrase.

Remote Lightning wallet connections, Lightning channel recovery, NIP-60 wallet
synchronization and hosted Lightning address registration are not implemented.
An empty Lightning address field looks up `lud16` in the recovered identity's
verified public Nostr profile. **Find address** retries; **Save address** stores
the result locally. Minibits publishes addresses in these profiles, not in the
mint's information endpoint. Lookup cannot find an address tied to a different
identity and never registers or transfers an address.

## Key storage

Each account has separate identity and transport keys. Both are encrypted with
an internal device password and stored under
`~/Library/Application Support/com.dgrr.byrgi/keys`. The database stores account,
client, permission, and activity metadata, not private keys.
The internal bundle ID and storage format retain their original identifiers so
renaming the app to Cashr keeps existing wallets accessible.

Setup and unlock use the macOS authentication dialog: Touch ID first, with the
Mac login password when Touch ID is unavailable, such as with the lid closed.
Cashr never receives the login password. The internal
device password is stored in plaintext in `unlock.passphrase` alongside the database.
macOS authentication gates access inside the app; anyone able to read that file and the key
files can decrypt the keys. This is app-enforced authentication, not Secure Enclave storage.
If local access is lost, **Recover with recovery words** repairs it while keeping
the wallet database. Inaccessible Nostr transport keys are replaced, so connected
apps may need to reconnect. The wallet and Nostr identity remain the same.

## Project layout

- `crates/signer-core`: accounts, signing sessions, permissions, and storage.
- `crates/relay-transport`: relay WebSocket connections.
- `crates/macos-native`: macOS authentication, notifications, and legacy Keychain access.
- `src-tauri`: desktop app, tray, and commands.
- `ui`: HTML, CSS, and JavaScript frontend.
