# Cashr

A macOS menu bar Cashu wallet with Nostr signing and zaps.

- Create or restore a wallet with a 12-word recovery phrase that also derives your Nostr identity.
- Send and receive Cashu tokens, pay Lightning invoices, and approve zaps.
- Connect Nostr apps using `bunker://`, `nostrconnect://`, or QR codes.
- Approve signing requests in the app or notifications, and save permissions for trusted apps.
- Scan QR codes from your screen or clipboard. Decoding stays on your Mac.

## Build and run

Requires macOS, Rust, and `just`.

```sh
just tools    # Install the Tauri CLI
just cert     # Create a local signing identity
just release  # Build, sign, and verify the app and DMG
just dev      # Run from source
```

Install the bundle from `src-tauri/target/release/bundle` in `/Applications`.
Use a signed build for notification approval buttons. Builds use a self-signed
`Cashr Local` certificate. Beta builds can be shared directly, but macOS will warn
that the developer cannot be verified. Developer ID signing and notarization
remove that warning. Set `APPLE_SIGNING_IDENTITY` to use another certificate.

For self-signed beta ZIPs and DMGs built in GitHub Actions and installation instructions,
see [CI signing setup](.github/SIGNING.md).

Run `just check` for formatting, linting, and tests. Run UI tests with
`node --test ui/tests/*.test.cjs`. See `just --list` for all tasks.

## Wallet

Create or restore a wallet in **Settings**. New wallets use Minibits by default.
Use **Choose mint** to select a saved or recommended mint, or add an HTTPS mint URL.
Each mint has its own balance; switching mints does not move funds. The mint holds
the bitcoin backing your tokens. Deposits and Lightning payments are limited to
10,000 sats.

Use **Wallet** to fund your balance, receive tokens, or pay Lightning invoices.
Payments require a separate amount and fee approval. Incoming payments are claimed
automatically while Cashr is awake and unlocked, even with the window closed.
Use **Refresh** to reconcile pending payments after an interruption. A timeout
does not mean a payment failed.

### Connect apps and send zaps

In **Wallet → Nostr**, paste a `nostrconnect://` link, copy a bunker URL, or scan a QR
code to connect a Nostr app. Manage saved approvals in **Permissions**.

For payments, use **Wallet → Nostr → Connect for zaps** and paste the NWC link into
your app's wallet settings. The connection uses that mint's balance, even if you
select another mint in Cashr. Every payment needs approval, and Cashr must be
running with the Mac awake. Use **Revoke** to remove payment access.

If an NWC payment's result is unknown, check wallet transactions. Cashr does not
automatically resubmit an invoice already attempted through NWC.

### Receive zaps

Use **Receive → Use npub.cash** to set up a Lightning address at the selected mint.
Copy it into your Nostr profile's Lightning Address field. Changing the mint picker
does not change where the address receives funds; use **Use npub.cash** again to
change its receiving mint.

**Receive → Get a readable name** lets you check and buy an npub.cash username.
Review the price and maximum fee before claiming it. The name also works as a
NIP-05 identifier. Cashr does not update your Nostr profile for you.

For an interrupted name purchase, use **Check status**, **Retry claim**, or
**Reclaim unspent payment**. Keep the wallet database until the purchase is resolved.

## Backup and recovery

Use **Backup and recovery → Show recovery phrase** while unlocked. Save the words,
every mint URL, and any BIP-39 passphrase used during restoration.

**Restore wallet** accepts those details, restores the same Nostr identity, and
scans for unspent tokens. Choose each original mint to recover its funds. Recovery
requires the mint to be available and support restoration, and may not recover
every pending operation.

Back up the entire app data directory at
`~/Library/Application Support/com.dgrr.cashr`, including the local device key.
Wallet databases and recovery words are encrypted with SQLCipher.

Cashr uses Touch ID or your Mac login password to unlock, with no separate wallet
password. Account keys are encrypted, but the internal device password is stored
in plaintext in `unlock.passphrase`. Anyone who can read that file and the key
files can decrypt the keys. Authentication is enforced by the app, not Secure Enclave storage.

If local access is lost, use **Recover with recovery words**. Your wallet and Nostr
identity stay the same, but connected apps may need to reconnect.

## NIP support

| NIP | Supported features |
| --- | --- |
| `NIP-01` | Event signing, relay subscriptions, and publishing. |
| `NIP-04` | Legacy encryption and decryption. |
| `NIP-06` | Nostr identity derived from the wallet recovery phrase. |
| `NIP-19` | `npub` display and identifier parsing. |
| `NIP-42` | Relay authentication. |
| `NIP-44` | Encryption and decryption, including NIP-46 messages. |
| `NIP-46` | Remote signing with bunker and Nostr Connect pairing. |
| `NIP-49` | Encrypted account key storage (`ncryptsec`). |
| `NIP-57` | Zap requests and payments through Cashu. |

Support covers these features, not every part of each NIP. Zap receipts are
published by the recipient's provider.

NWC supports `get_info`, `get_balance`, and `pay_invoice` with NIP-44 or NIP-04
encryption. Remote Lightning wallet import, Lightning channel recovery, and
NIP-60 wallet synchronization are not supported.

## Project layout

- `crates/signer-core`: accounts, signing, permissions, and storage.
- `crates/relay-transport`: relay connections.
- `crates/macos-native`: macOS authentication and notifications.
- `src-tauri`: desktop app, tray, and commands.
- `ui`: frontend.
