Cashr is a macOS menu bar Cashu wallet with Nostr signing and zaps.
This first beta supports Apple Silicon Macs running macOS 12 or later.

- Create or restore a wallet with 12 words that also derive your Nostr identity.
- Connect Nostr apps and approve signing requests, with saved per-app permissions.
- Send and receive Cashu tokens, pay Lightning invoices, and approve zaps.

## Install

Download the ZIP, double-click it to extract `Cashr.app`, then drag the app into
Applications. A DMG is also available. This build uses a self-signed certificate
and is **not notarized by Apple**; the ZIP avoids the separate DMG-opening step.

After attempting to open Cashr, if macOS says the developer cannot be verified,
use **System Settings → Privacy & Security → Open Anyway**, then confirm **Open**.
See [Apple's instructions](https://support.apple.com/en-us/102445).
You do not need to install a certificate or disable Gatekeeper.

To verify your download, place `SHA256SUMS` beside the ZIP or DMG and run:

```sh
shasum -a 256 -c SHA256SUMS --ignore-missing
```

## Beta limitations

Start with a separate identity and a small balance. Installation and upgrades on
a Mac without the local signing certificate still need validation.

Touch ID is enforced by the app. The device password is stored in
`unlock.passphrase`; someone who can read the app's data files can decrypt its
stored keys. See the repository's backup and recovery documentation.

Nostr signer relays reconnect after missing heartbeat responses. NWC payment
relay connections do not yet have the same pong-timeout detection.
