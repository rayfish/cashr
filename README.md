# nostr-tray

A macOS menu bar NIP-46 signer. Keys live in the Keychain behind Touch ID,
clients pair over relays, and every request is checked against a permission
rule before anything is signed.

## Layout

    crates/signer-core     policy, NIP-46 sessions, storage. No Tauri, no macOS.
    crates/relay-transport the relay pool behind signer-core's Transport trait
    crates/macos-native    Keychain and notification prompts
    src-tauri              the app: tray, window, commands
    ui                     the window's frontend, plain HTML and JS

`signer-core` reaches the platform through three traits (`KeyStore`,
`Approver`, `Transport`), which is what lets the parts that decide what may be
signed be tested without a Mac and without a relay.

## Building

The core crates build and test anywhere:

    cargo test -p signer-core -p relay-transport -p macos-native
    cargo clippy -p signer-core -p relay-transport -p macos-native --all-targets -- -D warnings

`src-tauri` is a separate workspace and needs a Mac:

    ./scripts/make-signing-cert.sh    # once per machine
    ./scripts/build-macos.sh          # .app and .dmg under src-tauri/target/release/bundle

For a dev loop, `cd src-tauri && cargo tauri dev`. Notification buttons only
work from a signed, bundled app, so a bare `cargo run` will not show them.

## Signing

The build is signed with a self-signed certificate created once by
`make-signing-cert.sh`. That is not about proving anything to anyone: a
Keychain item's ACL binds to the app's code signature, so a build signed with
a fresh key every time looks like a different app to macOS and is refused
access to the keys it stored last time. A stable identity is what stops your
keys apparently vanishing after every rebuild.

`UNUserNotificationCenter` is the other reason. Unsigned bundles commonly get
"Notifications are not allowed for this application" and post nothing, which
costs the Approve/Reject buttons. The tray badge and the window still list
pending requests, so it degrades rather than breaks.

Because the certificate is self-signed, Gatekeeper on any other Mac will
object to the download. Installing there means right-click, Open, or:

    xattr -dr com.apple.quarantine /Applications/nostr-tray.app

Distributing properly needs a Developer ID Application certificate from the
Apple Developer Program plus notarization and stapling. Nothing in the project
blocks that: set `APPLE_SIGNING_IDENTITY` to the Developer ID instead, and add
the notarization credentials the Tauri CLI reads.

The bundle identifier `dgrr.tray.nostr` is the Keychain service name and the
notification registration. Changing it orphans every stored key.

## How it works

Each account has two keys. The identity key is your npub and signs your
events. The transport key is what the bunker listens on, so relay operators do
not get a log of which apps connect to which npub. Both live in one Keychain
item per account, which makes unlocking an account a single Touch ID prompt.

Pairing works in both directions. `bunker://` is minted here and pasted into
the client; `nostrconnect://` is minted by the client and pasted in here. Both
end in a one-shot secret that the next matching `connect` consumes, and a
`nostrconnect://` secret is pinned to the client that produced it.

Permissions are stored per client, per method, and per event kind for
`sign_event`. Approving notes does not approve direct messages. Matching is
most specific first: an exact kind rule, then a method-wide rule, then the
user is asked.

A request with no stored rule posts a notification with Approve and Reject
buttons. A Focus mode can suppress that notification, so the tray icon badges
and the window lists pending requests: a prompt nobody saw is still reachable.

The database holds metadata only. No key material is ever written to it.
