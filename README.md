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

`src-tauri` is a separate workspace and needs a Mac. It also needs real icons
before the first bundle:

    cd src-tauri && cargo tauri icon icons/icon.png
    cargo tauri dev

Notification buttons only work from a signed, bundled app, so the dev loop is
`tauri dev` rather than a bare `cargo run`.

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
