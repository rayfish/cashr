# Byrgi

A macOS menu bar NIP-46 signer. *Byrgi* is Icelandic for a shelter, an
enclosed place: a bunker, which is what NIP-46 calls this.

Keys live in the Keychain behind Touch ID, clients pair over relays, and every
request is checked against a permission rule before anything is signed.

## Layout

    crates/signer-core     policy, NIP-46 sessions, storage. No Tauri, no macOS.
    crates/relay-transport relay websockets behind signer-core's Transport trait
    crates/macos-native    Keychain and notification prompts
    src-tauri              the app: tray, window, commands
    src-tauri/icons        tray.svg is the menu bar mark, icon.svg the app's
    ui                     the window's frontend, plain HTML and JS

`signer-core` reaches the platform through three traits (`KeyStore`,
`Approver`, `Transport`), which is what lets the parts that decide what may be
signed be tested without a Mac and without a relay.

## Building

`just --list` shows everything. The core crates build and test anywhere:

    just check        # fmt, clippy -D warnings, test

`src-tauri` is a separate workspace and needs a Mac. The macOS recipes only
appear there:

    just tools        # once, installs the Tauri CLI (a separate cargo binary)
    just cert         # once per machine, creates the signing identity
    just release      # build, sign, and report what it is signed with
    just dev          # run from source

The bundle lands in `src-tauri/target/release/bundle`. Notification buttons
only work from a signed, bundled app, so `just dev` shows the window and the
tray but not the Approve/Reject buttons.

## Signing

The build is signed with a self-signed certificate created once by
`just cert`. That is not about proving anything to anyone: a
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

    xattr -dr com.apple.quarantine /Applications/Byrgi.app

Distributing properly needs a Developer ID Application certificate from the
Apple Developer Program plus notarization and stapling. Nothing in the project
blocks that: set `APPLE_SIGNING_IDENTITY` to the Developer ID instead, and add
the notarization credentials the Tauri CLI reads.

The bundle identifier `dgrr.tray.byrgi` is the Keychain service name and the
notification registration. Changing it orphans every stored key.

## How it works

Each account has two keys. The identity key is your npub and signs your
events. The transport key is what the bunker listens on, so relay operators do
not get a log of which apps connect to which npub. Both live in one Keychain
item per account, which makes unlocking an account a single Touch ID prompt.

Pairing works in both directions, and the two are not symmetric. `bunker://`
is minted here and pasted into the client, which then sends a `connect` this
signer answers. `nostrconnect://` is minted by the client and pasted in here,
and there the signer speaks first: the client is already waiting for a message
carrying its own secret back, so accepting the URI sends that ack unprompted.
Either way the secret is one-shot, and a `nostrconnect://` secret is pinned to
the client that produced it.

A `nostrconnect://` URI names the relays the client listens on, which are its
own and need not be the signer's. Accepting one adds them to the account, so
they show up in the relay list and can be removed there.

Permissions are stored per client, per method, and per event kind for
`sign_event`. Approving notes does not approve direct messages. Matching is
most specific first: an exact kind rule, then a method-wide rule, then the
user is asked.

Left click on the menu bar icon opens the window under it and clicking again
puts it away. Right click gets the menu. The window is a popover: no title bar,
and it hides when it loses focus. The pin in its header holds it open, which is
what you want while pasting a `nostrconnect://` URI in from a browser, and it
is held automatically while an approval is waiting or while Touch ID has the
focus.

A request with no stored rule posts a notification with Approve and Reject
buttons. A Focus mode can suppress that notification, so the tray icon badges
and the window lists pending requests: a prompt nobody saw is still reachable.

The database holds metadata only. No key material is ever written to it.

Relay connections are one socket per account per relay, over yawc with
permessage-deflate. Two accounts never share a connection: that would tie them
together for the relay operator, which is the thing separate transport keys
exist to prevent. Each connection reconnects on its own with backoff, so a
relay being down is a property of that relay rather than something that stops
an account. TLS is rustls throughout; nothing in the tree wants a system
OpenSSL.
