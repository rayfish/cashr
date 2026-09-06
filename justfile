# nostr-tray

# The code signing identity builds are signed with. Override with
# APPLE_SIGNING_IDENTITY to use a Developer ID instead.
identity := env_var_or_default("APPLE_SIGNING_IDENTITY", "nostr-tray Local")

# How long the self-signed certificate lasts.
cert_days := "3650"

core_crates := "-p signer-core -p relay-transport -p macos-native"

_default:
    @just --list

# Format, lint and test everything that builds off a Mac
check: fmt lint test

fmt:
    cargo fmt --all
    cd src-tauri && cargo fmt

lint:
    cargo clippy {{ core_crates }} --all-targets -- -D warnings

test:
    cargo test {{ core_crates }}

# Run the app from source
dev:
    # Notification buttons need a signed bundle, so this shows the window and
    # the tray but not the Approve/Reject buttons.
    cd src-tauri && cargo tauri dev

# Generate the icon set from icons/icon.png
icon:
    cd src-tauri && cargo tauri icon icons/icon.png

# Create the self-signed code signing identity, once per Mac
[macos]
cert:
    #!/usr/bin/env bash
    set -euo pipefail

    # The point is that the identity is stable. A Keychain item's ACL binds to
    # the app's code signature, so a build signed with a fresh key every time
    # looks like a different app to macOS and is refused the keys it stored
    # last time. This certificate never leaves the machine and proves nothing
    # to anyone else.

    if security find-identity -v -p codesigning | grep -qF "{{ identity }}"; then
        echo "Identity '{{ identity }}' already exists. Nothing to do."
        exit 0
    fi

    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT

    cat > "$work/openssl.cnf" <<CONF
    [ req ]
    distinguished_name = dn
    prompt             = no
    x509_extensions    = codesign

    [ dn ]
    CN = {{ identity }}

    [ codesign ]
    basicConstraints     = critical,CA:false
    keyUsage             = critical,digitalSignature
    extendedKeyUsage     = critical,codeSigning
    CONF

    echo "Creating a {{ cert_days }}-day code signing certificate for '{{ identity }}'."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$work/key.pem" -out "$work/cert.pem" \
        -days {{ cert_days }} -config "$work/openssl.cnf"

    keychain="$HOME/Library/Keychains/login.keychain-db"

    # Key and certificate go in separately rather than as a PKCS#12 bundle.
    # OpenSSL and the Security framework disagree about how an empty-password
    # p12 is authenticated, which fails as "MAC verification failed during
    # PKCS12 import". Two PEMs have no password to disagree about.
    #
    # -T lets those tools use the key without a dialog on every signature.
    echo "Importing the private key."
    security import "$work/key.pem" -k "$keychain" \
        -T /usr/bin/codesign -T /usr/bin/productsign

    echo "Importing the certificate."
    security import "$work/cert.pem" -k "$keychain" -T /usr/bin/codesign

    # codesign refuses an identity that is not trusted for code signing. This
    # is a user-domain trust setting, so no sudo, but it does put up a dialog.
    echo "macOS will ask you to confirm trusting the certificate."
    security add-trusted-cert -r trustRoot -p codeSign -k "$keychain" "$work/cert.pem"

    # Without this the first codesign run pops a keychain dialog that a build
    # cannot answer. It needs the login password, so it asks.
    echo "Pre-authorising the key for codesign."
    security set-key-partition-list -S apple-tool:,apple:,codesign: -s "$keychain" >/dev/null 2>&1 || \
        echo "Could not pre-authorise the key; expect one prompt on the first build."

    if ! security find-identity -v -p codesigning | grep -qF "{{ identity }}"; then
        echo >&2
        echo "The identity did not appear in the code signing list." >&2
        echo "Fall back to Keychain Access: Certificate Assistant, Create a" >&2
        echo "Certificate, type Code Signing, self-signed, named" >&2
        echo "'{{ identity }}'." >&2
        exit 1
    fi

    echo
    security find-identity -v -p codesigning | grep -F "{{ identity }}"

# Build and sign the app bundle
[macos]
build:
    #!/usr/bin/env bash
    set -euo pipefail

    # Signing is not optional in practice: an unsigned build gets a new
    # signature every time and the Keychain refuses keys stored by what it
    # considers a different app. Notifications also stay silent without one.

    if ! security find-identity -v -p codesigning | grep -qF "{{ identity }}"; then
        echo "No code signing identity called '{{ identity }}'." >&2
        echo "Create one with: just cert" >&2
        exit 1
    fi

    if [[ ! -f src-tauri/icons/icon.icns ]]; then
        just icon
    fi

    export APPLE_SIGNING_IDENTITY="{{ identity }}"
    cd src-tauri && cargo tauri build

# Report what the built bundle is signed with
[macos]
verify:
    #!/usr/bin/env bash
    set -euo pipefail

    app="src-tauri/target/release/bundle/macos/nostr-tray.app"
    if [[ ! -d "$app" ]]; then
        echo "No bundle at $app. Run: just build" >&2
        exit 1
    fi

    codesign --verify --deep --strict --verbose=2 "$app"
    codesign -dvv "$app" 2>&1 | grep -E "Identifier|Authority|Signature"

    echo
    # A self-signed certificate is not a Gatekeeper-accepted authority, so
    # this fails on purpose. Printing it keeps the failure expected rather
    # than alarming.
    echo "Gatekeeper (a rejection is expected for a self-signed build):"
    spctl --assess --type execute --verbose=4 "$app" || true

    echo
    echo "Bundle:    $app"
    echo "Installer: $(ls src-tauri/target/release/bundle/dmg/*.dmg 2>/dev/null || echo none)"

# Build, sign and report in one go
[macos]
release: build verify
