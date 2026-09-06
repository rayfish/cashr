#!/usr/bin/env bash
#
# Build, sign and check the app bundle.
#
# Signing is not optional in practice: an unsigned or ad-hoc-signed build gets
# a new signature every time, and the Keychain refuses keys stored by what it
# considers a different app. Notifications also tend to stay silent without a
# signed bundle, which costs the Approve/Reject buttons.

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "The app bundle can only be built on macOS." >&2
  exit 1
fi

IDENTITY="${APPLE_SIGNING_IDENTITY:-nostr-tray Local}"

if ! security find-identity -v -p codesigning | grep -qF "$IDENTITY"; then
  echo "No code signing identity called '$IDENTITY'." >&2
  echo "Create one with: ./scripts/make-signing-cert.sh" >&2
  exit 1
fi

if [[ ! -f src-tauri/icons/icon.icns ]]; then
  echo "Generating the icon set from icons/icon.png."
  (cd src-tauri && cargo tauri icon icons/icon.png)
fi

export APPLE_SIGNING_IDENTITY="$IDENTITY"
(cd src-tauri && cargo tauri build)

app="src-tauri/target/release/bundle/macos/nostr-tray.app"
if [[ ! -d "$app" ]]; then
  echo "Expected a bundle at $app and did not find one." >&2
  exit 1
fi

echo
echo "Signature:"
codesign --verify --deep --strict --verbose=2 "$app"
codesign -dvv "$app" 2>&1 | grep -E "Identifier|Authority|TeamIdentifier|Signature"

echo
# A self-signed certificate is not a Gatekeeper-accepted authority, so this
# fails on purpose. It is worth printing so the failure is expected rather
# than alarming.
echo "Gatekeeper assessment (a rejection here is expected for a self-signed build):"
spctl --assess --type execute --verbose=4 "$app" || true

echo
echo "Bundle:    $app"
echo "Installer: $(ls src-tauri/target/release/bundle/dmg/*.dmg 2>/dev/null || echo 'none built')"
