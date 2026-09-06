#!/usr/bin/env bash
#
# Create the self-signed code signing identity nostr-tray builds with.
#
# Run this once per Mac. The point is that the identity is stable: a Keychain
# item's ACL binds to the app's code signature, so an app signed with a
# different key every build looks like a different app to macOS and loses
# access to the keys it stored last time.
#
# The certificate never leaves this machine and proves nothing to anyone else.
# Gatekeeper on someone else's Mac will still object to the download.

set -euo pipefail

NAME="${1:-nostr-tray Local}"
DAYS="${DAYS:-3650}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This script only makes sense on macOS." >&2
  exit 1
fi

if security find-identity -v -p codesigning | grep -qF "$NAME"; then
  echo "Identity '$NAME' already exists. Nothing to do."
  echo "Build with: APPLE_SIGNING_IDENTITY=\"$NAME\" ./scripts/build-macos.sh"
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
CN = ${NAME}

[ codesign ]
basicConstraints     = critical,CA:false
keyUsage             = critical,digitalSignature
extendedKeyUsage     = critical,codeSigning
CONF

echo "Creating a $DAYS-day code signing certificate for '$NAME'."
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$work/key.pem" -out "$work/cert.pem" \
  -days "$DAYS" -config "$work/openssl.cnf"

# An empty password: the p12 only exists for the length of this script, and a
# password here would just have to be typed back in on the next line.
openssl pkcs12 -export -inkey "$work/key.pem" -in "$work/cert.pem" \
  -out "$work/identity.p12" -passout pass:

keychain="$HOME/Library/Keychains/login.keychain-db"

# -T codesign lets codesign use the key without asking every single time.
security import "$work/identity.p12" -k "$keychain" -P "" \
  -T /usr/bin/codesign -T /usr/bin/productsign

# codesign refuses an identity that is not trusted for code signing. This is a
# user-level trust setting, so it does not need sudo, but it does put up a
# password prompt.
echo "macOS will ask for your password to trust the certificate for code signing."
security add-trusted-cert -p codeSign -k "$keychain" "$work/cert.pem"

# Without this, the first codesign run pops a keychain dialog that a build
# script cannot answer.
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "" "$keychain" >/dev/null 2>&1 || \
  echo "Could not pre-authorise the key; expect one keychain prompt on the first build."

echo
echo "Done. Verify with:"
echo "  security find-identity -v -p codesigning"
echo
echo "Then build with:"
echo "  APPLE_SIGNING_IDENTITY=\"$NAME\" ./scripts/build-macos.sh"
