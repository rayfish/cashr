# macOS beta builds

The **macOS beta DMG** workflow builds an Apple Silicon app, signs it with our
self-signed `Cashr Local` certificate, and uploads a DMG and `SHA256SUMS`.
It runs only when a new `v*` tag is pushed and publishes a GitHub prerelease after
verification. Branch pushes and updates to existing tags do not build a DMG.
No Apple Developer membership is needed. These builds are not notarized and
require a macOS installation exception.

## Signing secrets

Local builds use `just build` and the certificate already in your Keychain.
GitHub Actions needs a copy of that signing identity:

1. In Keychain Access, select **login → My Certificates → Cashr Local**.
2. Export the certificate together with its private key as a password-protected
   `.p12` file. If needed, expand the certificate to select its private key.
3. Encode the export:

   ```sh
   openssl base64 -A -in /path/to/cashr-signing.p12 -out certificate-base64.txt
   ```

4. Under the repository's **Settings → Secrets and variables → Actions**, add:

| Secret | Value |
| --- | --- |
| `APPLE_CERTIFICATE` | Contents of `certificate-base64.txt` (certificate and private key). |
| `APPLE_CERTIFICATE_PASSWORD` | Password chosen when exporting the `.p12`. |
| `APPLE_SIGNING_IDENTITY` | `Cashr Local` |

The names follow the existing build convention; this certificate is self-signed.
No `APPLE_ID`, `APPLE_PASSWORD`, or `APPLE_TEAM_ID` is required.
Keep the same certificate across releases. Never commit the `.p12`, its base64
copy, or its password. This is the app's signing key, not a wallet key.

The workflow uses [apple-actions/import-codesign-certs](https://github.com/Apple-Actions/import-codesign-certs)
to import the identity into a temporary keychain and delete it after the build.
A separate step trusts our self-signed certificate for code signing on the
disposable runner. End users do not need to install or trust the certificate.

## Build and download

After the workflow and release notes are committed and the three secrets are
configured, create and push a new version tag. The tagged commit must contain
this workflow. Keep the version in `src-tauri/tauri.conf.json` and
`src-tauri/Cargo.toml` in sync with the tag, and update `.github/RELEASE_NOTES.md`.
Download the DMG and `SHA256SUMS` from the resulting GitHub prerelease.

The workflow verifies the app and DMG signatures and the disk image integrity.
It skips notarization and Gatekeeper acceptance checks because these builds have
no Apple-verified developer identity. Before publishing, test a browser download,
Touch ID, notifications, recovery, and an upgrade on a Mac without the local
signing certificate.

## Install a beta

1. Download the DMG from this repository's release page and drag Cashr into Applications.
2. Open Cashr. If macOS blocks it because the developer cannot be verified, open
   **System Settings → Privacy & Security → Open Anyway**, then confirm **Open**.

This creates an exception for Cashr. It does not require disabling Gatekeeper.
See [Apple's instructions](https://support.apple.com/en-us/102445).

To verify the download, place `SHA256SUMS` beside the DMG and run:

```sh
shasum -a 256 -c SHA256SUMS
```

The checksum detects a mismatched download; it does not replace developer
verification or notarization. Use a separate identity and a small balance when
trying an early beta.

See [Tauri's signing guide](https://v2.tauri.app/distribute/sign/macos/) for
Developer ID signing and notarization when enrollment becomes available.
