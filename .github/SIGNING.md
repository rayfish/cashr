# Signed macOS builds

The **Signed macOS DMG** GitHub Actions workflow builds an Apple Silicon app,
signs it with Developer ID, notarizes it through Apple, and uploads the signed
DMG as a workflow artifact. It runs manually and does not publish a release.

## One-time setup

You need an Apple Developer account with a **Developer ID Application**
certificate and its private key. The local `Cashr Local` certificate cannot
be used for this notarized build.

In Keychain Access, export the signing identity and private key as a
password-protected `.p12` file. Encode it for GitHub using Tauri's documented command:

```sh
openssl base64 -A -in /path/to/certificate.p12 -out certificate-base64.txt
```

In the repository's **Settings → Secrets and variables → Actions**, add:

| Secret | Value |
| --- | --- |
| `APPLE_CERTIFICATE` | Contents of `certificate-base64.txt`. |
| `APPLE_CERTIFICATE_PASSWORD` | Password used when exporting the `.p12`. |
| `APPLE_SIGNING_IDENTITY` | Full identity, such as `Developer ID Application: Your Name (TEAMID)`. |
| `APPLE_ID` | Apple account email. |
| `APPLE_PASSWORD` | An Apple **app-specific password**, not your account password. |
| `APPLE_TEAM_ID` | Apple Developer Team ID. |

Keep certificate files and passwords out of the repository. Tauri imports the
identity into a temporary keychain on the GitHub macOS runner.

See [Tauri's signing and notarization guide](https://v2.tauri.app/distribute/sign/macos/)
for certificate creation and Apple credential setup.

## Build and download

Once the workflow is on the default branch, open **Actions → Signed macOS DMG →
Run workflow**. Download the DMG artifact from the completed run.

The workflow checks the app signature, stapled notarization ticket, Gatekeeper
acceptance, and DMG signature before uploading. Missing credentials fail the run
before compilation.
