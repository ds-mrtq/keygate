# Releases

## Cut a release

Push a version tag on the commit to release (initial release: `v0.1.0`):

```sh
git tag v0.1.0
git push origin v0.1.0
```

The Release workflow builds Linux, macOS, and Windows for amd64 and arm64,
with cgo disabled. It creates a **draft** GitHub release; review its assets
and publish it manually. Workflow dispatches and pull requests changing the
workflow only build/package `dev-<shortsha>` workflow artifacts: no signing,
attestation, or release creation.

Each `kg_<tag>_<os>_<arch>.tar.gz` (Windows: `.zip`) includes `LICENSE`,
`README.md`, and `kg` (Windows: both `kg.exe` and tray broker `kgw.exe`).
Every binary is stamped with `-ldflags "-X main.version=<version> -X main.commit=<sha>"`,
so `kg version` prints the tag (or `dev-<shortsha>` for dry runs). The
`verify-packages` job unpacks the Linux amd64 archive and the Windows amd64
zip on matching runners and fails unless `kg version` reports that version and
commit; a tag release is only created after it passes.
The committed Windows amd64 `.syso` embeds the icon automatically; the
amd64-only `tools/gen-winres` generator is not needed for releases. Windows
arm64 builds without that icon resource.

## Verify downloads

All release archives and `SHA256SUMS` receive GitHub build-provenance
attestations, signed keylessly using GitHub OIDC/Sigstore. With GitHub CLI,
verify the manifest and every archive you intend to use before extracting:

```sh
gh attestation verify SHA256SUMS --repo ds-mrtq/keygate
gh attestation verify kg_v0.1.0_linux_amd64.tar.gz --repo ds-mrtq/keygate
sha256sum -c SHA256SUMS
```

Download all archives to check the complete manifest (or check only the
relevant manifest entries). Attestations establish workflow provenance;
checksums detect corruption. Neither implies native OS signing.

## Optional native signing

Configure repository Actions secrets before pushing the tag:

- Apple: `APPLE_CERT_P12_BASE64` (Developer ID Application certificate and
  private key), `APPLE_CERT_PASSWORD`, `APPLE_NOTARY_KEY_P8_BASE64` (App Store
  Connect API private key), `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID`.
  Both macOS binaries are codesigned with hardened runtime and a timestamp,
  then submitted to Apple notarization and required to be accepted. Bare
  executables cannot carry stapled tickets; Gatekeeper may need network
  access to retrieve the notarization ticket.
- Windows: `WINDOWS_CERT_PFX_BASE64` (code-signing certificate and private
  key) and `WINDOWS_CERT_PASSWORD`. Both executables on both architectures
  receive SHA-256 Authenticode signatures with an RFC 3161 timestamp.

If any required secret for a platform is absent/empty, native signing for
that platform is skipped. If all are present, signing or notarization
failure stops the release. Native signing happens before packaging,
checksumming, and provenance attestation. Temporary credentials are removed
on step exit. Native signing is never attempted in dry runs.
