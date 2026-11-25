# Releases

## Weekly releases

The Release workflow (`.github/workflows/release.yml`) runs every Monday at
02:00 UTC (09:00 +07) on `main`. It finds the highest `vX.Y.Z` tag and:

- stops, with a "nothing to release" notice and every later job skipped, when
  `main` has no commits since that tag;
- otherwise bumps the patch (`v0.1.4` after `v0.1.3`; `v0.1.0` when there is
  no tag yet), builds and packages, then creates the tag on the built commit
  and a **published** (non-draft) release in one step with the workflow's own
  `GITHUB_TOKEN`. No other secret is needed. A tag created with that token
  starts no second workflow run, so the scheduled run is the only one for it.

Release notes list the commits merged into `main` since the previous tag
(squash merges, so one line per PR) and the install and verify commands.

Starting the workflow by hand from the Actions page ("Run workflow" on `main`)
does the same as the scheduled run; it is how the first release is cut. Tick
`dry_run` to build and verify without a tag or release. GitHub disables
scheduled workflows after 60 days without repository activity; re-enable it
on the Actions page if that happens.

## Manual tags

For a minor or major bump, push the tag yourself; the weekly patch bumps
continue from it (`v0.2.1` after `v0.2.0`):

```sh
git tag v0.2.0
git push origin v0.2.0
```

The tag-push run builds that commit and publishes the release the same way
(a tag with a `-` suffix, such as `v0.2.0-rc1`, is published as a prerelease
and ignored by the version computation).

## What a run builds and checks

The workflow builds Linux, macOS, and Windows for amd64 and arm64, with cgo
disabled. Each `kg_<tag>_<os>_<arch>.tar.gz` (Windows: `.zip`) includes
`LICENSE`, `README.md`, and `kg` (Windows: both `kg.exe` and tray broker
`kgw.exe`). Every binary is stamped with
`-ldflags "-X main.version=<version> -X main.commit=<sha>"`, so `kg version`
prints the tag (or `dev-<shortsha>` for dry runs). `SHA256SUMS` lists all six
archives.

Before anything is published, `verify-packages` unpacks the Linux amd64
archive and the Windows amd64 zip on matching runners and requires
`kg version` to report that version and commit, and `verify-install` installs
them with the install scripts (below).

After publishing, `verify-release` downloads the published assets on Linux and
Windows, requires all six archives to be present and listed, checks them
against `SHA256SUMS` (`sha256sum -c` on Linux, `Get-FileHash` on Windows), runs
`gh attestation verify` on every asset, and requires `kg version` of the
amd64 binary to equal the tag. If it fails, `mark-result` puts a "Verification
failed, do not install" notice with the run link at the top of the release
notes and demotes the release to a prerelease, so `/releases/latest` (what the
install scripts resolve) skips it; the run stays failed. If "Re-run failed
jobs" then passes `verify-release`, the notice is removed and the release is
no longer a prerelease (latest again unless a newer release exists).

Pull requests that change the workflow, the install scripts or
`tools/release/`, and runs off `main` or with `dry_run`, are dry runs: the
`plan` job tests the version computation and the notes
(`tools/release/release_test.sh`) and reports "Next version would be vX",
packages are built as `dev-<shortsha>`, and `verify-release` runs against those
packages (attestation skipped: dry runs have none). No signing, attestation,
tag or release. A dry run from the Actions page with `simulate_no_changes`
moves the last tag to `HEAD` in the runner's checkout only (nothing is pushed)
to show the skip path.

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
sha256sum -c --ignore-missing SHA256SUMS
```

On Windows (PowerShell), compare the archive's hash with its line in
`SHA256SUMS`:

```powershell
$want = (Select-String -Path SHA256SUMS -Pattern 'kg_v0.1.0_windows_amd64.zip').Line.Split(' ')[0]
(Get-FileHash kg_v0.1.0_windows_amd64.zip -Algorithm SHA256).Hash.ToLower() -eq $want
```

`--ignore-missing` checks only the archives you downloaded; drop it after
downloading all of them to check the complete manifest. Attestations establish workflow provenance;
checksums detect corruption. Neither implies native OS signing.

## Install scripts

`install.sh` (Linux amd64/arm64) and `install.ps1` (Windows amd64/arm64) at the
repository root install a published release for the current user, without
`sudo` or administrator rights:

```sh
curl -fsSL https://raw.githubusercontent.com/ds-mrtq/keygate/main/install.sh | sh
```

```powershell
irm https://raw.githubusercontent.com/ds-mrtq/keygate/main/install.ps1 | iex
```

Both resolve the latest release (or take `--version` / `-Version`, env
`KG_VERSION`), download the archive and `SHA256SUMS`, and exit non-zero
without installing anything unless the archive's SHA-256 matches its
`SHA256SUMS` entry. `install.sh` puts `kg` in `~/.local/bin` and prints a PATH
hint if needed; `install.ps1` puts `kg.exe` and `kgw.exe` in
`%LOCALAPPDATA%\Programs\KeyGate` and adds it to the user PATH. Both print the
`gh attestation verify` commands for the downloaded files. `--dir` /
`-InstallDir` (`KG_INSTALL_DIR`) changes the directory; `--base-url` /
`-BaseUrl` (`KG_BASE_URL`, a URL or local directory, needs a version) points
them at other packages. The Release workflow's `verify-install` job uses it to
install the dry-run packages on Linux (also in a bare `ubuntu:24.04` container
with only `curl` added) and on Windows (PowerShell 5.1 and 7), and requires a
copy with one byte of each archive flipped to be refused with no file installed.

## Optional native signing

Configure repository Actions secrets before the release run (scheduled, started by hand, or a pushed tag):

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
on step exit. Native signing is never attempted in dry runs; without these secrets releases
are published unsigned, as the weekly releases are today.
