#!/bin/sh
# Prints the release notes for TAG built from REV: the commits on the first-parent history since
# PREVIOUS (all of history when PREVIOUS is empty), which on main are the merged PRs, then the
# verify commands. Usage: notes.sh TAG PREVIOUS [REV] [REPO]
set -eu

tag=$1
previous=$2
rev=${3:-HEAD}
repo=${4:-ds-mrtq/keygate}

range=$rev
if [ -n "$previous" ]; then range="$previous..$rev"; fi

echo "## Changes"
echo
if [ -n "$previous" ]; then
	echo "Merged since $previous:"
else
	echo "First release. Merged so far:"
fi
echo
git log --first-parent --format='- %s' "$range"
cat <<NOTES

## Install

Linux (amd64, arm64), installs \`kg\` to \`~/.local/bin\`:

\`\`\`sh
curl -fsSL https://raw.githubusercontent.com/$repo/main/install.sh | sh -s -- --version $tag
\`\`\`

Windows (amd64, arm64), installs \`kg.exe\` and \`kgw.exe\` to \`%LOCALAPPDATA%\\Programs\\KeyGate\`:

\`\`\`powershell
\$env:KG_VERSION = '$tag'; irm https://raw.githubusercontent.com/$repo/main/install.ps1 | iex
\`\`\`

Both refuse an archive whose SHA-256 does not match \`SHA256SUMS\`.

## Verify a manual download

Download the archive you need and \`SHA256SUMS\` into one directory, then:

\`\`\`sh
sha256sum -c --ignore-missing SHA256SUMS
gh attestation verify SHA256SUMS --repo $repo
gh attestation verify kg_${tag}_linux_amd64.tar.gz --repo $repo
\`\`\`

\`\`\`powershell
\$want = (Select-String -Path SHA256SUMS -Pattern 'kg_${tag}_windows_amd64.zip').Line.Split(' ')[0]
(Get-FileHash kg_${tag}_windows_amd64.zip -Algorithm SHA256).Hash.ToLower() -eq \$want
gh attestation verify kg_${tag}_windows_amd64.zip --repo $repo
\`\`\`

\`kg version\` prints \`kg $tag (commit ...)\`. Every archive and \`SHA256SUMS\` carry GitHub build provenance; the binaries have no native OS code signature. See [docs/RELEASE.md](https://github.com/$repo/blob/$tag/docs/RELEASE.md).
NOTES
