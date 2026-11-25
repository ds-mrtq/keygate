#!/bin/sh
# Checks next-version.sh and notes.sh against scratch git repositories. Run from anywhere.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
fail=0
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

repo() {
	rm -rf "$scratch/r"
	git init -q -b main "$scratch/r"
	git -C "$scratch/r" config user.email test@example.invalid
	git -C "$scratch/r" config user.name test
	git -C "$scratch/r" config tag.gpgSign false
	git -C "$scratch/r" config commit.gpgSign false
}
commit() { git -C "$scratch/r" commit -q --allow-empty -m "$1"; }
tag() { git -C "$scratch/r" tag "$1"; }
check() { # name want-output [ignore-tag]
	got=$(cd "$scratch/r" && sh "$here/next-version.sh" HEAD "${3:-}" | tr '\n' ' ')
	if [ "$got" = "$2" ]; then
		echo "ok   $1: $got"
	else
		echo "FAIL $1: got '$got', want '$2'"
		fail=1
	fi
}

repo
commit 'first (#1)'
commit 'second (#2)'
check 'no tag yet: first release' 'last= version=v0.1.0 commits=2 skip=false '
tag v0.1.0
check 'nothing since the last tag: skip' 'last=v0.1.0 version=v0.1.1 commits=0 skip=true '
commit 'third (#3)'
check 'one commit since v0.1.0' 'last=v0.1.0 version=v0.1.1 commits=1 skip=false '
for p in 1 2 3 4 5 6 7 8 9; do tag "v0.1.$p"; done
commit 'fourth (#4)'
tag v0.1.10
commit 'fifth (#5)'
check 'versions sort numerically (v0.1.10 > v0.1.9)' 'last=v0.1.10 version=v0.1.11 commits=1 skip=false '
tag v0.2.0-rc1
tag v0.2
tag vnext
tag 0.3.0
check 'only plain vX.Y.Z tags count' 'last=v0.1.10 version=v0.1.11 commits=1 skip=false '
tag v0.2.0
check 'a manual minor tag on HEAD: skip' 'last=v0.2.0 version=v0.2.1 commits=0 skip=true '
commit 'sixth (#6)'
check 'patch bumps after a manual minor tag' 'last=v0.2.0 version=v0.2.1 commits=1 skip=false '
tag v0.3.0
check 'a pushed tag finds the tag before it' 'last=v0.2.0 version=v0.2.1 commits=1 skip=false ' v0.3.0
git -C "$scratch/r" tag -d v0.3.0 >/dev/null

notes=$(cd "$scratch/r" && sh "$here/notes.sh" v0.2.1 v0.2.0)
for want in 'Merged since v0.2.0:' '- sixth (#6)' 'sh -s -- --version v0.2.1' 'sha256sum -c --ignore-missing SHA256SUMS' \
	'gh attestation verify kg_v0.2.1_linux_amd64.tar.gz --repo ds-mrtq/keygate' "Get-FileHash kg_v0.2.1_windows_amd64.zip"; do
	if printf '%s\n' "$notes" | grep -qF -- "$want"; then echo "ok   notes contain: $want"; else echo "FAIL notes lack: $want"; fail=1; fi
done
if printf '%s\n' "$notes" | grep -qF 'fifth (#5)'; then echo 'FAIL notes list a commit before v0.2.0'; fail=1; else echo 'ok   notes list only commits since v0.2.0'; fi
first=$(cd "$scratch/r" && sh "$here/notes.sh" v0.1.0 '')
if printf '%s\n' "$first" | grep -qF -- '- first (#1)'; then echo 'ok   first-release notes list all of history'; else echo 'FAIL first-release notes'; fail=1; fi

exit "$fail"
