#!/bin/sh
# KeyGate installer for Linux (amd64, arm64).
#
#   curl -fsSL https://raw.githubusercontent.com/ds-mrtq/keygate/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/ds-mrtq/keygate/main/install.sh | sh -s -- --version v0.1.0
#
# Downloads the release archive and SHA256SUMS, refuses to install unless the archive's SHA-256
# matches its SHA256SUMS entry, and installs kg to ~/.local/bin. Needs only curl, tar, sha256sum;
# no sudo.
#
# Options (or environment variables):
#   --version <tag>    KG_VERSION      release tag to install (default: the latest release)
#   --dir <path>       KG_INSTALL_DIR  install directory (default: ~/.local/bin)
#   --base-url <url>   KG_BASE_URL     where the archives and SHA256SUMS are (a URL or a local
#                                      directory; default: the GitHub release of --version);
#                                      needs --version
set -eu

repo=ds-mrtq/keygate
version=${KG_VERSION:-}
install_dir=${KG_INSTALL_DIR:-}
base_url=${KG_BASE_URL:-}

die() {
	echo "kg install: $*" >&2
	exit 1
}

need_arg() {
	if [ "$#" -lt 2 ] || [ -z "$2" ]; then
		die "$1 needs a value"
	fi
}

while [ "$#" -gt 0 ]; do
	case "$1" in
	--version) need_arg "$@"; version=$2; shift 2 ;;
	--dir) need_arg "$@"; install_dir=$2; shift 2 ;;
	--base-url) need_arg "$@"; base_url=$2; shift 2 ;;
	-h | --help)
		sed -n '2,17s/^# \{0,1\}//p' "$0" 2>/dev/null || true
		exit 0
		;;
	*) die "unknown option: $1 (see --help)" ;;
	esac
done

for tool in curl tar sha256sum uname mktemp; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool is required but was not found"
done

[ "$(uname -s)" = Linux ] || die "this script installs on Linux only; on Windows use install.ps1"
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unsupported CPU architecture: $(uname -m) (release archives exist for amd64 and arm64)" ;;
esac

if [ -z "$version" ]; then
	[ -z "$base_url" ] || die "--base-url needs --version"
	latest="https://github.com/$repo/releases/latest"
	resolved=$(curl -fsSL --proto '=https' --proto-redir '=https' -o /dev/null -w '%{url_effective}' "$latest") ||
		die "could not reach $latest; pass --version <tag>"
	case "$resolved" in
	*/releases/tag/*) version=${resolved##*/releases/tag/} ;;
	*) die "no published release found at $latest; pass --version <tag>" ;;
	esac
fi
case "$version" in
'' | *[!A-Za-z0-9._-]*) die "invalid version: $version" ;;
esac

[ -n "$base_url" ] || base_url="https://github.com/$repo/releases/download/$version"
base_url=${base_url%/}
# The checksum comes from the same place as the archive, so the transport must be authenticated.
case "$base_url" in
https://* | file://* | /*) ;;
*://*) die "--base-url must be https://, file:// or a local directory: $base_url" ;;
esac
[ -n "$install_dir" ] || {
	[ -n "${HOME:-}" ] || die "HOME is not set; pass --dir"
	install_dir="$HOME/.local/bin"
}

archive="kg_${version}_linux_${arch}.tar.gz"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' HUP INT TERM

fetch() {
	if [ -d "$base_url" ]; then
		cp "$base_url/$1" "$tmp/$1" || die "could not copy $base_url/$1"
	else
		curl -fsSL --proto '=https,file' --proto-redir '=https' --retry 3 -o "$tmp/$1" "$base_url/$1" || die "could not download $base_url/$1"
	fi
}

echo "Downloading KeyGate $version (linux/$arch) from $base_url"
fetch SHA256SUMS
fetch "$archive"

want=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/SHA256SUMS")
[ -n "$want" ] || die "SHA256SUMS has no entry for $archive; nothing installed"
got=$(sha256sum "$tmp/$archive" | awk '{ print $1 }')
if [ "$got" != "$want" ]; then
	die "checksum mismatch for $archive: SHA256SUMS says $want, the download is $got; nothing installed"
fi
echo "Checksum OK: $archive $got"

mkdir "$tmp/unpacked"
tar -xzf "$tmp/$archive" -C "$tmp/unpacked" kg || die "could not unpack $archive"
mkdir -p "$install_dir" || die "could not create $install_dir"
install_dir=$(CDPATH='' cd -- "$install_dir" && pwd -P) || die "could not enter $install_dir"
cp "$tmp/unpacked/kg" "$install_dir/.kg.new" || die "could not write to $install_dir"
chmod 755 "$install_dir/.kg.new"
mv -f "$install_dir/.kg.new" "$install_dir/kg" || die "could not install $install_dir/kg"

echo "Installed $install_dir/kg"
"$install_dir/kg" version || die "the installed kg did not run"

case ":${PATH:-}:" in
*":$install_dir:"*) ;;
*)
	echo
	echo "$install_dir is not on your PATH. Add it, for example:"
	echo "  echo 'export PATH=\"$install_dir:\$PATH\"' >> ~/.profile && . ~/.profile"
	;;
esac

cat <<MSG

Optional: check the build provenance attestation with the GitHub CLI (gh):
  gh release download $version --repo $repo -p $archive -p SHA256SUMS
  gh attestation verify $archive --repo $repo
  gh attestation verify SHA256SUMS --repo $repo
MSG
