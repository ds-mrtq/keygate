#!/bin/sh
# Prints the next weekly release for the commit REV (default HEAD) of the git repository in the
# current directory, as shell assignments (IGNORE, if given, is a tag left out of the search, e.g.
# the tag being released, to find the one before it):
#   last=<highest vX.Y.Z tag, or empty>
#   version=<last with the patch bumped, or v0.1.0 when there is no tag>
#   commits=<commits in REV not in last>
#   skip=<true when last already contains REV, so there is nothing new to release>
# Only plain vX.Y.Z tags count; they are ordered as versions (v0.1.10 > v0.1.9).
set -eu

rev=${1:-HEAD}
ignore=${2:-}
git rev-parse --verify --quiet "$rev^{commit}" >/dev/null || {
	echo "next-version: unknown revision $rev" >&2
	exit 1
}

last=$(git tag --list 'v*' | grep -E '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' | grep -vxF -- "${ignore:-//}" | sort -t. -k1.2,1n -k2,2n -k3,3n | tail -n 1 || true)

if [ -z "$last" ]; then
	version=v0.1.0
	commits=$(git rev-list --count "$rev")
else
	major=${last#v}
	patch=${major##*.}
	minor=${major%.*}
	major=${minor%%.*}
	minor=${minor#*.}
	version="v$major.$minor.$((patch + 1))"
	commits=$(git rev-list --count "$last..$rev")
fi

skip=false
if [ "$commits" -eq 0 ]; then skip=true; fi

echo "last=$last"
echo "version=$version"
echo "commits=$commits"
echo "skip=$skip"
