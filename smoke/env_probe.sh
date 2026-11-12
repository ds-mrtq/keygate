#!/usr/bin/env bash
# KeyGate smoke: pinned bash script receives the secret via env; output must be redacted.
set -eu
v="${DNS_API_TOKEN:-}"
echo "len=${#v}"
echo "raw=$v"
printf 'b64=%s\n' "$(printf '%s' "$v" | base64 -w0)"
