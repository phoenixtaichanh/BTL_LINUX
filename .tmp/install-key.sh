#!/bin/bash
# Install a public key for the given user.
# Usage: install-key.sh <user> <key-file>
set -euo pipefail

USER_NAME="$1"
KEY_FILE="$2"

home_dir=$(getent passwd "$USER_NAME" | cut -d: -f6)
if [[ -z "$home_dir" ]]; then
    echo "no such user: $USER_NAME" >&2
    exit 1
fi

mkdir -p "$home_dir/.ssh"
chmod 700 "$home_dir/.ssh"

key_line=$(grep -v '^[[:space:]]*#' "$KEY_FILE" | tr -d '\r' | grep -v '^[[:space:]]*$' | head -1)
if [[ -z "$key_line" ]]; then
    echo "the key file is empty" >&2
    exit 1
fi

touch "$home_dir/.ssh/authorized_keys"
grep -qxF "$key_line" "$home_dir/.ssh/authorized_keys" \
    || printf '%s\n' "$key_line" >> "$home_dir/.ssh/authorized_keys"

chown -R "$USER_NAME:$USER_NAME" "$home_dir/.ssh"
chmod 600 "$home_dir/.ssh/authorized_keys"

echo "installed key for $USER_NAME ($home_dir/.ssh/authorized_keys)"
wc -l < "$home_dir/.ssh/authorized_keys"
