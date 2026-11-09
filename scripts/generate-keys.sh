#!/usr/bin/env bash
# ============================================================
# BTL - Generate the SSH key pairs used by the project.
#
#   ./scripts/generate-keys.sh [key-directory]
#
# Creates:
#   <dir>/id_ed25519            key for the administrator account
#   <dir>/id_ed25519_sftp       key for the SFTP-only account
#   <dir>/id_ed25519.pub        the matching public keys
# ============================================================
set -euo pipefail

KEY_DIR="${1:-$HOME/.ssh}"
KEY_TYPE="ed25519"
KEY_BITS=100   # KDF rounds for the passphrase

mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"

generate() {
    local name="$1"
    local path="$KEY_DIR/$name"

    if [[ -f "$path" ]]; then
        echo "==> $path already exists, skipping"
        return
    fi

    echo "==> generating $path"
    ssh-keygen -t "$KEY_TYPE" -a "$KEY_BITS" -f "$path" -C "btl-$(whoami)@$(hostname)"
    chmod 600 "$path"
    chmod 644 "$path.pub"
}

echo "==> key directory: $KEY_DIR"
generate id_ed25519
generate id_ed25519_sftp

echo
echo "==> public key fingerprints"
for pub in "$KEY_DIR"/id_ed25519.pub "$KEY_DIR"/id_ed25519_sftp.pub; do
    [[ -f "$pub" ]] && ssh-keygen -lf "$pub"
done

cat <<'EOF'

Next steps:
  1. Copy the administrator public key to the server:
       ssh-copy-id -i ~/.ssh/id_ed25519.pub <user>@<server>

  2. Trust the server host key (do this BEFORE hardening):
       btl hostkey add <server> --key-file /etc/ssh/ssh_host_ed25519_key.pub

     Or, if you are on the server console, read the fingerprint:
       ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub

  3. Provision the server:
       btl provision --host <server> --user <user> \
                     --identity ~/.ssh/id_ed25519 \
                     --admin-users <admin> --sftp-users <sftp-user>
EOF
