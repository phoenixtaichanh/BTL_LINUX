#!/bin/bash
# Grant the sshusers group password-less sudo for the automation account.
# This is scoped to a single user and a single group.
set -euo pipefail

TARGET_USER="${1:-tuananh}"
GROUP="${2:-sshusers}"
SUDOERS_FILE="/etc/sudoers.d/90-btl-${TARGET_USER}"

if [[ ! -e "$SUDOERS_FILE" ]]; then
    printf '%s ALL=(ALL:ALL) NOPASSWD: ALL\n' "$TARGET_USER" > "$SUDOERS_FILE"
    chmod 440 "$SUDOERS_FILE"
    echo "created $SUDOERS_FILE"
else
    echo "$SUDOERS_FILE already exists"
fi

# Validate before it is used, otherwise the file could lock everybody out.
visudo -cf "$SUDOERS_FILE"

# The account also needs a valid shell for sudo to work.
usermod -s /bin/bash "$TARGET_USER"
echo "shell: $(getent passwd "$TARGET_USER" | cut -d: -f7)"
