#!/usr/bin/env bash
cd /d/BTL_Linux || exit 1
export MSYS_NO_PATHCONV=1
echo "=== identity ==="
IDENTITY="$HOME/.ssh/id_ed25519"
ls -la "$IDENTITY"
echo "=== connectivity ==="
timeout 30 ssh -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=10 \
    -i "$IDENTITY" tuananh@192.168.118.128 'echo SSH_OK; sudo -n true && echo SUDO_OK'
echo "exit=$?"
