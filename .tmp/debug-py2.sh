#!/usr/bin/env bash
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
cd /d/BTL_Linux || exit 1

TMP=$(mktemp -d)
echo "hello from btl" > "$TMP/sample.txt"
SAMPLE=$(cygpath -w "$TMP/sample.txt")
ID=$(cygpath -w "$HOME/.ssh/id_ed25519")
KH=$(cygpath -w "$HOME/.ssh/known_hosts")
echo "sample=$SAMPLE"
echo "id=$ID"
echo "kh=$KH"

echo "=== project scp upload (full output) ==="
python -m btl.cli scp --user tuananh --identity "$ID" --known-hosts "$KH" \
    192.168.118.128 "$SAMPLE" "/tmp/btl-dbg-own.txt"
echo "rc=$?"

echo "=== verify on server ==="
ssh -o StrictHostKeyChecking=yes -o BatchMode=yes -i "$ID" tuananh@192.168.118.128 \
    "ls -la /tmp/btl-dbg-own.txt && cat /tmp/btl-dbg-own.txt"
echo "rc=$?"
rm -rf "$TMP"
