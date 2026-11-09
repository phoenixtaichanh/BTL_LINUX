#!/usr/bin/env bash
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
cd /d/BTL_Linux || exit 1

TMP=$(mktemp -d)
echo "hello from btl" > "$TMP/sample.txt"
WIN=$(cygpath -w "$TMP/sample.txt")
echo "local: $WIN"

echo "=== 1. project scp upload ==="
python -m btl.cli scp --user tuananh --identity "C:/Users/LOQ/.ssh/id_ed25519" \
    --known-hosts "C:/Users/LOQ/.ssh/known_hosts" \
    192.168.118.128 "$WIN" "/tmp/btl-dbg-own.txt" 2>&1 | tail -20
echo "rc=$?"

echo "=== 2. project scp download ==="
python -m btl.cli scp --download --user tuananh --identity "C:/Users/LOQ/.ssh/id_ed25519" \
    --known-hosts "C:/Users/LOQ/.ssh/known_hosts" \
    192.168.118.128 "$(cygpath -w "$TMP/dl.txt")" "tuananh@192.168.118.128:/tmp/btl-dbg-own.txt" 2>&1 | tail -20
echo "rc=$?"

echo "=== 3. sftp put ==="
sftp -b - -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=10 \
    -i "C:/Users/LOQ/.ssh/id_ed25519" tuananh@192.168.118.128 <<EOF
put $WIN /tmp/btl-dbg-sftp.txt
EOF
echo "rc=$?"

echo "=== 4. sftp get ==="
sftp -b - -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=10 \
    -i "C:/Users/LOQ/.ssh/id_ed25519" tuananh@192.168.118.128 <<EOF
get /tmp/btl-dbg-sftp.txt $(cygpath -w "$TMP/dl2.txt")
EOF
echo "rc=$?"

rm -rf "$TMP"
