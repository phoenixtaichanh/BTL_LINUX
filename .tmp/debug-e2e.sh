#!/usr/bin/env bash
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
HOST=192.168.118.128
U=tuananh
ID="C:/Users/LOQ/.ssh/id_ed25519"
OPTS=(-o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=10 -i "$ID")

echo "=== 1. plain remote command ==="
ssh "${OPTS[@]}" "$U@$HOST" "echo HELLO; id; pwd" ; echo "rc=$?"

echo "=== 2. test -f drop-in ==="
ssh "${OPTS[@]}" "$U@$HOST" "test -f /etc/ssh/sshd_config.d/00-btl-hardening.conf && echo EXISTS || echo MISSING"; echo "rc=$?"

echo "=== 3. sudo -n sshd -T | grep ==="
ssh "${OPTS[@]}" "$U@$HOST" "sudo -n sshd -T | grep -i '^passwordauthentication'"; echo "rc=$?"

echo "=== 4. id ftpsvc ==="
ssh "${OPTS[@]}" "$U@$HOST" "id ftpsvc"; echo "rc=$?"

echo "=== 5. scp upload ==="
TMP=$(mktemp -d); echo "hello" > "$TMP/s.txt"
WIN=$(cygpath -w "$TMP/s.txt"); echo "local: $WIN"
scp "${OPTS[@]}" "$WIN" "$U@$HOST:/tmp/btl-dbg.txt"; echo "rc=$?"

echo "=== 6. fail2ban status ==="
ssh "${OPTS[@]}" "$U@$HOST" "sudo -n fail2ban-client status sshd 2>&1 | head -8"; echo "rc=$?"
rm -rf "$TMP"
