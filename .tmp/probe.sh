#!/bin/bash
echo "=== identity ==="
id
echo "=== sudo ==="
echo '1234' | sudo -S -p '' id
echo "=== os ==="
. /etc/os-release; echo "$PRETTY_NAME"
echo "=== openssh-server ==="
dpkg -l openssh-server 2>&1 | tail -3
ls -l /usr/sbin/sshd 2>&1
echo "=== sshd running ==="
systemctl is-active ssh 2>&1
systemctl is-enabled ssh 2>&1
echo "=== port 22 ==="
ss -ltnp 2>/dev/null | grep -E ':22\b' || echo "nothing on 22"
echo "=== tools ==="
which ssh sftp scp curl git python3 2>&1
echo "=== network ==="
ip -4 addr show scope global | grep inet
echo "=== ip fwd ==="
cat /proc/sys/net/ipv4/ip_forward
