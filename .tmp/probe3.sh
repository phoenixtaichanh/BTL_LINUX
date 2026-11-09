#!/bin/bash
echo "=== sshd -T | grep auth directives ==="
sshd -T 2>&1 | grep -Ei 'challenge|kbdinteractive|passwordauth|pubkey' 
echo "=== sshd -t warnings ==="
sshd -t 2>&1 | head -10 || echo "sshd -t clean"
echo "=== full -T line count ==="
sshd -T 2>&1 | wc -l
echo "=== ufw status ==="
ufw status verbose 2>&1 | head -12
echo "=== fail2ban jails ==="
fail2ban-client status 2>&1 | head -5
echo "=== auditd ==="
systemctl is-active auditd 2>&1
auditctl -l 2>&1 | head -5
echo "=== accounts ==="
getent passwd btladmin ftpsvc
echo "=== groups ==="
id btladmin 2>&1
id ftpsvc 2>&1
echo "=== jail ==="
ls -la /opt/sftp-jails/ftpsvc/ 2>&1
echo "=== authorized_keys ==="
ls -la /home/btladmin/.ssh/ /home/ftpsvc/.ssh/ 2>&1
echo "=== banner ==="
cat /etc/ssh/banner.txt 2>&1
