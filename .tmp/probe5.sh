#!/bin/bash
echo "=== ufw status numbered ==="
ufw status numbered 2>&1 | head -15
echo "=== fail2ban sshd ==="
fail2ban-client status sshd 2>&1 | head -12
echo "=== fail2ban ignoreip in jail ==="
grep -n 'ignoreip' /etc/fail2ban/jail.d/btl-sshd.local 2>&1
grep -n 'ignoreip' /etc/fail2ban/jail.d/defaults-debian.conf 2>&1 | head -5
echo "=== fail2ban log tail ==="
tail -12 /var/log/fail2ban.log 2>&1
echo "=== ufw log ==="
journalctl -u ufw --no-pager -n 15 2>&1 | tail -15
grep -i "UFW BLOCK" /var/log/syslog 2>/dev/null | tail -8
echo "=== kernel ==="
dmesg 2>/dev/null | tail -5
