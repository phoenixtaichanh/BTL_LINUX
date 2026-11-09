#!/bin/bash
echo "=== ufw status verbose ==="
ufw status verbose 2>&1 | head -20
echo "=== fail2ban banned IPs ==="
fail2ban-client status sshd 2>&1 | head -20
echo "=== fail2ban banned list (raw) ==="
fail2ban-client get sshd banip 2>&1 | head -20
echo "=== ufw user rules ==="
ufw status numbered 2>&1 | head -20
echo "=== sshd listening ==="
ss -ltn | grep ':22'
echo "=== recent fail2ban log ==="
tail -20 /var/log/fail2ban.log 2>&1
echo "=== recent ufw log ==="
tail -20 /var/log/ufw.log 2>&1
echo "=== auth log ==="
tail -25 /var/log/auth.log 2>&1
