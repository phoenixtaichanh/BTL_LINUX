#!/bin/bash
# Unban the management network and update the fail2ban ignore list.
set -euo pipefail

MANAGEMENT_NET="${1:-192.168.118.0/24}"

echo "=== current bans ==="
fail2ban-client status sshd 2>&1 | grep -i "banned IP" || echo "none"

for ip in $(fail2ban-client get sshd banip 2>/dev/null); do
    echo "unbanning $ip"
    fail2ban-client set sshd unbanip "$ip" || true
done

# Write the jail file with the management network excluded.
JAIL_FILE=/etc/fail2ban/jail.d/btl-sshd.local
if grep -q '^ignoreip' "$JAIL_FILE"; then
    sed -i "s|^ignoreip = .*|ignoreip = 127.0.0.1/8 ::1 ${MANAGEMENT_NET}|" "$JAIL_FILE"
else
    echo "no ignoreip line in $JAIL_FILE"
fi
grep -n 'ignoreip' "$JAIL_FILE"

systemctl restart fail2ban
sleep 3
fail2ban-client status sshd 2>&1 | head -8
