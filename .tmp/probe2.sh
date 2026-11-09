#!/bin/bash
echo "=== Include directive in main sshd_config ==="
grep -n -i '^Include' /etc/ssh/sshd_config || echo "NO Include directive"
echo "=== sshd_config.d contents ==="
ls -la /etc/ssh/sshd_config.d/ 2>&1
echo "=== socket activation ==="
systemctl is-enabled ssh.socket 2>&1
systemctl is-active ssh.socket 2>&1
echo "=== ssh service ==="
systemctl is-enabled ssh 2>&1
systemctl is-active ssh 2>&1
echo "=== sshd -T port/password ==="
sshd -T 2>&1 | grep -Ei '^(port|passwordauthentication|pubkeyauthentication|allowgroups|usedns)' 
echo "=== ufw status ==="
ufw status 2>&1 | head -10
echo "=== fail2ban ==="
systemctl is-active fail2ban 2>&1
echo "=== auditd ==="
systemctl is-active auditd 2>&1
echo "=== apparmor ==="
systemctl is-active apparmor 2>&1
echo "=== groups ==="
getent group sshusers || echo "no sshusers group"
echo "=== sudoers for tuananh ==="
sudo -l -U tuananh 2>&1 | tail -5
