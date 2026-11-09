#!/bin/bash
# Install and enable openssh-server on the Ubuntu guest.
set -x
export DEBIAN_FRONTEND=noninteractive

echo '1234' | sudo -S -p '' true
RC=$?
echo "sudo check rc=$RC"

sudo -S -p '' apt-get update -o Acquire::Retries=3 2>&1 | tail -20
echo "=== update rc=$? ==="

sudo -S -p '' apt-get install -y openssh-server openssh-client 2>&1 | tail -30
echo "=== install rc=$? ==="

sudo -S -p '' systemctl enable --now ssh 2>&1
echo "=== enable rc=$? ==="

systemctl is-active ssh
systemctl is-enabled ssh
ls -l /usr/sbin/sshd
ss -ltn | grep ':22' || echo "NOT LISTENING on 22"
