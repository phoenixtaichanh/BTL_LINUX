#!/usr/bin/env bash
# ============================================================
# BTL - firewall configuration
# Generated file. Do not edit by hand.
# ============================================================
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# The rules are reset first so that the script can be re-run
# without accumulating duplicates.
ufw --force reset

ufw default deny incoming
ufw default allow outgoing

# Rate limiting rejects a burst of connections before the
# authentication attempt is even made.
ufw limit 22/tcp

ufw --force enable
ufw status verbose

