"""Generation of the intrusion prevention configuration.

This module produces the configuration for the three complementary layers of
the defence in depth model:

``fail2ban``
    Detects repeated authentication failures and bans the offending address.
``ufw``
    Restricts which ports are reachable at all.
``auditd``
    Records changes to the sensitive files at the system call level, so that
    tampering with the log files themselves is still detectable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from ..utils.errors import ConfigError
from ..utils.logging import get_logger

logger = get_logger("security.defense")


@dataclass
class Fail2BanPolicy:
    """The desired fail2ban configuration.

    Attributes:
        port: The port sshd listens on.
        bantime: How long an address stays banned.
        findtime: The window in which failures are counted.
        maxretry: The number of failures that trigger a ban.
        ignore_ip: Addresses that are never banned.
        enable_recidive: Whether to ban repeat offenders for a long time.
    """

    port: int = 22
    bantime: str = "1h"
    findtime: str = "10m"
    maxretry: int = 3
    ignore_ip: List[str] = field(
        default_factory=lambda: ["127.0.0.1/8", "::1"]
    )
    enable_recidive: bool = True
    #: The fail2ban filter mode.  "aggressive" also catches scanners that
    #: connect but never attempt to authenticate.  It is a good default for a
    #: server that is exposed to the internet, but it also bans an
    #: administrator who probes the access control with a deliberately
    #: invalid account, so the management network has to be in ``ignore_ip``.
    mode: str = "aggressive"

    def to_config(self) -> str:
        """Render the policy as a ``jail.local`` file.

        Returns:
            The full text of the configuration file.
        """
        lines = [
            "# ============================================================",
            "# BTL - fail2ban configuration",
            "# Generated file. Do not edit by hand.",
            "# ============================================================",
            "",
            "[DEFAULT]",
            f"bantime  = {self.bantime}",
            f"findtime = {self.findtime}",
            f"maxretry = {self.maxretry}",
            f"ignoreip = {' '.join(self.ignore_ip)}",
            "# Repeated offenders get an ever longer ban, capped at one week.",
            "bantime.increment = true",
            "bantime.factor    = 1",
            "bantime.maxtime   = 1w",
            "backend = systemd",
            "",
            "[sshd]",
            "enabled  = true",
            f"port     = {self.port}",
            "maxretry = " + str(self.maxretry),
            "# 'aggressive' also catches scanners that connect but never",
            "# attempt to authenticate.",
            f"mode     = {self.mode}",
            "backend  = systemd",
            "",
        ]

        if self.enable_recidive:
            lines += [
                "[recidive]",
                "enabled  = true",
                "bantime  = 1w",
                "findtime = 1d",
                "",
            ]

        return "\n".join(lines)


@dataclass
class FirewallPolicy:
    """The desired UFW firewall configuration.

    Attributes:
        ssh_port: The port that SSH is allowed on.
        allowed_tcp: Additional TCP ports to allow.
        allowed_udp: Additional UDP ports to allow.
        default_incoming: Default policy for incoming traffic.
        default_outgoing: Default policy for outgoing traffic.
        rate_limit_ssh: Whether to apply UFW's SSH rate limiting.
    """

    ssh_port: int = 22
    allowed_tcp: List[int] = field(default_factory=list)
    allowed_udp: List[int] = field(default_factory=list)
    default_incoming: str = "deny"
    default_outgoing: str = "allow"
    #: Whether the SSH rule uses ``ufw limit`` instead of ``ufw allow``.
    #:
    #: ``ufw limit`` rejects more than six new connections from the same
    #: address within thirty seconds.  That is the right rule for a server
    #: that faces the public internet, but it also blocks a legitimate
    #: administrator who opens a burst of sessions, and it silently breaks
    #: the end to end test, which opens more than twenty sessions in a row.
    #: The brute force protection is provided by fail2ban and by the
    #: ``MaxAuthTries`` and ``MaxStartups`` directives of sshd, so the plain
    #: rule is the default and the stricter one has to be asked for.
    rate_limit_ssh: bool = False

    def to_script(self) -> str:
        """Render the policy as an idempotent shell script.

        The script uses ``ufw`` rather than direct ``iptables`` calls so that
        it works with the ``ufw`` service that ships with Ubuntu.
        """
        lines = [
            "#!/usr/bin/env bash",
            "# ============================================================",
            "# BTL - firewall configuration",
            "# Generated file. Do not edit by hand.",
            "# ============================================================",
            "set -euo pipefail",
            "",
            "export DEBIAN_FRONTEND=noninteractive",
            "",
            "# The rules are reset first so that the script can be re-run",
            "# without accumulating duplicates.",
            "ufw --force reset",
            "",
            f"ufw default {self.default_incoming} incoming",
            f"ufw default {self.default_outgoing} outgoing",
            "",
        ]

        if self.rate_limit_ssh:
            lines += [
                "# Rate limiting rejects a burst of connections before the",
                "# authentication attempt is even made.",
                f"ufw limit {self.ssh_port}/tcp",
            ]
        else:
            lines += [f"ufw allow {self.ssh_port}/tcp"]

        for port in self.allowed_tcp:
            lines.append(f"ufw allow {port}/tcp")

        for port in self.allowed_udp:
            lines.append(f"ufw allow {port}/udp")

        lines += [
            "",
            "ufw --force enable",
            "ufw status verbose",
            "",
        ]
        return "\n".join(lines)


@dataclass
class AuditPolicy:
    """The desired auditd rule set.

    Attributes:
        ssh_config: Path to the sshd configuration file.
        authorized_keys_paths: Key files whose modification is security relevant.
        sudoers_paths: Paths to the sudoers configuration.
    """

    ssh_config: str = "/etc/ssh/sshd_config"
    authorized_keys_paths: List[str] = field(default_factory=list)
    sudoers_paths: List[str] = field(default_factory=lambda: ["/etc/sudoers", "/etc/sudoers.d"])

    def to_rules(self) -> str:
        """Render the policy as an audit rules file.

        Returns:
            The full text of the rules file, in the ``/etc/audit/rules.d``
            format.
        """
        lines = [
            "# ============================================================",
            "# BTL - auditd rules",
            "# Generated file. Do not edit by hand.",
            "# ============================================================",
            "",
            "## SSH configuration changes ##",
            f"-w {self.ssh_config} -p wa -k btl_sshd_config",
            "",
        ]

        lines += ["## SSH key material ##"]
        for path in self.authorized_keys_paths:
            lines.append(f"-w {path} -p wa -k btl_authorized_keys")

        lines += [
            "",
            "## Privilege escalation configuration ##",
        ]
        for path in self.sudoers_paths:
            lines.append(f"-w {path} -p wa -k btl_sudoers")

        lines += [
            "",
            "## User and group databases ##",
            "-w /etc/passwd -p wa -k btl_identity",
            "-w /etc/group -p wa -k btl_identity",
            "-w /etc/shadow -p wa -k btl_identity",
            "",
            "## SFTP jail configuration ##",
            "-w /opt/sftp-jails -p wa -k btl_sftp_jail",
            "",
            "## Commands executed as root ##",
            "-a always,exit -F arch=b64 -F euid=0 -S execve -k btl_root_commands",
            "",
            "## The sshd binary itself must not be replaced ##",
            "-w /usr/sbin/sshd -p x -k btl_sshd_exec",
            "",
        ]
        return "\n".join(lines)


def sshd_effective_config() -> "Dict[str, str]":
    """Run ``sshd -T`` and parse the effective configuration.

    This must run on the target host, because ``sshd -T`` prints the
    configuration as sshd would actually interpret it, after all drop-in
    files have been merged.

    Returns:
        A mapping of directive name to effective value.

    Raises:
        ConfigError: If ``sshd`` is not available or the output cannot be
            parsed.
    """
    import subprocess

    try:
        completed = subprocess.run(
            ["sshd", "-T"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise ConfigError(f"could not run 'sshd -T': {exc}") from exc

    if completed.returncode != 0:
        raise ConfigError(
            f"'sshd -T' failed with status {completed.returncode}: "
            f"{completed.stderr.strip()}"
        )

    effective: "Dict[str, str]" = {}
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        key = parts[0].lower()
        value = parts[1] if len(parts) > 1 else ""
        effective[key] = value
    return effective


__all__ = [
    "AuditPolicy",
    "Fail2BanPolicy",
    "FirewallPolicy",
    "sshd_effective_config",
]
