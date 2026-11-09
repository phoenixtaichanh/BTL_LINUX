"""Generation of the hardened SSH server configuration.

The centrepiece of the assignment is the ``sshd`` configuration that this
module produces.  It is generated from a single declarative specification so
that:

* the same policy can be rendered as a ``sshd_config`` drop-in,
* the effective configuration can be audited against a reference baseline,
* changes are reviewable as code rather than as ad hoc edits on a server.

The drop-in is written to ``/etc/ssh/sshd_config.d/00-btl-hardening.conf`` so
that it takes precedence over the stock configuration.  OpenSSH honours the
*first* value it reads for a directive, and the ``sshd_config.d`` directory is
read before the main file, so a low numbered file wins.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from ..utils.errors import ConfigError
from ..utils.logging import get_logger

logger = get_logger("security.sshd")

#: Where the generated drop-in is written on the target host.
DROP_IN_PATH = "/etc/ssh/sshd_config.d/00-btl-hardening.conf"

#: The reference baseline used by the auditor.  A configuration is considered
#: compliant when every one of these directives is present with the expected
#: effective value.
#:
#: Only directives that exist in every supported OpenSSH release are listed
#: here.  In particular ``PerSourcePenalties`` (OpenSSH 9.8+) is deliberately
#: excluded: Ubuntu 24.04 ships OpenSSH 9.6, and an unknown directive makes
#: ``sshd -t`` fail, which would leave the server unable to start.
#: ``MaxAuthTries`` plus fail2ban already cover the brute force case.
BASELINE: "Dict[str, str]" = {
    "permitrootlogin": "no",
    "passwordauthentication": "no",
    "kbdinteractiveauthentication": "no",
    "pubkeyauthentication": "yes",
    "challengeresponseauthentication": "no",
    "allowgroups": "sshusers",
    "allowtcpforwarding": "no",
    "maxauthtries": "3",
    "logingracetime": "30",
    "maxsessions": "10",
    "maxstartups": "10:30:60",
    "x11forwarding": "no",
    "allowagentforwarding": "no",
    "permitemptypasswords": "no",
    "permittunnel": "no",
    "gatewayports": "no",
    "clientaliveinterval": "300",
    "clientalivecountmax": "2",
}

#: Directives that are aliases of another directive.
#:
#: ``sshd_config(5)`` states that ``ChallengeResponseAuthentication`` is a
#: deprecated alias of ``KbdInteractiveAuthentication``.  Newer OpenSSH
#: releases therefore print only the canonical name in the output of
#: ``sshd -T``, even though the deprecated spelling is still accepted in a
#: configuration file.  Without this mapping the auditor would report a
#: missing directive on a server that is in fact fully compliant.
ALIASES: "Dict[str, str]" = {
    "challengeresponseauthentication": "kbdinteractiveauthentication",
}


@dataclass
class SSHDPolicy:
    """The declarative description of the desired sshd configuration.

    Attributes:
        port: The port sshd listens on.
        allowed_groups: Groups allowed to log in via ``AllowGroups``.
        allowed_users: Individual users allowed to log in via ``AllowUsers``.
        listen_address: Address to bind to.
        banner: Path to a login banner.
        ciphers: Allowed cipher list.
        macs: Allowed MAC list.
        kex_algorithms: Allowed key exchange algorithms.
        use_pam: Whether to use PAM for authentication.
        log_level: sshd log verbosity.
    """

    port: int = 22
    allowed_groups: List[str] = field(default_factory=lambda: ["sshusers"])
    allowed_users: List[str] = field(default_factory=list)
    listen_address: str = "0.0.0.0"
    banner: str = "/etc/ssh/banner.txt"
    ciphers: str = (
        "chacha20-poly1305@openssh.com,"
        "aes256-gcm@openssh.com,"
        "aes128-gcm@openssh.com,"
        "aes256-ctr,aes192-ctr,aes128-ctr"
    )
    macs: str = (
        "hmac-sha2-512-etm@openssh.com,"
        "hmac-sha2-256-etm@openssh.com,"
        "hmac-sha2-512,hmac-sha2-256"
    )
    kex_algorithms: str = (
        "curve25519-sha256,curve25519-sha256@libssh.org,"
        "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
        "diffie-hellman-group-exchange-sha256"
    )
    use_pam: bool = True
    log_level: str = "VERBOSE"

    def validate(self) -> None:
        """Check the policy for obvious mistakes."""
        if not 1 <= self.port <= 65535:
            raise ConfigError(f"invalid SSH port: {self.port}")
        if not self.allowed_groups and not self.allowed_users:
            raise ConfigError(
                "at least one of allowed_groups or allowed_users must be set"
            )

    def to_config(self) -> str:
        """Render the policy as an ``sshd_config`` drop-in.

        Returns:
            The full text of the configuration file.
        """
        self.validate()

        lines: List[str] = [
            "# ============================================================",
            "# BTL - Secured Network Service Configuration",
            "# Generated file. Do not edit by hand.",
            f"# Target: Ubuntu / OpenSSH server, port {self.port}",
            "# ============================================================",
            "",
            "### Listener ###",
            f"Port {self.port}",
            f"ListenAddress {self.listen_address}",
            "",
            "### Who may log in ###",
            "# Only members of the listed groups may establish a session.",
            "PermitRootLogin no",
            "PermitEmptyPasswords no",
            "UsePAM yes" if self.use_pam else "UsePAM no",
        ]

        if self.allowed_users:
            lines.append(f"AllowUsers {' '.join(self.allowed_users)}")
        if self.allowed_groups:
            lines.append(f"AllowGroups {' '.join(self.allowed_groups)}")

        lines += [
            "",
            "### Authentication ###",
            "# Public key only. Password and keyboard-interactive are refused so",
            "# that a stolen passphrase cannot be used from an unexpected host.",
            "PubkeyAuthentication yes",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "ChallengeResponseAuthentication no",
            "GSSAPIAuthentication no",
            "HostbasedAuthentication no",
            "PermitUserEnvironment no",
            "",
            "### Brute force resistance ###",
            "MaxAuthTries 3",
            "LoginGraceTime 30",
            "MaxSessions 10",
            "MaxStartups 10:30:60",
            "",
            "### Forwarding and tunnelling are disabled ###",
            "# None of these are needed for SCP/SFTP file transfer and each one",
            "# is a way for a user to reach hosts they should not reach.",
            "X11Forwarding no",
            "AllowAgentForwarding no",
            "AllowTcpForwarding no",
            "PermitTunnel no",
            "GatewayPorts no",
            "StreamLocalBindMask 0077",
            "",
            "### Session hygiene ###",
            "ClientAliveInterval 300",
            "ClientAliveCountMax 2",
            "TCPKeepAlive yes",
            "PrintMotd no",
            "PrintLastLog yes",
            "AcceptEnv LANG LC_*",
            "SetEnv PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "Banner /etc/ssh/banner.txt",
            "",
            "### Crypto policy ###",
            f"Ciphers {self.ciphers}",
            f"MACs {self.macs}",
            f"KexAlgorithms {self.kex_algorithms}",
            "HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256",
            "",
            "### Logging ###",
            "SyslogFacility AUTH",
            "LogLevel " + self.log_level,
            "",
        ]

        config = "\n".join(lines)
        # The configuration is validated before it leaves the process.  An
        # unknown directive would make "sshd -t" fail on the server and
        # could leave the machine unable to start.
        from .validate import validate_config

        validate_config(config)
        return config

    def to_sftp_match_block(self, jail_users: List[str]) -> str:
        """Render a ``Match`` block that confines SFTP-only accounts.

        Accounts listed here are jailed into their own directory and can only
        use SFTP.  This is the server side counterpart to the client side
        virtual root.

        Args:
            jail_users: The accounts to confine.

        Returns:
            The text of the ``Match`` block.
        """
        lines = [
            "### SFTP only accounts, jailed into their own directory ###",
            "# These accounts cannot open a shell; they can only transfer files",
            "# and they cannot see anything outside of their jail.",
        ]
        for user in jail_users:
            lines += [
                "",
                f"Match User {user}",
                f"    ChrootDirectory /opt/sftp-jails/{user}",
                "    ForceCommand internal-sftp -d /upload",
                "    AllowTcpForwarding no",
                "    X11Forwarding no",
                "    PermitTTY no",
                "    GatewayPorts no",
            ]
        lines += ["", "Match all", ""]
        return "\n".join(lines)


def audit_config(effective: "Dict[str, str]") -> "List[Dict[str, str]]":
    """Compare an effective sshd configuration against the baseline.

    Args:
        effective: The mapping produced by ``sshd -T``.

    Returns:
        A list of findings.  Each finding has ``directive``, ``expected``,
        ``actual`` and ``status`` keys, where status is ``"ok"``,
        ``"missing"``, ``"weak"`` or ``"unexpected"``.
    """
    findings: List[Dict[str, str]] = []

    for directive, expected in BASELINE.items():
        actual = effective.get(directive)

        if actual is None:
            # The directive may be a deprecated alias whose canonical name
            # is the one that 'sshd -T' prints.
            alias = ALIASES.get(directive)
            if alias is not None:
                actual = effective.get(alias)

        if actual is None:
            findings.append(
                {
                    "directive": directive,
                    "expected": expected,
                    "actual": "<not set>",
                    "status": "missing",
                }
            )
        elif actual.lower() != expected.lower():
            findings.append(
                {
                    "directive": directive,
                    "expected": expected,
                    "actual": actual,
                    "status": "weak",
                }
            )
        else:
            findings.append(
                {
                    "directive": directive,
                    "expected": expected,
                    "actual": actual,
                    "status": "ok",
                }
            )

    return findings


def summarize(findings: "List[Dict[str, str]]") -> "Dict[str, int]":
    """Count the findings by status."""
    counts: "Dict[str, int]" = {}
    for finding in findings:
        counts[finding["status"]] = counts.get(finding["status"], 0) + 1
    return counts


__all__ = [
    "ALIASES",
    "BASELINE",
    "DROP_IN_PATH",
    "SSHDPolicy",
    "audit_config",
    "summarize",
]
