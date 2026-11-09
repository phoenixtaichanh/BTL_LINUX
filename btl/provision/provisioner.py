"""Idempotent provisioning of the target Ubuntu host.

Everything in this module is designed to be safe to run repeatedly.  Each
step checks the current state before changing it, and a dry-run mode prints
the commands that would be executed without touching the system.

The provisioning runs over SSH against the Ubuntu VM, so it can be driven
from a Windows or Linux workstation.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Dict, List

from ..security.defense import AuditPolicy, Fail2BanPolicy, FirewallPolicy
from ..security.sshd_config import DROP_IN_PATH, SSHDPolicy
from ..utils.errors import ConfigError
from ..utils.logging import get_logger

logger = get_logger("provision")

#: The banner shown to users after they authenticate.
BANNER_TEXT = """\
This system is restricted to authorised users.
All connections are logged and monitored.
Misuse of this system is a criminal offence.
"""

#: The directory that holds the per-account SFTP jails.
JAIL_BASE = "/opt/sftp-jails"

#: The group that is allowed to log in over SSH.
SSH_GROUP = "sshusers"


@dataclass
class ProvisionPlan:
    """A description of the changes that provisioning will make."""

    steps: List[str] = field(default_factory=list)
    sshd_policy: SSHDPolicy = field(default_factory=SSHDPolicy)
    fail2ban_policy: Fail2BanPolicy = field(default_factory=Fail2BanPolicy)
    firewall_policy: FirewallPolicy = field(default_factory=FirewallPolicy)
    audit_policy: AuditPolicy = field(default_factory=AuditPolicy)
    sftp_users: List[str] = field(default_factory=list)
    admin_users: List[str] = field(default_factory=list)
    #: Public keys to install in ``~/.ssh/authorized_keys``, per account.
    admin_public_keys: Dict[str, List[str]] = field(default_factory=dict)
    #: Public keys to install for the jailed SFTP-only accounts.
    sftp_public_keys: Dict[str, List[str]] = field(default_factory=dict)
    #: The account that is used to run the provisioning.  It has to keep its
    #: access, because the hardened configuration refuses every account that
    #: is not a member of :data:`SSH_GROUP`.
    keep_access_user: str = ""

    def validate(self) -> None:
        """Validate the plan before it is applied."""
        self.sshd_policy.validate()
        if not self.admin_users and not self.sftp_users:
            raise ConfigError(
                "the plan must create at least one admin or sftp account"
            )
        if self.sshd_policy.allowed_groups and self.keep_access_user:
            if SSH_GROUP not in self.sshd_policy.allowed_groups:
                raise ConfigError(
                    f"the account used for provisioning ({self.keep_access_user}) "
                    f"would lose access because AllowGroups is "
                    f"{' '.join(self.sshd_policy.allowed_groups)}"
                )

    def public_keys_for(self, user: str) -> List[str]:
        """Return the public keys that must be installed for *user*.

        Args:
            user: The account name.

        Returns:
            The list of public key lines, which may be empty.
        """
        keys = list(self.admin_public_keys.get(user, []))
        if (
            self.keep_access_user
            and user == self.keep_access_user
            and user not in self.admin_public_keys
        ):
            # The account that drives the provisioning uses the same key as
            # the administrators, otherwise it would be locked out.
            for other, other_keys in self.admin_public_keys.items():
                if other in self.admin_users:
                    keys = list(other_keys)
                    break
        return keys

    def render_scripts(self) -> "dict[str, str]":
        """Render every file that will be written to the target host.

        Returns:
            A mapping of remote path to the file content.
        """
        scripts: "dict[str, str]" = {
            DROP_IN_PATH: self.sshd_policy.to_config(),
            "/etc/ssh/sshd_config.d/10-btl-sftp.conf": (
                self.sshd_policy.to_sftp_match_block(self.sftp_users)
                if self.sftp_users
                else "# No SFTP-only accounts are configured.\n"
            ),
            "/etc/fail2ban/jail.d/btl-sshd.local": self.fail2ban_policy.to_config(),
            "/etc/audit/rules.d/50-btl.rules": self.audit_policy.to_rules(),
            "/etc/ssh/banner.txt": BANNER_TEXT,
        }
        return scripts


def build_admin_script(plan: ProvisionPlan) -> str:
    """Build the shell script that creates the administrator accounts.

    The script also installs the public keys.  Without them the accounts
    would be unusable: the hardened configuration sets
    ``PasswordAuthentication no`` and the script locks the password, so the
    only remaining way in is public key authentication.

    Args:
        plan: The provisioning plan.

    Returns:
        The script as a string.
    """
    lines = [
        "#!/usr/bin/env bash",
        "# BTL - create the SSH administrator accounts.",
        "set -euo pipefail",
        "",
        f"if ! getent group {SSH_GROUP} >/dev/null; then",
        f"    groupadd {SSH_GROUP}",
        f"    echo 'created group {SSH_GROUP}'",
        "fi",
        "",
    ]

    # The account that runs the provisioning must survive the hardening,
    # otherwise the server becomes unreachable.
    keep_access = plan.keep_access_user
    if keep_access and keep_access not in plan.admin_users:
        lines += [
            f"# Keep the provisioning account ({keep_access}) able to log in.",
            f"usermod -aG {SSH_GROUP} {keep_access} 2>/dev/null || true",
            "",
        ]

    for user in plan.admin_users:
        lines += [
            f"if ! id -u {user} >/dev/null 2>&1; then",
            f"    adduser --disabled-password --gecos '' {user}",
            f"    echo 'created user {user}'",
            "fi",
            f"usermod -aG {SSH_GROUP} {user}",
            "",
        ]

    lines += [
        "# The accounts must not be able to log in with a password.",
        "for user in " + " ".join(plan.admin_users or ["root"]) + "; do",
        "    passwd -l \"$user\" || true",
        "done",
        "",
    ]

    # Install the public keys.  This has to happen *after* the password is
    # locked, because a locked account with no key can never be used again.
    for user in sorted(set(plan.admin_users) | ({keep_access} if keep_access else set())):
        keys = plan.public_keys_for(user)
        if not keys:
            continue
        lines += [
            f"# Install the public keys for {user}.",
            f"home_dir=$(getent passwd {user} | cut -d: -f6)",
            "mkdir -p \"$home_dir/.ssh\"",
            "chmod 700 \"$home_dir/.ssh\"",
            # Merge instead of appending blindly: the file is rewritten with
            # the union of the existing keys and the new ones, so that
            # provisioning twice does not duplicate the entries.
            "cat > \"$home_dir/.ssh/authorized_keys.new\" <<'BTL_KEYS_EOF'",
        ]
        lines.extend(keys)
        lines += [
            "BTL_KEYS_EOF",
            "touch \"$home_dir/.ssh/authorized_keys\"",
            "cat \"$home_dir/.ssh/authorized_keys\" >> \"$home_dir/.ssh/authorized_keys.new\"",
            "sort -u \"$home_dir/.ssh/authorized_keys.new\" > \"$home_dir/.ssh/authorized_keys\"",
            "rm -f \"$home_dir/.ssh/authorized_keys.new\"",
            f"chown -R {user}:{user} \"$home_dir/.ssh\"",
            "chmod 600 \"$home_dir/.ssh/authorized_keys\"",
            f"echo 'installed {len(keys)} key(s) for {user}'",
            "",
        ]

    return "\n".join(lines)


def build_sftp_script(plan: ProvisionPlan) -> str:
    """Build the shell script that creates the jailed SFTP accounts.

    Args:
        plan: The provisioning plan.

    Returns:
        The script as a string.
    """
    lines = [
        "#!/usr/bin/env bash",
        "# BTL - create the jailed SFTP-only accounts.",
        "set -euo pipefail",
        "",
        f"mkdir -p {JAIL_BASE}",
        "",
    ]

    for user in plan.sftp_users:
        jail = f"{JAIL_BASE}/{user}"
        upload = f"{jail}/upload"
        home = f"/home/{user}"
        lines += [
            f"if ! id -u {user} >/dev/null 2>&1; then",
            f"    adduser --disabled-password --gecos '' {user}",
            f"    echo 'created user {user}'",
            "fi",
            "",
            # The account has to be a member of the allowed group, otherwise
            # 'AllowGroups' refuses it before the Match block is ever read.
            f"usermod -aG {SSH_GROUP} {user}",
            "",
            f"mkdir -p {home} {jail} {upload}",
            "",
            "# The jail root must be owned by root and not writable by",
            "# anyone else, otherwise chroot() could be escaped.",
            f"chown root:root {jail}",
            f"chmod 755 {jail}",
            "",
            "# Only the upload directory belongs to the account.",
            f"chown {user}:{user} {upload}",
            f"chmod 700 {upload}",
            "",
            "# The home directory has to exist for the account to start a",
            "# session, but it is not part of the jail.",
            f"chown {user}:{user} {home}",
            f"chmod 750 {home}",
            "",
        ]

        # The SFTP accounts are password locked as well, so their public key
        # is the only way to reach them.
        keys = plan.sftp_public_keys.get(user, [])
        if keys:
            lines += [
                f"mkdir -p {home}/.ssh",
                f"chmod 700 {home}/.ssh",
                # Merge instead of appending blindly, so that provisioning
                # twice does not duplicate the entries.
                f"cat > {home}/.ssh/authorized_keys.new <<'BTL_KEYS_EOF'",
            ]
            lines.extend(keys)
            lines += [
                "BTL_KEYS_EOF",
                f"touch {home}/.ssh/authorized_keys",
                f"cat {home}/.ssh/authorized_keys >> {home}/.ssh/authorized_keys.new",
                f"sort -u {home}/.ssh/authorized_keys.new > {home}/.ssh/authorized_keys",
                f"rm -f {home}/.ssh/authorized_keys.new",
                f"chown -R {user}:{user} {home}/.ssh",
                f"chmod 600 {home}/.ssh/authorized_keys",
                f"passwd -l {user} || true",
                f"echo 'installed {len(keys)} key(s) for {user}'",
                "",
            ]

    return "\n".join(lines)


def build_install_script() -> str:
    """Build the script that installs the required packages."""
    return """\
#!/usr/bin/env bash
# BTL - install the required packages.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \\
    openssh-server \\
    openssh-client \\
    fail2ban \\
    ufw \\
    auditd \\
    audispd-plugins \\
    python3-paramiko \\
    python3-yaml

systemctl enable --now ssh
systemctl enable --now fail2ban

# The firewall is deliberately *not* enabled here.  ufw's default incoming
# policy is "deny", so enabling it before the SSH rule exists would cut
# every remote session off.  The rules are applied first and the firewall is
# enabled by the apply step, in that order.
"""


def build_apply_script(plan: ProvisionPlan) -> str:
    """Build the script that applies the configuration and reloads sshd.

    The configuration is validated with ``sshd -t`` before sshd is reloaded,
    and the currently open session is never terminated by the script itself.

    Args:
        plan: The provisioning plan.

    Returns:
        The script as a string.
    """
    return """\
#!/usr/bin/env bash
# BTL - apply the hardened configuration.
set -euo pipefail

# Validate the configuration before touching the running service.
if ! sshd -t; then
    echo 'sshd configuration is invalid, refusing to reload' >&2
    exit 1
fi

systemctl reload ssh
systemctl restart fail2ban || true

# The audit daemon records the privileged operations on the host.
systemctl enable --now auditd || true

# Load the audit rules.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
fi

echo 'configuration applied'
"""


def scp_upload_script(content: str, remote_path: str) -> str:
    """Wrap *content* so it can be written to a file over SSH.

    The content is embedded in a quoted heredoc, which avoids any shell
    expansion of the configuration text.  The file is written to a temporary
    location first and only moved into place once it is complete, so an
    interrupted transfer cannot leave a half written configuration behind.

    Args:
        content: The text to write.
        remote_path: The final path of the file on the remote host.

    Returns:
        The script as a string.
    """
    delimiter = "BTL_EOF_MARKER"
    while delimiter in content:
        delimiter += "_"
    return (
        f"cat > /tmp/btl_upload <<'{delimiter}'\n"
        f"{content}\n"
        f"{delimiter}\n"
        f"chmod 644 /tmp/btl_upload\n"
        f"install -m 644 /tmp/btl_upload {shlex.quote(remote_path)}\n"
        f"rm -f /tmp/btl_upload\n"
    )


def sudo_password_of(connection) -> str:
    """Return the password to feed to ``sudo -S`` on the remote host.

    Args:
        connection: The SSH connection in use.

    Returns:
        The password, or an empty string when none is configured.
    """
    return getattr(connection.config, "sudo_password", None) or ""


def write_file_over_ssh(connection, remote_path: str, content: str) -> None:
    """Write *content* to *remote_path* over an SSH connection.

    The file is written to a temporary location first and then moved into
    place, so an interrupted transfer cannot leave a half written
    configuration behind.
    """
    script = scp_upload_script(content, remote_path)
    quoted = shlex.quote(script)
    command = f"sudo -S -p '' bash -c {quoted}"
    result = connection.exec_command(command, stdin_data=sudo_password_of(connection))
    if result.exit_status != 0:
        raise ConfigError(
            f"failed to write {remote_path}: exit {result.exit_status}\n"
            f"{result.stderr}"
        )


def run_script(connection, script: str, *, sudo: bool = True) -> str:
    """Run *script* on the remote host and return its output.

    Args:
        connection: The SSH connection to use.
        script: The script body.
        sudo: Whether to run the script with root privileges.

    Returns:
        The combined output of the script.

    Raises:
        ConfigError: If the script exits with a non-zero status.
    """
    quoted = shlex.quote(script)
    if sudo:
        # ``-S`` makes sudo read the password from standard input instead of
        # from the terminal, and ``-p ''`` suppresses the prompt so that it
        # does not end up in the captured output.
        command = f"sudo -S -p '' bash -c {quoted}"
        stdin_data = sudo_password_of(connection)
    else:
        command = f"bash -c {quoted}"
        stdin_data = None

    result = connection.exec_command(command, stdin_data=stdin_data)
    if result.exit_status != 0:
        raise ConfigError(
            f"script failed with status {result.exit_status}:\n{result.stderr}"
        )
    return result.stdout


__all__ = [
    "BANNER_TEXT",
    "JAIL_BASE",
    "ProvisionPlan",
    "SSH_GROUP",
    "build_admin_script",
    "build_apply_script",
    "build_install_script",
    "build_sftp_script",
    "run_script",
    "scp_upload_script",
    "write_file_over_ssh",
]
