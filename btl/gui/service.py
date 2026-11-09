"""Service layer shared by the graphical interface and the command line.

The web interface and the ``btl`` command line tool must not drift apart:
both have to apply the same host key policy, the same authentication rules
and the same path confinement.  Both therefore drive the *same* service
layer, which in turn uses the core :mod:`btl` modules.

This module contains no HTTP concepts at all.  It is a plain Python API that
raises :class:`~btl.utils.errors.BTLException` subclasses, so it can be used
from a script, from the CLI or from a web request handler.
"""

from __future__ import annotations

import base64
import os
import shlex
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..provision.provisioner import (
    ProvisionPlan,
    build_admin_script,
    build_apply_script,
    build_install_script,
    build_sftp_script,
    run_script,
    write_file_over_ssh,
)
from ..scp.client import SCPClient
from ..security.defense import (
    AuditPolicy,
    Fail2BanPolicy,
    FirewallPolicy,
    sshd_effective_config,
)
from ..security.sshd_config import SSHDPolicy, audit_config, summarize
from ..sftp.client import SFTPClient
from ..ssh.connection import (
    AuthConfig,
    ConnectionConfig,
    SSHConnection,
    load_public_key,
)
from ..ssh.hostkeys import HostKeyPolicy, KnownHostsStore
from ..utils.errors import BTLException, ConfigError
from ..utils.logging import get_logger

logger = get_logger("gui.service")

#: The largest file that may be transferred through the browser.
MAX_INLINE_BYTES = 32 * 1024 * 1024


@dataclass
class ConnectionSettings:
    """Everything the interface needs to open an SSH connection.

    Attributes:
        host: Hostname or IP address of the server.
        port: TCP port of the SSH service.
        username: Account to log in as.
        auth_method: ``"key"``, ``"password"`` or ``"agent"``.
        key_path: Path to a private key file, used by the ``"key"`` method.
        passphrase: Passphrase protecting the private key.
        password: Password, used by the ``"password"`` method.
        known_hosts: Path to the trusted host key store.
        auto_accept_host_key: Whether an unknown host key is accepted.
        timeout: Connection timeout in seconds.
        sudo_password: Password used to satisfy ``sudo -S`` on the server.
    """

    host: str = ""
    port: int = 22
    username: str = "root"
    auth_method: str = "key"
    key_path: str = ""
    passphrase: str = ""
    password: str = ""
    known_hosts: str = ""
    auto_accept_host_key: bool = False
    timeout: float = 15.0
    sudo_password: str = ""

    def validate(self) -> None:
        """Check that the settings can be used to build a connection.

        Raises:
            ConfigError: If a required value is missing.
        """
        if not self.host.strip():
            raise ConfigError("the server address must not be empty")
        if not self.username.strip():
            raise ConfigError("the user name must not be empty")
        if not 1 <= int(self.port) <= 65535:
            raise ConfigError(f"invalid port: {self.port}")
        if self.auth_method not in ("key", "password", "agent"):
            raise ConfigError(f"unsupported authentication method: {self.auth_method!r}")
        if self.auth_method == "key" and not self.key_path.strip():
            raise ConfigError("a private key file is required for key authentication")

    def to_connection_config(self) -> ConnectionConfig:
        """Build a :class:`ConnectionConfig` from these settings."""
        self.validate()

        if self.auth_method == "key":
            auth = AuthConfig(
                method="key",
                key_path=self.key_path.strip(),
                passphrase=self.passphrase or None,
            )
        elif self.auth_method == "password":
            auth = AuthConfig(method="password", password=self.password or None)
        else:
            auth = AuthConfig(method="agent")

        known_hosts = self.known_hosts.strip()
        store = (
            KnownHostsStore(known_hosts)
            if known_hosts
            else KnownHostsStore()
        )

        sudo_password = self.sudo_password or self.password or None

        return ConnectionConfig(
            host=self.host.strip(),
            port=int(self.port),
            username=self.username.strip(),
            auth=auth,
            host_key_policy=HostKeyPolicy(
                store, auto_accept=bool(self.auto_accept_host_key)
            ),
            timeout=float(self.timeout),
            sudo_password=sudo_password,
        )


@dataclass
class ProvisionSettings:
    """The parameters of a provisioning run.

    Attributes:
        group: The group that is allowed to log in over SSH.
        admin_users: Accounts that get a login shell.
        sftp_users: Accounts that are jailed into SFTP only.
        admin_public_key: Public key installed for the administrator accounts.
        sftp_public_key: Public key installed for the SFTP-only accounts.
        fail2ban_ignore: Addresses that fail2ban must never ban.
        ufw_limit_ssh: Whether ``ufw limit`` is used instead of ``ufw allow``.
        no_firewall: Whether the firewall is left untouched.
    """

    group: str = "sshusers"
    admin_users: str = ""
    sftp_users: str = ""
    admin_public_key: str = ""
    sftp_public_key: str = ""
    fail2ban_ignore: str = ""
    ufw_limit_ssh: bool = False
    no_firewall: bool = False

    def build_plan(self, keep_access_user: str = "") -> ProvisionPlan:
        """Build the :class:`ProvisionPlan` described by these settings."""
        plan = ProvisionPlan()
        plan.sshd_policy = SSHDPolicy(
            port=22, allowed_groups=[self.group] if self.group else ["sshusers"]
        )
        plan.fail2ban_policy = Fail2BanPolicy(port=22)

        ignored = [ip.strip() for ip in self.fail2ban_ignore.split(",") if ip.strip()]
        if ignored:
            plan.fail2ban_policy.ignore_ip = (
                list(plan.fail2ban_policy.ignore_ip) + ignored
            )

        plan.firewall_policy = FirewallPolicy(
            ssh_port=22, rate_limit_ssh=bool(self.ufw_limit_ssh)
        )
        plan.admin_users = [u.strip() for u in self.admin_users.split(",") if u.strip()]
        plan.sftp_users = [u.strip() for u in self.sftp_users.split(",") if u.strip()]
        plan.keep_access_user = keep_access_user

        admin_key = _read_public_key(self.admin_public_key)
        if admin_key:
            for user in plan.admin_users:
                plan.admin_public_keys[user] = [admin_key]

        sftp_key = _read_public_key(self.sftp_public_key)
        if sftp_key:
            for user in plan.sftp_users:
                plan.sftp_public_keys[user] = [sftp_key]

        plan.validate()
        return plan


def _read_public_key(path: str) -> str:
    """Read the first usable key line from *path*.

    Args:
        path: Path to a ``.pub`` file, or an empty string.

    Returns:
        The key line, or an empty string when no path was given.

    Raises:
        ConfigError: If the file cannot be read or holds no key.
    """
    if not path or not path.strip():
        return ""

    path = path.strip()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
    except OSError as exc:
        raise ConfigError(f"could not read the public key {path}: {exc}") from exc

    raise ConfigError(f"the public key file {path} does not contain a key")


class Session:
    """Holds the single SSH connection that the interface works with.

    A Paramiko transport is not thread safe, so every operation is guarded
    by a lock.  The web server handles each request in its own thread, and
    two requests that try to use the connection at the same time would
    otherwise interleave their reads and writes.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._connection: Optional[SSHConnection] = None
        self._settings: Optional[ConnectionSettings] = None

    # -- state -----------------------------------------------------------

    @property
    def connected(self) -> bool:
        """Whether a connection is currently open."""
        return self._connection is not None

    @property
    def settings(self) -> Optional[ConnectionSettings]:
        """The settings of the current connection."""
        return self._settings

    def state(self) -> "Dict[str, Any]":
        """Return a summary of the session for the interface."""
        with self._lock:
            settings = self._settings
            return {
                "connected": self._connection is not None,
                "host": settings.host if settings else "",
                "port": settings.port if settings else 22,
                "username": settings.username if settings else "",
                "auth_method": settings.auth_method if settings else "key",
            }

    def _require_connection(self) -> SSHConnection:
        """Return the open connection.

        Raises:
            BTLException: If no connection is open.
        """
        if self._connection is None:
            raise BTLException("not connected; open a connection first")
        return self._connection

    # -- connection lifecycle -------------------------------------------

    def connect(self, settings: ConnectionSettings) -> "Dict[str, Any]":
        """Open a connection, replacing any connection that is already open.

        Args:
            settings: The connection settings.

        Returns:
            A summary of the new session.
        """
        with self._lock:
            self.disconnect()
            config = settings.to_connection_config()
            connection = SSHConnection(config)
            try:
                connection.connect()
            except BTLException:
                connection.close()
                raise
            self._connection = connection
            self._settings = settings
            logger.info("session opened for %s@%s", config.username, config.host)
            return self.state()

    def disconnect(self) -> "Dict[str, Any]":
        """Close the current connection, if there is one."""
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
            self._settings = None
            return self.state()

    # -- server information ---------------------------------------------

    def server_info(self) -> "Dict[str, Any]":
        """Return the SSH capabilities of the connected server."""
        with self._lock:
            return self._require_connection().get_server_info()

    # -- command execution ----------------------------------------------

    def run_command(self, command: str) -> "Dict[str, Any]":
        """Run *command* on the server and return its output."""
        if not command or not command.strip():
            raise ConfigError("the command must not be empty")

        with self._lock:
            connection = self._require_connection()
            result = connection.exec_command(command)
            return {
                "command": result.command,
                "exit_status": result.exit_status,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

    # -- audit -----------------------------------------------------------

    def audit(self, scope: str = "remote") -> "Dict[str, Any]":
        """Audit the effective sshd configuration.

        Args:
            scope: ``"remote"`` audits the connected server, ``"local"``
                audits the machine the interface runs on.

        Returns:
            The findings and their summary.
        """
        with self._lock:
            if scope == "local":
                effective = sshd_effective_config()
            else:
                connection = self._require_connection()
                result = connection.exec_command(
                    "sudo -S -p '' sshd -T",
                    stdin_data=connection.config.sudo_password or "",
                )
                if result.exit_status != 0:
                    raise BTLException(
                        f"'sshd -T' failed with status {result.exit_status}: "
                        f"{result.stderr.strip()}"
                    )
                effective = {}
                for line in result.stdout.splitlines():
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        effective[parts[0].lower()] = parts[1].strip()

        findings = audit_config(effective)
        counts = summarize(findings)
        return {
            "scope": scope,
            "findings": findings,
            "summary": counts,
            "compliant": counts.get("weak", 0) == 0 and counts.get("missing", 0) == 0,
        }

    # -- SFTP ------------------------------------------------------------

    def sftp_list(self, path: str = ".", root: str = "") -> "Dict[str, Any]":
        """List a remote directory over SFTP.

        Args:
            path: The remote directory to list.
            root: Optional virtual root that confines every path.

        Returns:
            The directory entries.
        """
        with self._lock:
            connection = self._require_connection()
            with connection.sftp() as raw:
                client = SFTPClient(raw, root=root or None)
                entries = client.listdir(path or ".")
                return {
                    "path": path or ".",
                    "root": root or "",
                    "entries": [
                        {
                            "name": item.name,
                            "path": item.path,
                            "size": item.size,
                            "size_human": item.size_human,
                            "permissions": item.permissions,
                            "is_dir": item.is_dir,
                            "is_link": item.is_link,
                        }
                        for item in entries
                    ],
                }

    def sftp_read(self, path: str, root: str = "", max_bytes: int = 512 * 1024) -> "Dict[str, Any]":
        """Read a remote text file over SFTP."""
        with self._lock:
            connection = self._require_connection()
            with connection.sftp() as raw:
                client = SFTPClient(raw, root=root or None)
                target = client.resolve(path, must_exist=True)
                if client.stat(path).size > max_bytes:
                    raise ConfigError(
                        f"the file is larger than the {max_bytes} byte preview limit"
                    )
                with raw.open(target, "rb") as handle:
                    data = handle.read(max_bytes)
        return {
            "path": path,
            "size": len(data),
            "text": data.decode("utf-8", errors="replace"),
        }

    def sftp_upload(
        self,
        local_path: str,
        remote_path: str,
        root: str = "",
        resume: bool = False,
    ) -> "Dict[str, Any]":
        """Upload a local file to the server over SFTP."""
        with self._lock:
            connection = self._require_connection()
            with connection.sftp() as raw:
                client = SFTPClient(raw, root=root or None)
                size = client.put(local_path, remote_path, resume=resume)
        return {"remote_path": remote_path, "bytes": size}

    def sftp_download(
        self, remote_path: str, local_path: str, root: str = "", resume: bool = False
    ) -> "Dict[str, Any]":
        """Download a file from the server over SFTP."""
        with self._lock:
            connection = self._require_connection()
            with connection.sftp() as raw:
                client = SFTPClient(raw, root=root or None)
                size = client.get(remote_path, local_path, resume=resume)
        return {"local_path": local_path, "bytes": size}

    def sftp_upload_inline(
        self, remote_path: str, content: bytes, root: str = ""
    ) -> "Dict[str, Any]":
        """Upload the bytes that the browser sent to the server.

        Args:
            remote_path: The destination on the remote host.
            content: The file content.
            root: Optional virtual root.

        Returns:
            A summary of the upload.
        """
        if len(content) > MAX_INLINE_BYTES:
            raise ConfigError(
                f"the file is larger than the {MAX_INLINE_BYTES} byte limit"
            )

        with self._lock:
            connection = self._require_connection()
            with connection.sftp() as raw:
                client = SFTPClient(raw, root=root or None)
                target = client.resolve(remote_path)
                parent = os.path.dirname(target)
                if parent:
                    try:
                        raw.stat(parent)
                    except IOError:
                        client.makedirs(parent, exist_ok=True)
                with raw.open(target, "wb") as handle:
                    handle.write(content)
        return {"remote_path": remote_path, "bytes": len(content)}

    # -- SCP -------------------------------------------------------------

    def scp_upload(
        self,
        local_path: str,
        remote_path: str,
        recursive: bool = False,
        preserve_times: bool = False,
    ) -> "Dict[str, Any]":
        """Upload a local file or directory to the server over SCP."""
        with self._lock:
            connection = self._require_connection()
            client = SCPClient(connection)
            result = client.put(
                local_path,
                remote_path,
                recursive=recursive,
                preserve_times=preserve_times,
            )
            return {
                "remote_path": remote_path,
                "files": result.transferred,
                "count": result.count,
            }

    def scp_download(
        self,
        remote_path: str,
        local_path: str,
        recursive: bool = False,
        preserve_times: bool = False,
    ) -> "Dict[str, Any]":
        """Download a file or directory from the server over SCP."""
        with self._lock:
            connection = self._require_connection()
            client = SCPClient(connection)
            result = client.get(
                remote_path,
                local_path,
                recursive=recursive,
                preserve_times=preserve_times,
            )
            return {
                "local_path": local_path,
                "files": result.transferred,
                "count": result.count,
            }

    # -- host keys -------------------------------------------------------

    def hostkey_list(self, known_hosts: str = "") -> "Dict[str, Any]":
        """List the trusted host keys."""
        store = KnownHostsStore(known_hosts) if known_hosts else KnownHostsStore()
        entries = store.load()
        return {
            "path": store.path,
            "entries": [
                {
                    "hostname": entry.hostname,
                    "key_type": entry.key_type,
                    "fingerprint": entry.fingerprint(),
                    "comment": entry.comment,
                }
                for entry in entries
            ],
        }

    def hostkey_add(
        self,
        hostname: str,
        key_file: str,
        port: int = 22,
        known_hosts: str = "",
    ) -> "Dict[str, Any]":
        """Trust a new host key.

        Args:
            hostname: The host the key belongs to.
            key_file: Path to the public key file.
            port: The port the host listens on.
            known_hosts: Path to the trusted host key store.

        Returns:
            The entry that was added.
        """
        if not hostname.strip():
            raise ConfigError("the host name must not be empty")
        if not key_file.strip():
            raise ConfigError("a public key file is required")

        store = KnownHostsStore(known_hosts) if known_hosts else KnownHostsStore()
        try:
            key = load_public_key(key_file.strip())
        except BTLException:
            raise
        entry = store.add(hostname.strip(), key.get_name(), key.get_base64(), port=port)
        return {
            "hostname": entry.hostname,
            "key_type": entry.key_type,
            "fingerprint": entry.fingerprint(),
            "path": store.path,
        }

    def hostkey_remove(
        self, hostname: str, port: int = 22, known_hosts: str = ""
    ) -> "Dict[str, Any]":
        """Remove every key trusted for *hostname*."""
        store = KnownHostsStore(known_hosts) if known_hosts else KnownHostsStore()
        removed = store.remove(hostname.strip(), port=port)
        return {"hostname": hostname, "removed": removed, "path": store.path}

    # -- configuration rendering ----------------------------------------

    def render(
        self,
        what: str,
        port: int = 22,
        groups: str = "sshusers",
        users: str = "",
        sftp_users: str = "",
    ) -> "Dict[str, Any]":
        """Render a configuration file without touching a server."""
        policy = SSHDPolicy(
            port=port,
            allowed_groups=[g.strip() for g in groups.split(",") if g.strip()]
            or ["sshusers"],
            allowed_users=[u.strip() for u in users.split(",") if u.strip()],
        )
        jail_users = [u.strip() for u in sftp_users.split(",") if u.strip()]

        if what == "sshd":
            content = policy.to_config()
        elif what == "sshd-sftp":
            content = policy.to_sftp_match_block(jail_users)
        elif what == "fail2ban":
            content = Fail2BanPolicy(port=port).to_config()
        elif what == "firewall":
            content = FirewallPolicy(ssh_port=port).to_script()
        elif what == "audit":
            content = AuditPolicy().to_rules()
        else:
            raise ConfigError(f"unknown configuration file: {what!r}")

        return {"what": what, "content": content}

    # -- provisioning ----------------------------------------------------

    def provision_preview(self, settings: ProvisionSettings) -> "Dict[str, Any]":
        """Render everything provisioning would do, without applying it."""
        keep = self._settings.username if self._settings else ""
        plan = settings.build_plan(keep_access_user=keep)

        files: "Dict[str, str]" = {}
        for path, content in plan.render_scripts().items():
            files[path] = content

        return {
            "files": files,
            "admin_script": build_admin_script(plan),
            "sftp_script": build_sftp_script(plan),
            "install_script": build_install_script(),
            "apply_script": build_apply_script(plan),
        }

    def provision_apply(self, settings: ProvisionSettings) -> "Dict[str, Any]":
        """Provision the connected server.

        The steps run in the same order as the command line tool, and the
        firewall is applied last so that the session cannot be cut off.
        """
        with self._lock:
            connection = self._require_connection()
            keep = self._settings.username if self._settings else ""
            plan = settings.build_plan(keep_access_user=keep)

            steps: "List[Dict[str, Any]]" = []

            def _run(label: str, script: str) -> None:
                output = run_script(connection, script)
                steps.append({"label": label, "output": output})

            _run("Installing packages", build_install_script())
            _run("Creating administrator accounts", build_admin_script(plan))
            _run("Creating SFTP accounts", build_sftp_script(plan))

            for path, content in plan.render_scripts().items():
                write_file_over_ssh(connection, path, content)
                steps.append({"label": f"Wrote {path}", "output": ""})

            _run("Applying the configuration", build_apply_script(plan))

            if not settings.no_firewall:
                _run("Applying the firewall", plan.firewall_policy.to_script())

            return {"steps": steps}


class Service:
    """The application service, holding the session and the settings.

    Args:
        known_hosts: Default path of the trusted host key store.
        downloads_dir: Directory that receives the files that the browser
            downloads.
    """

    def __init__(
        self,
        known_hosts: str = "",
        downloads_dir: str = "",
    ) -> None:
        self.session = Session()
        self.known_hosts = known_hosts
        self.downloads_dir = downloads_dir or os.path.join(
            os.path.expanduser("~"), "btl-downloads"
        )

    def default_known_hosts(self) -> str:
        """Return the trusted host key store that is used by default."""
        if self.known_hosts:
            return self.known_hosts
        return os.path.join(os.path.expanduser("~"), ".ssh", "known_hosts")

    def defaults(self) -> "Dict[str, Any]":
        """Return the values that the interface pre-fills the form with.

        The paths are the usual OpenSSH locations, so a user who already
        has a key does not have to type the path in every time.
        """
        home = os.path.expanduser("~")
        ssh_dir = os.path.join(home, ".ssh")
        return {
            "known_hosts": self.default_known_hosts(),
            "key_path": os.path.join(ssh_dir, "id_ed25519"),
            "default_port": 22,
            "default_timeout": 15.0,
        }


__all__ = [
    "ConnectionSettings",
    "MAX_INLINE_BYTES",
    "ProvisionSettings",
    "Service",
    "Session",
]
