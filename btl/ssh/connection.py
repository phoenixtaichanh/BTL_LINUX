"""SSH connection management with strong authentication defaults.

This module wraps :mod:`paramiko` and adds the policy that the project cares
about:

* Host keys are verified strictly (see :mod:`btl.ssh.hostkeys`).
* Password authentication is opt-in and never the default.
* Public key authentication supports both the default OpenSSH agent lookup
  and an explicit key file, with passphrase support through Paramiko's agent
  interface.
* Sessions are executed through a single :class:`SSHConnection` object so
  that credentials never leak into the rest of the code base.
"""

from __future__ import annotations

import base64
import os
import stat
from dataclasses import dataclass, field
from typing import List, Optional

import paramiko

from ..utils.errors import AuthError, ConfigError, HostKeyError
from ..utils.logging import get_logger
from .hostkeys import HostKeyPolicy, HostKeyStatus, KnownHostsStore

logger = get_logger("ssh.connection")

#: The key types the project is willing to handle.
KEY_TYPES = (
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)


class _StrictMissingHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Bridge Paramiko's missing-host-key hook to the project's own policy.

    Paramiko consults its missing-host-key policy *during* the handshake, before
    the transport is available to the caller.  Installing
    :class:`paramiko.RejectPolicy` there therefore rejected every host key
    before the project's :class:`~btl.ssh.hostkeys.HostKeyPolicy` ever ran, which
    made ``--auto-accept-host-key`` and ``btl hostkey add`` unusable.

    This adapter simply defers to that policy, so the decision is made exactly
    once and in a single place.
    """

    def __init__(self, policy: HostKeyPolicy, port: int) -> None:
        self.policy = policy
        self.port = port

    def missing_host_key(self, client, hostname, key) -> None:
        """Verify *key* with the project policy.

        Args:
            client: The Paramiko client that received the key.
            hostname: The host that presented the key.
            key: The presented host key.

        Raises:
            HostKeyError: If the key is unacceptable.
        """
        self.policy.check(hostname, self.port, key)


@dataclass
class AuthConfig:
    """How to authenticate against the server.

    Attributes:
        method: ``"key"``, ``"agent"`` or ``"password"``.
        key_path: Path to a private key file, used by the ``"key"`` method.
        password: Password, used by the ``"password"`` method.
        passphrase: Passphrase protecting the private key.
        agent_socket: Path of the SSH agent socket.
    """

    method: str = "agent"
    key_path: Optional[str] = None
    password: Optional[str] = None
    passphrase: Optional[str] = None
    agent_socket: Optional[str] = None

    def validate(self) -> None:
        """Check that the configuration is internally consistent."""
        if self.method == "key":
            if not self.key_path:
                raise ConfigError("key authentication requires a key_path")
            if not os.path.exists(self.key_path):
                raise ConfigError(f"private key not found: {self.key_path}")
            # The permission bits are only meaningful on a POSIX file system.
            # On Windows the mode is synthesised from the read-only attribute,
            # so every file looks group/world accessible and the warning would
            # be noise rather than a finding.
            if os.name != "nt":
                mode = os.stat(self.key_path).st_mode
                if mode & (stat.S_IRWXG | stat.S_IRWXO):
                    logger.warning(
                        "private key %s is group/world accessible; tighten it "
                        "with chmod 600",
                        self.key_path,
                    )
        elif self.method == "password":
            if not self.password:
                raise ConfigError("password authentication requires a password")
        elif self.method == "agent":
            pass
        else:
            raise ConfigError(f"unsupported authentication method: {self.method!r}")


@dataclass
class ConnectionConfig:
    """Everything needed to open an SSH connection.

    Attributes:
        host: Hostname or IP address.
        port: TCP port of the SSH service.
        username: Account to log in as.
        auth: Authentication configuration.
        host_key_policy: Policy used to verify the server host key.
        timeout: Connection and authentication timeout in seconds.
        allow_agent_forwarding: Whether to request agent forwarding.
        keepalive_interval: Seconds between keepalive packets, ``0`` disables.
        sudo_password: Password used to satisfy ``sudo -S`` on the remote host.
    """

    host: str
    port: int = 22
    username: str = "root"
    auth: AuthConfig = field(default_factory=AuthConfig)
    host_key_policy: Optional[HostKeyPolicy] = None
    timeout: float = 15.0
    allow_agent_forwarding: bool = False
    keepalive_interval: int = 30
    sudo_password: Optional[str] = None

    def validate(self) -> None:
        """Validate the connection configuration."""
        if not self.host:
            raise ConfigError("host must not be empty")
        if not 1 <= self.port <= 65535:
            raise ConfigError(f"invalid port: {self.port}")
        if not self.username:
            raise ConfigError("username must not be empty")
        self.auth.validate()


class SSHConnection:
    """A connected SSH session.

    Use :meth:`connect` to open the connection and :meth:`close` (or use the
    context manager protocol) to release it.
    """

    def __init__(self, config: ConnectionConfig) -> None:
        self.config = config
        self._client: Optional[paramiko.SSHClient] = None
        self._transport: Optional[paramiko.Transport] = None

    # -- lifecycle -------------------------------------------------------

    def connect(self) -> "SSHConnection":
        """Open the connection.

        Returns:
            ``self``, so the call can be chained.

        Raises:
            AuthError: If authentication fails.
            HostKeyError: If the host key is not acceptable.
            ConfigError: If the configuration is invalid.
        """
        self.config.validate()

        client = paramiko.SSHClient()
        # The host key decision is delegated to the project's own strict
        # policy.  Paramiko asks its missing-host-key policy during the
        # handshake, so the adapter has to be installed *before* connecting;
        # otherwise a plain RejectPolicy would refuse every host before the
        # project policy could accept or reject it.
        policy = self.config.host_key_policy or HostKeyPolicy(
            KnownHostsStore(), auto_accept=False
        )
        client.set_missing_host_key_policy(
            _StrictMissingHostKeyPolicy(policy, self.config.port)
        )

        try:
            client.connect(
                hostname=self.config.host,
                port=self.config.port,
                username=self.config.username,
                timeout=self.config.timeout,
                banner_timeout=self.config.timeout,
                auth_timeout=self.config.timeout,
                allow_agent=self.config.auth.method == "agent",
                look_for_keys=False,
                key_filename=(
                    self.config.auth.key_path
                    if self.config.auth.method == "key"
                    else None
                ),
                password=(
                    self.config.auth.password
                    if self.config.auth.method == "password"
                    else None
                ),
                passphrase=(
                    self.config.auth.passphrase
                    if self.config.auth.method == "key"
                    else None
                ),
            )
        except HostKeyError:
            # The project's own policy already produced a precise message;
            # it must not be rewritten as a generic connection failure.
            client.close()
            raise
        except paramiko.BadHostKeyException as exc:
            client.close()
            raise HostKeyError(f"host key mismatch for {self.config.host}: {exc}") from exc
        except paramiko.AuthenticationException as exc:
            client.close()
            raise AuthError(f"authentication failed for {self.config.username}@{self.config.host}: {exc}") from exc
        except paramiko.PasswordRequiredException as exc:
            client.close()
            raise AuthError(
                f"the key for {self.config.username}@{self.config.host} requires a passphrase"
            ) from exc
        except (paramiko.SSHException, OSError) as exc:
            client.close()
            raise AuthError(f"could not connect to {self.config.host}: {exc}") from exc

        transport = client.get_transport()
        if transport is None:
            raise AuthError("connection established but no transport available")

        # Verify the host key explicitly.  Paramiko's own check uses the
        # client's known hosts, which we deliberately bypass above, so the
        # strict policy is applied here against our own store.
        self._verify_host_key(transport, policy)

        if self.config.keepalive_interval:
            transport.set_keepalive(self.config.keepalive_interval)

        self._client = client
        self._transport = transport
        logger.info(
            "connected to %s@%s:%s", self.config.username, self.config.host, self.config.port
        )
        return self

    def _verify_host_key(self, transport, policy: HostKeyPolicy) -> None:
        """Check the server host key against the configured policy."""
        key = transport.get_remote_server_key()
        if key is None:
            raise HostKeyError("the server did not present a host key")
        policy.check(self.config.host, self.config.port, key)

    def close(self) -> None:
        """Close the connection, ignoring errors."""
        if self._transport is not None:
            try:
                self._transport.close()
            except Exception:  # noqa: BLE001 - best effort cleanup
                pass
            self._transport = None
        if self._client is not None:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001 - best effort cleanup
                pass
            self._client = None

    def __enter__(self) -> "SSHConnection":
        if self._client is None:
            self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # -- operations ------------------------------------------------------

    @property
    def transport(self) -> paramiko.Transport:
        """The underlying Paramiko transport."""
        if self._transport is None:
            raise AuthError("not connected")
        return self._transport

    def open_session(self) -> paramiko.Channel:
        """Open a new session channel for command execution."""
        channel = self.transport.open_session()
        if self.config.allow_agent_forwarding:
            channel.request_agent_forwarding()
        return channel

    def exec_command(
        self,
        command: str,
        timeout: Optional[float] = None,
        stdin_data: Optional[str] = None,
    ) -> "CommandResult":
        """Run *command* on the remote host and collect its output.

        Args:
            command: The command line to run.
            timeout: Optional timeout in seconds.
            stdin_data: Optional data to write to the standard input of the
                remote command.  This is how the password for ``sudo -S`` is
                supplied; without it ``sudo`` would wait for the password on
                the terminal and the session would hang until it timed out.

        Returns:
            A :class:`CommandResult` with the exit status and output.

        Raises:
            AuthError: If the channel could not be opened.
        """
        channel = self.open_session()
        try:
            channel.settimeout(timeout or self.config.timeout)
            channel.exec_command(command)

            stdout = channel.makefile("rb")
            stderr = channel.makefile_stderr("rb")

            if stdin_data is not None:
                channel.sendall(stdin_data.encode("utf-8"))
                # Signal the end of input so that commands such as
                # ``cat`` terminate instead of waiting for more data.
                try:
                    channel.shutdown_write()
                except OSError:
                    pass

            out = stdout.read()
            err = stderr.read()
            status = channel.recv_exit_status()
            return CommandResult(
                command=command,
                exit_status=status,
                stdout=out.decode("utf-8", errors="replace"),
                stderr=err.decode("utf-8", errors="replace"),
            )
        finally:
            channel.close()

    def sftp(self) -> paramiko.SFTPClient:
        """Open an SFTP client on this connection."""
        if self._client is None:
            raise AuthError("not connected")
        return self._client.open_sftp()

    def get_server_info(self) -> dict:
        """Return a summary of the server's SSH capabilities.

        Paramiko 5 dropped the ``cipher()``, ``mac()`` and ``compression``
        accessors in favour of plain attributes, and the older releases do
        not have those attributes at all.  Both spellings are handled here so
        that the tool works with every supported Paramiko version.
        """
        transport = self.transport
        return {
            "remote_version": transport.remote_version,
            "local_version": transport.local_version,
            "cipher": _negotiated_value(transport, "cipher"),
            "mac": _negotiated_value(transport, "mac"),
            "compression": _negotiated_value(transport, "compression"),
            "kex": _negotiated_kex(transport),
            "host_key_types": list(
                getattr(transport, "server_key_types", None)
                or _server_key_types(transport)
            ),
            "allowed_auth_methods": _allowed_auth_methods(transport),
        }


@dataclass
class CommandResult:
    """The outcome of a remote command."""

    command: str
    exit_status: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        """``True`` when the command exited with status zero."""
        return self.exit_status == 0

    def check(self) -> "CommandResult":
        """Raise if the command failed, otherwise return ``self``."""
        if not self.ok:
            raise AuthError(
                f"command failed with status {self.exit_status}: {self.command}\n"
                f"{self.stderr.strip()}"
            )
        return self


def list_agent_keys(agent_socket: Optional[str] = None) -> List[str]:
    """Return the fingerprints of the keys held by the SSH agent."""
    agent = paramiko.Agent(agent_socket) if agent_socket else paramiko.Agent()
    try:
        return [key.get_fingerprint().hex() for key in agent.get_keys()]
    finally:
        agent.close()


def load_client_key(
    key_path: str, passphrase: Optional[str] = None
) -> paramiko.PKey:
    """Load a private key from disk, trying the common key types.

    Args:
        key_path: Path to the private key.
        passphrase: Passphrase, if the key is protected.

    Returns:
        The loaded key object.

    Raises:
        AuthError: If the key cannot be loaded.
    """
    errors = []
    # DSSKey was removed from Paramiko in version 3.x, so it is not tried
    # here; DSA keys are no longer considered safe anyway.
    for key_class in (
        paramiko.Ed25519Key,
        paramiko.ECDSAKey,
        paramiko.RSAKey,
    ):
        try:
            return key_class.from_private_key_file(key_path, password=passphrase)
        except paramiko.PasswordRequiredException:
            raise AuthError(f"private key {key_path} requires a passphrase")
        except (paramiko.SSHException, OSError, ValueError) as exc:
            errors.append(f"{key_class.__name__}: {exc}")
    raise AuthError(f"could not load private key {key_path}: {'; '.join(errors)}")


def load_public_key(key_path: str) -> paramiko.PKey:
    """Load a key from either a public or a private key file.

    The server's host key is normally distributed as a public key file, so
    this accepts both forms:

    * a ``.pub`` file, which is parsed directly;
    * a private key file, whose public half is derived.

    Args:
        key_path: Path to the key file.

    Returns:
        The key object.

    Raises:
        AuthError: If the key cannot be loaded.
    """
    try:
        with open(key_path, "r", encoding="utf-8", errors="replace") as handle:
            first = handle.readline().strip()
    except OSError as exc:
        raise AuthError(f"could not read {key_path}: {exc}") from exc

    parts = first.split()
    if parts and parts[0] not in KEY_TYPES:
        # The file uses the ``known_hosts`` layout, where the host name comes
        # first: "host ssh-ed25519 AAAA...".  This is what ``ssh-keyscan``
        # produces, so it has to be accepted here.
        if len(parts) >= 3 and parts[1] in KEY_TYPES:
            parts = parts[1:]

    if len(parts) >= 2 and parts[0] in KEY_TYPES:
        try:
            return paramiko.PKey.from_type_string(
                parts[0], base64.b64decode(parts[1])
            )
        except Exception as exc:  # noqa: BLE001 - report a friendly error
            raise AuthError(f"could not parse the public key {key_path}: {exc}") from exc

    # Not a public key, so it must be a private key.
    return load_client_key(key_path)


def _negotiated_value(transport: paramiko.Transport, name: str) -> Optional[str]:
    """Return the negotiated value of *name*, whatever the Paramiko version.

    Paramiko 5 exposes the negotiated algorithms as plain attributes
    (``remote_cipher``, ``remote_mac``, ...), while older releases only offer
    accessor methods (``cipher()``, ``mac()``, ...).

    Args:
        transport: The active transport.
        name: The base name, for example ``"cipher"``.

    Returns:
        The negotiated value, or ``None`` when it is not available.
    """
    value = getattr(transport, f"remote_{name}", None)
    if value:
        return str(value)

    accessor = getattr(transport, name, None)
    if callable(accessor):
        try:
            result = accessor()
        except Exception:  # noqa: BLE001 - the value is only informational
            return None
        if isinstance(result, (tuple, list)):
            return str(result[0]) if result else None
        if result:
            return str(result)

    value = getattr(transport, name, None)
    return str(value) if value else None


def _negotiated_kex(transport: paramiko.Transport) -> Optional[str]:
    """Return the key exchange algorithm that was negotiated.

    Older Paramiko releases expose it as the ``kex`` attribute.  Paramiko 5
    logs the agreement but does not keep it in an attribute, so ``None`` is
    returned there, which is better than reporting a guess.
    """
    value = getattr(transport, "kex", None)
    return str(value) if value else None


def _server_key_types(transport: paramiko.Transport) -> list:
    """Return the host key types the server accepts.

    In client mode the negotiated host key type is the only one that the
    project can report reliably, because the server never sends a list.
    """
    key_type = getattr(transport, "host_key_type", None)
    if key_type:
        return [str(key_type)]

    getter = getattr(transport, "get_server_key", None)
    if callable(getter):
        try:
            key = getter()
        except Exception:  # noqa: BLE001 - the value is only informational
            key = None
        if key is not None:
            return [key.get_name()]
    return []


def _allowed_auth_methods(transport: paramiko.Transport) -> list:
    """Return the authentication methods the server offers.

    Paramiko 5 does not keep the list of methods advertised by the server.
    The effective configuration is therefore read from ``sshd -T``, which is
    also the more meaningful answer: it reflects what the server really
    allows rather than what it claimed during the handshake.
    """
    handler = getattr(transport, "auth_handler", None)
    methods = getattr(handler, "auth_methods", None)
    if methods:
        return list(methods)

    try:
        channel = transport.open_session()
        channel.exec_command("sudo -n sshd -T 2>/dev/null || sshd -T 2>/dev/null")
        stdout = channel.makefile("r", -1)
        output = stdout.read().decode("utf-8", errors="replace")
        channel.recv_exit_status()
        channel.close()
    except Exception:  # noqa: BLE001 - the value is only informational
        return []

    enabled = []
    for line in output.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        name, value = parts[0].lower(), parts[1].strip().lower()
        if name in ("passwordauthentication", "kbdinteractiveauthentication") and value == "yes":
            enabled.append(name)
        elif name == "pubkeyauthentication" and value == "yes":
            enabled.append("publickey")
    return enabled


__all__ = [
    "AuthConfig",
    "CommandResult",
    "ConnectionConfig",
    "SSHConnection",
    "HostKeyStatus",
    "list_agent_keys",
    "load_client_key",
    "load_public_key",
]
