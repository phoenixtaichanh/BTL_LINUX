"""Strict SSH host key verification.

Trusting whatever key a server presents on first contact is the classic
"man in the middle" weakness of SSH.  This module implements a strict
known-hosts workflow:

* A host key that is already known is accepted only if it matches exactly.
* A host key that is unknown is *not* silently trusted; the operator must
  explicitly add it.
* A host key that changed is always a hard error, because that is precisely
  the signature of an interception attack.

The store is a plain ``known_hosts`` file in the format OpenSSH uses, so it
can be inspected and edited with the usual tooling.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional

from ..utils.errors import HostKeyError
from ..utils.logging import get_logger

logger = get_logger("ssh.hostkeys")

#: Default location of the known hosts file.
DEFAULT_KNOWN_HOSTS = os.path.join(
    os.path.expanduser("~"), ".ssh", "known_hosts"
)

#: Key types we are willing to accept, strongest first.
SUPPORTED_KEY_TYPES = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)


class HostKeyStatus(str, Enum):
    """Outcome of verifying a presented host key."""

    #: The key matched a previously trusted key.
    MATCHED = "matched"
    #: The key is not present in the store yet.
    UNKNOWN = "unknown"
    #: The key differs from the one stored for this host.
    CHANGED = "changed"
    #: The key type is not in :data:`SUPPORTED_KEY_TYPES`.
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class HostKeyEntry:
    """A single trusted host key."""

    hostname: str
    key_type: str
    key_data: str
    comment: str = ""

    def to_line(self) -> str:
        """Render this entry as a ``known_hosts`` line."""
        parts = [self.hostname, self.key_type, self.key_data]
        if self.comment:
            parts.append(self.comment)
        return " ".join(parts)

    def fingerprint(self) -> str:
        """Return the SHA256 fingerprint of this key."""
        return _fingerprint(self.key_type, self.key_data)


def _fingerprint(key_type: str, key_data: str) -> str:
    """Compute the OpenSSH style ``SHA256:...`` fingerprint."""
    import base64
    import hashlib

    try:
        raw = base64.b64decode(key_data)
    except Exception:  # noqa: BLE001 - malformed key, report as unknown
        return "SHA256:<invalid>"
    digest = hashlib.sha256(raw).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


class KnownHostsStore:
    """A ``known_hosts`` file with strict verification semantics."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = os.path.abspath(path or DEFAULT_KNOWN_HOSTS)

    # -- loading and saving ---------------------------------------------

    def load(self) -> "list[HostKeyEntry]":
        """Parse the store, ignoring comments and blank lines."""
        entries: "list[HostKeyEntry]" = []
        if not os.path.exists(self.path):
            return entries

        with open(self.path, "r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                # Hashed hostnames start with "|1|" and are skipped because
                # we cannot match them without the salt.
                if line.startswith("|"):
                    continue
                parts = line.split()
                if len(parts) < 3:
                    continue
                hostname, key_type, key_data = parts[0], parts[1], parts[2]
                comment = " ".join(parts[3:]) if len(parts) > 3 else ""
                entries.append(
                    HostKeyEntry(
                        hostname=hostname,
                        key_type=key_type,
                        key_data=key_data,
                        comment=comment,
                    )
                )
        return entries

    def save(self, entries: Iterable[HostKeyEntry]) -> None:
        """Rewrite the store atomically."""
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)

        temp_path = f"{self.path}.tmp"
        with open(temp_path, "w", encoding="utf-8") as handle:
            for entry in entries:
                handle.write(entry.to_line() + "\n")
        os.replace(temp_path, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # -- lookup and modification ----------------------------------------

    def find(self, hostname: str, port: int = 22) -> "list[HostKeyEntry]":
        """Return every stored entry that applies to *hostname*."""
        candidates = {hostname}
        if port != 22:
            # OpenSSH brackets the host when a non default port is used.
            candidates.add(f"[{hostname}]:{port}")

        return [entry for entry in self.load() if entry.hostname in candidates]

    def add(
        self,
        hostname: str,
        key_type: str,
        key_data: str,
        *,
        port: int = 22,
        comment: str = "",
    ) -> HostKeyEntry:
        """Add a trusted key for *hostname*.

        Any previously stored key for the same host and key type is removed
        first so that the store never contains conflicting entries.
        """
        entries = self.load()
        host_field = format_known_hosts(hostname, port)
        entries = [
            entry
            for entry in entries
            if not (entry.hostname == host_field and entry.key_type == key_type)
        ]
        entry = HostKeyEntry(
            hostname=host_field, key_type=key_type, key_data=key_data, comment=comment
        )
        entries.append(entry)
        self.save(entries)
        return entry

    def remove(self, hostname: str, *, port: int = 22) -> int:
        """Remove every key stored for *hostname*; return how many were removed."""
        entries = self.load()
        candidates = {hostname}
        if port != 22:
            candidates.add(f"[{hostname}]:{port}")
        kept = [entry for entry in entries if entry.hostname not in candidates]
        removed = len(entries) - len(kept)
        if removed:
            self.save(kept)
        return removed

    # -- verification ----------------------------------------------------

    def verify(
        self,
        hostname: str,
        port: int,
        key_type: str,
        key_data: str,
    ) -> HostKeyStatus:
        """Compare a presented host key against the store.

        Args:
            hostname: The host that presented the key.
            port: The port that was connected to.
            key_type: The key type, e.g. ``ssh-ed25519``.
            key_data: The base64 encoded key body.

        Returns:
            The verification outcome.

        Raises:
            HostKeyError: If the key type is not supported.
        """
        if key_type not in SUPPORTED_KEY_TYPES:
            raise HostKeyError(
                f"unsupported host key type {key_type!r}; "
                f"supported types are: {', '.join(SUPPORTED_KEY_TYPES)}"
            )

        entries = self.find(hostname, port)
        matching_type = [entry for entry in entries if entry.key_type == key_type]

        if not matching_type:
            return HostKeyStatus.UNKNOWN

        for entry in matching_type:
            if entry.key_data == key_data:
                return HostKeyStatus.MATCHED

        return HostKeyStatus.CHANGED


class HostKeyPolicy:
    """Decides how to react to the result of a host key verification."""

    def __init__(
        self,
        store: Optional[KnownHostsStore] = None,
        *,
        auto_accept: bool = False,
        known_hosts: Optional[str] = None,
    ) -> None:
        self.store = store or KnownHostsStore(known_hosts)
        self.auto_accept = auto_accept

    def check(self, hostname: str, port: int, key) -> HostKeyStatus:
        """Verify a host key and apply the policy.

        Args:
            hostname: The host that presented the key.
            port: The port that was connected to.
            key: A ``paramiko.PKey`` instance.

        Returns:
            The verification status.

        Raises:
            HostKeyError: If the key changed, is unsupported, or is unknown
                while automatic acceptance is disabled.
        """
        key_type = key.get_name()
        key_data = key.get_base64()
        status = self.store.verify(hostname, port, key_type, key_data)

        if status is HostKeyStatus.MATCHED:
            logger.debug("host key for %s matches the store", hostname)
            return status

        if status is HostKeyStatus.UNKNOWN:
            fingerprint = _fingerprint(key_type, key_data)
            if not self.auto_accept:
                raise HostKeyError(
                    f"unknown host key for {hostname} ({key_type} {fingerprint}). "
                    "Verify the fingerprint out of band, then add it with "
                    "`btl hostkey add`."
                )
            logger.warning(
                "auto-accepting unknown host key for %s (%s)", hostname, fingerprint
            )
            self.store.add(hostname, key_type, key_data, port=port)
            return status

        if status is HostKeyStatus.CHANGED:
            stored = self.store.find(hostname, port)
            expected = ", ".join(entry.fingerprint() for entry in stored)
            raise HostKeyError(
                f"host key for {hostname} CHANGED. Expected {expected}. "
                "This may indicate a man in the middle attack. "
                "Investigate before removing the old key."
            )

        return status


def format_known_hosts(hostname: str, port: int = 22) -> str:
    """Return the ``known_hosts`` style host name for a given host and port."""
    if port == 22:
        return hostname
    return f"[{hostname}]:{port}"


def reverse_dns_lookup(hostname: str, timeout: float = 3.0) -> Optional[str]:
    """Best effort reverse DNS lookup, used only for logging."""
    try:
        return socket.gethostbyaddr(hostname)[0]
    except (OSError, socket.herror, socket.gaierror):
        return None


__all__ = [
    "DEFAULT_KNOWN_HOSTS",
    "HostKeyEntry",
    "HostKeyPolicy",
    "HostKeyStatus",
    "KnownHostsStore",
    "SUPPORTED_KEY_TYPES",
    "format_known_hosts",
    "reverse_dns_lookup",
]
