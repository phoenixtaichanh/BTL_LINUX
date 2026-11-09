"""Server side SFTP subsystem with an optional chroot jail.

This module implements the receiving half of the SFTP subsystem.  It is meant
to be attached to an inbound SSH server connection, typically as a
``Subsystem`` handler.

Two confinement mechanisms are available and can be combined:

``SFTPServer``
    A plain SFTP server rooted at *root_dir*.  Paths are resolved inside the
    root and anything escaping it is refused.  This works without ``chroot``
    and therefore also works on systems where the server is not running as
    root.

``chroot_jail``
    A helper that creates the classic OpenSSH chroot jail: a root owned
    directory tree with a writable subdirectory for the user.  This is the
    strongest option and is normally combined with ``ForceCommand
    internal-sftp`` in ``sshd_config``.
"""

from __future__ import annotations

import os
import posixpath
from dataclasses import dataclass
from typing import Optional

from ..utils.errors import SFTPError, ValidationError
from ..utils.logging import get_logger
from ..utils.paths import SafePath

logger = get_logger("sftp.server")


@dataclass
class JailSpec:
    """Describes a chroot jail for one account.

    Attributes:
        username: The account the jail belongs to.
        jail_root: The chroot directory on the host.
        upload_dir: The writable directory inside the jail.
        home_dir: The user's home directory on the host.
    """

    username: str
    jail_root: str
    upload_dir: str = "upload"
    home_dir: str = ""

    def build(self) -> None:
        """Create the jail directory structure.

        The jail root itself must be owned by root and must not be writable by
        anyone else, otherwise ``chroot()`` would fail or be escapable.  The
        upload directory is owned by the account.
        """
        os.makedirs(self.jail_root, exist_ok=True)
        os.makedirs(os.path.home_dir, exist_ok=True)

        # The jail root and every intermediate directory must be root owned
        # and not group/world writable.
        _secure_dir(self.jail_root)

        upload = os.path.join(self.jail_root, self.upload_dir)
        os.makedirs(upload, exist_ok=True)
        try:
            import pwd

            info = pwd.getpwnam(self.username)
            os.chown(upload, info.pw_uid, info.pw_gid)
        except (KeyError, ImportError, OSError) as exc:
            logger.warning("could not chown %s: %s", upload, exc)
        _secure_dir(upload, writable_by_user=self.username)


def _secure_dir(path: str, writable_by_user: Optional[str] = None) -> None:
    """Apply ownership and permissions that keep a jail from being escaped."""
    try:
        os.chmod(path, 0o755)
    except OSError:
        pass

    if writable_by_user:
        try:
            import pwd

            info = pwd.getpwnam(writable_by_user)
            os.chown(path, info.pw_uid, info.pw_gid)
            os.chmod(path, 0o700)
        except (KeyError, ImportError, OSError) as exc:
            logger.warning("could not secure %s: %s", path, exc)
    else:
        try:
            os.chown(path, 0, 0)
        except OSError:
            pass


def chroot_jail(
    username: str,
    *,
    jail_base: str = "/opt/sftp-jails",
    upload_dir: str = "upload",
) -> JailSpec:
    """Create a chroot jail for *username* and return its specification.

    Args:
        username: The account to jail.
        jail_base: The directory that holds all jails.
        upload_dir: The name of the writable directory inside the jail.

    Returns:
        The :class:`JailSpec` describing the created jail.
    """
    jail_root = os.path.join(jail_base, username)
    home_dir = os.path.join("/home", username)

    spec = JailSpec(
        username=username,
        jail_root=jail_root,
        upload_dir=upload_dir,
        home_dir=home_dir,
    )
    spec.build()
    logger.info("created chroot jail for %s at %s", username, jail_root)
    return spec


class SFTPServer:
    """A path confined SFTP server.

    Args:
        root_dir: The directory that all paths are resolved inside.
        allow_upload: Whether uploads are permitted.
        allow_download: Whether downloads are permitted.
        allow_delete: Whether files may be removed.
        read_only_extensions: Extensions that may never be written.
    """

    def __init__(
        self,
        root_dir: str,
        *,
        allow_upload: bool = True,
        allow_download: bool = True,
        allow_delete: bool = False,
        read_only_extensions: Optional[list] = None,
    ) -> None:
        self.root_dir = os.path.abspath(root_dir)
        self.allow_upload = allow_upload
        self.allow_download = allow_download
        self.allow_delete = allow_delete
        self.read_only_extensions = [
            ext.lower() for ext in (read_only_extensions or [])
        ]
        os.makedirs(self.root_dir, exist_ok=True)

    # -- path handling ---------------------------------------------------

    def resolve(self, path: str, *, must_exist: bool = False) -> str:
        """Resolve *path* inside the root directory.

        Raises:
            ValidationError: If the path escapes the root.
        """
        if not path:
            raise ValidationError("path must not be empty")
        resolved = SafePath.resolve(
            self.root_dir, path, allow_absolute=False, must_exist=must_exist
        )
        return resolved.path

    def _check_writable(self, path: str) -> None:
        """Refuse writes to protected extensions."""
        if not self.read_only_extensions:
            return
        _, ext = posixpath.splitext(path)
        if ext.lower() in self.read_only_extensions:
            raise PermissionError(f"writing {ext!r} files is not permitted")

    # -- operations ------------------------------------------------------

    def listdir(self, path: str) -> "list[os.stat_result]":
        """List a directory."""
        target = self.resolve(path, must_exist=True)
        if not os.path.isdir(target):
            raise SFTPError(f"not a directory: {path}")
        return [os.stat(os.path.join(target, name)) for name in sorted(os.listdir(target))]

    def stat(self, path: str) -> os.stat_result:
        """Return the metadata of a path."""
        target = self.resolve(path, must_exist=True)
        return os.stat(target)

    def open(self, path: str, mode: str = "rb"):
        """Open a file for reading or writing.

        The path is resolved inside the root, so a client cannot reach files
        outside of it.
        """
        target = self.resolve(path)
        writing = any(flag in mode for flag in ("w", "a", "+", "x"))

        if writing:
            if not self.allow_upload:
                raise PermissionError("uploads are not permitted on this server")
            self._check_writable(target)

        parent = os.path.dirname(target)
        if writing and parent and not os.path.isdir(parent):
            raise SFTPError(f"parent directory does not exist: {os.path.dirname(path)}")

        if not writing and not self.allow_download:
            raise PermissionError("downloads are not permitted on this server")

        return open(target, mode)

    def remove(self, path: str) -> None:
        """Delete a file."""
        if not self.allow_delete:
            raise PermissionError("deletion is not permitted on this server")
        target = self.resolve(path, must_exist=True)
        os.remove(target)

    def mkdir(self, path: str, mode: int = 0o755) -> None:
        """Create a directory."""
        if not self.allow_upload:
            raise PermissionError("uploads are not permitted on this server")
        target = self.resolve(path)
        os.makedirs(target, mode=mode, exist_ok=True)

    def rmdir(self, path: str) -> None:
        """Remove an empty directory."""
        if not self.allow_delete:
            raise PermissionError("deletion is not permitted on this server")
        target = self.resolve(path, must_exist=True)
        os.rmdir(target)

    def rename(self, old_path: str, new_path: str) -> None:
        """Rename or move a path."""
        source = self.resolve(old_path, must_exist=True)
        destination = self.resolve(new_path)
        os.rename(source, destination)

    def chattr(self, path: str, attr: int) -> None:
        """Apply permission bits to a path."""
        target = self.resolve(path, must_exist=True)
        os.chmod(target, attr)

    def symlink(self, source: str, target: str) -> None:
        """Create a symbolic link."""
        resolved = self.resolve(target)
        os.symlink(source, resolved)

    def readlink(self, path: str) -> str:
        """Read the target of a symbolic link."""
        target = self.resolve(path, must_exist=True)
        return os.readlink(target)

    def canonicalize(self, path: str) -> str:
        """Return the canonical form of a path."""
        target = self.resolve(path)
        return os.path.realpath(target)

    def statvfs(self, path: str) -> "os.statvfs_result":
        """Return filesystem statistics for the root."""
        return os.statvfs(self.root_dir)


__all__ = ["JailSpec", "SFTPServer", "chroot_jail"]
