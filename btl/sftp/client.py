"""SFTP client with an enforced virtual root.

SFTP is the protocol this project leans on most for "safe" file transfer: it
carries its own request/response framing, so it does not depend on a remote
shell, and it supports resuming and granular permission checks.

The most important feature of this module is the *virtual root*.  When a root
is configured, every path the client touches is resolved inside that root and
anything that would escape it is rejected.  This mirrors the behaviour of a
chroot but is enforced in the client, which means it also protects against a
misconfigured or malicious server.
"""

from __future__ import annotations

import os
import posixpath
import stat
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

import paramiko

from ..utils.errors import SFTPError, ValidationError
from ..utils.logging import get_logger
from ..utils.paths import SafePath, native_to_remote

logger = get_logger("sftp.client")


@dataclass
class FileInfo:
    """Metadata about a remote file."""

    path: str
    name: str
    size: int
    mode: int
    is_dir: bool
    is_link: bool
    modified: Optional[float] = None

    @property
    def permissions(self) -> str:
        """The permission bits rendered in the familiar ``ls -l`` style."""
        return stat.filemode(self.mode)

    @property
    def size_human(self) -> str:
        """The size rendered with a unit suffix."""
        value = float(self.size)
        for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
            if value < 1024 or unit == "TiB":
                return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
            value /= 1024
        return f"{value:.1f} TiB"


class SFTPClient:
    """A higher level SFTP client with path confinement.

    Args:
        sftp: The underlying ``paramiko.SFTPClient``.
        root: Optional virtual root.  All paths are resolved inside it.
    """

    def __init__(self, sftp: paramiko.SFTPClient, *, root: Optional[str] = None) -> None:
        self._sftp = sftp
        self._root = root.rstrip("/") if root else None

    # -- path handling ---------------------------------------------------

    def _resolve(self, path: str, *, must_exist: bool = False) -> str:
        """Resolve *path* inside the virtual root.

        The returned path is a *remote* POSIX path, because it is what has to
        be sent to the server.  The confinement check is performed against the
        native representation of the root.

        Args:
            path: The requested path.
            must_exist: Whether the path must exist.

        Returns:
            The resolved absolute remote path.

        Raises:
            ValidationError: If the path escapes the virtual root.
        """
        if not path:
            raise ValidationError("path must not be empty")

        if self._root:
            resolved = SafePath.resolve(
                self._root, path, allow_absolute=False, must_exist=must_exist
            )
            return native_to_remote(resolved.path, self._root)

        # Without a root the path is used as given, but still normalised.
        if not path.startswith("/"):
            raise ValidationError(
                "an absolute path is required when no virtual root is configured"
            )
        return posixpath.normpath(path)

    def _display(self, path: str) -> str:
        """Return a path relative to the virtual root, for display."""
        if not self._root:
            return path
        if path == self._root:
            return "/"
        prefix = self._root + "/"
        if path.startswith(prefix):
            return "/" + path[len(prefix):]
        return path

    def resolve(self, path: str, *, must_exist: bool = False) -> str:
        """Resolve *path* inside the virtual root and return the remote path.

        This is the public counterpart of the internal resolution used by
        the client.  Callers that need the resolved path themselves, such
        as a user interface that wants to read a file directly, use it to
        make sure that the confinement rules are applied before the path is
        handed to the underlying Paramiko client.

        Args:
            path: The requested path.
            must_exist: Whether the path must exist.

        Returns:
            The resolved absolute remote path.

        Raises:
            ValidationError: If the path escapes the virtual root.
        """
        return self._resolve(path, must_exist=must_exist)

    # -- listing ---------------------------------------------------------

    def listdir(self, path: str = ".") -> List[FileInfo]:
        """List the contents of a directory.

        Args:
            path: The directory to list.

        Returns:
            A list of :class:`FileInfo` for each entry.
        """
        target = self._resolve(path, must_exist=True)
        try:
            entries = self._sftp.listdir_attr(target)
        except IOError as exc:
            raise SFTPError(f"could not list {path}: {exc}") from exc

        result = []
        for entry in entries:
            result.append(
                FileInfo(
                    path=posixpath.join(target, entry.filename),
                    name=entry.filename,
                    size=entry.st_size,
                    mode=entry.st_mode,
                    is_dir=stat.S_ISDIR(entry.st_mode),
                    is_link=stat.S_ISLNK(entry.st_mode),
                    modified=entry.st_mtime,
                )
            )
        result.sort(key=lambda item: item.name)
        return result

    def stat(self, path: str) -> FileInfo:
        """Return the metadata of a single path."""
        target = self._resolve(path, must_exist=True)
        try:
            entry = self._sftp.stat(target)
        except IOError as exc:
            raise SFTPError(f"could not stat {path}: {exc}") from exc
        return FileInfo(
            path=target,
            name=posixpath.basename(target),
            size=entry.st_size,
            mode=entry.st_mode,
            is_dir=stat.S_ISDIR(entry.st_mode),
            is_link=stat.S_ISLNK(entry.st_mode),
            modified=entry.st_mtime,
        )

    def exists(self, path: str) -> bool:
        """Return whether *path* exists inside the virtual root."""
        try:
            self._resolve(path, must_exist=True)
        except (ValidationError, SFTPError):
            return False
        return True

    def isdir(self, path: str) -> bool:
        """Return whether *path* is a directory."""
        try:
            return self.stat(path).is_dir
        except (ValidationError, SFTPError):
            return False

    # -- transfers -------------------------------------------------------

    def get(
        self,
        remote_path: str,
        local_path: str,
        *,
        callback: Optional[Callable[[int, int], None]] = None,
        resume: bool = False,
    ) -> int:
        """Download a file.

        Args:
            remote_path: The remote file to download.
            local_path: Where to write it locally.
            callback: Optional progress callback receiving
                ``(transferred, total)``.
            resume: Continue a partially transferred file.

        Returns:
            The number of bytes written.
        """
        target = self._resolve(remote_path, must_exist=True)
        local_path = os.path.abspath(local_path)
        os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)

        if resume and os.path.exists(local_path):
            return self._get_resume(target, local_path, callback)

        try:
            self._sftp.get(target, local_path, callback=callback)
        except IOError as exc:
            raise SFTPError(f"could not download {remote_path}: {exc}") from exc
        return os.path.getsize(local_path)

    def _get_resume(
        self,
        target: str,
        local_path: str,
        callback: Optional[Callable[[int, int], None]],
    ) -> int:
        """Resume an interrupted download using the SFTP read offset."""
        offset = os.path.getsize(local_path)
        try:
            with self._sftp.open(target, "rb") as remote, open(local_path, "ab") as local:
                remote.seek(offset)
                while True:
                    chunk = remote.read(32 * 1024)
                    if not chunk:
                        break
                    local.write(chunk)
                    offset += len(chunk)
                    if callback:
                        callback(offset, offset)
        except IOError as exc:
            raise SFTPError(f"could not resume download: {exc}") from exc
        return offset

    def put(
        self,
        local_path: str,
        remote_path: str,
        *,
        callback: Optional[Callable[[int, int], None]] = None,
        resume: bool = False,
    ) -> int:
        """Upload a file.

        Args:
            local_path: The local file to upload.
            remote_path: The destination on the remote host.
            callback: Optional progress callback receiving
                ``(transferred, total)``.
            resume: Continue a partially transferred file.

        Returns:
            The number of bytes transferred.
        """
        local_path = os.path.abspath(local_path)
        if not os.path.exists(local_path):
            raise ValidationError(f"local file does not exist: {local_path}")
        if os.path.isdir(local_path):
            raise ValidationError("put() only handles files; use puttree()")

        target = self._resolve(remote_path)
        parent = posixpath.dirname(target)
        if parent:
            try:
                self._sftp.stat(parent)
            except IOError:
                self.makedirs(posixpath.dirname(target) or "/", exist_ok=True)

        mode = os.stat(local_path).st_mode & 0o7777
        try:
            if resume and self.exists(remote_path):
                offset = self.stat(remote_path).size
                with open(local_path, "rb") as source, self._sftp.open(target, "ab") as dest:
                    source.seek(offset)
                    while True:
                        chunk = source.read(32 * 1024)
                        if not chunk:
                            break
                        dest.write(chunk)
                        offset += len(chunk)
                        if callback:
                            callback(offset, offset)
                return offset

            self._sftp.put(local_path, target, callback=callback)
            try:
                self._sftp.chmod(target, mode)
            except IOError:
                pass
        except IOError as exc:
            raise SFTPError(f"could not upload {local_path}: {exc}") from exc
        return os.path.getsize(local_path)

    def puttree(
        self,
        local_dir: str,
        remote_dir: str,
        *,
        callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[str]:
        """Recursively upload a directory tree.

        Returns:
            The list of remote paths that were written.
        """
        local_dir = os.path.abspath(local_dir)
        if not os.path.isdir(local_dir):
            raise ValidationError(f"not a directory: {local_dir}")

        base = self._resolve(remote_dir)
        self.makedirs(base, exist_ok=True)

        written: List[str] = []
        for dirpath, dirnames, filenames in os.walk(local_dir):
            dirnames.sort()
            filenames.sort()
            relative = os.path.relpath(dirpath, local_dir)
            remote_base = (
                base if relative == "." else posixpath.join(base, relative.replace(os.sep, "/"))
            )
            self.makedirs(remote_base, exist_ok=True)

            for name in filenames:
                local_file = os.path.join(dirpath, name)
                if os.path.islink(local_file):
                    continue
                remote_file = posixpath.join(remote_base, name)
                self.put(local_file, remote_file, callback=callback)
                written.append(remote_file)
        return written

    # -- directories -----------------------------------------------------

    def mkdir(self, path: str, *, mode: int = 0o755) -> None:
        """Create a single directory."""
        target = self._resolve(path)
        try:
            self._sftp.mkdir(target, mode)
        except IOError as exc:
            raise SFTPError(f"could not create {path}: {exc}") from exc

    def makedirs(self, path: str, *, mode: int = 0o755, exist_ok: bool = True) -> None:
        """Create a directory and all missing parents."""
        target = self._resolve(path)
        parts = [p for p in target.split("/") if p]
        current = "/" if target.startswith("/") else ""
        for part in parts:
            current = posixpath.join(current, part) if current != "/" else "/" + part
            try:
                self._sftp.stat(current)
            except IOError:
                try:
                    self._sftp.mkdir(current, mode)
                except IOError as exc:
                    if not exist_ok:
                        raise SFTPError(f"could not create {path}: {exc}") from exc
            else:
                if not exist_ok:
                    raise SFTPError(f"directory already exists: {path}")

    def rmdir(self, path: str) -> None:
        """Remove an empty directory."""
        target = self._resolve(path)
        try:
            self._sftp.rmdir(target)
        except IOError as exc:
            raise SFTPError(f"could not remove directory {path}: {exc}") from exc

    def remove(self, path: str) -> None:
        """Delete a file."""
        target = self._resolve(path)
        try:
            self._sftp.remove(target)
        except IOError as exc:
            raise SFTPError(f"could not remove {path}: {exc}") from exc

    def rename(self, old_path: str, new_path: str) -> None:
        """Rename or move a path."""
        source = self._resolve(old_path)
        destination = self._resolve(new_path)
        try:
            self._sftp.rename(source, destination)
        except IOError as exc:
            raise SFTPError(f"could not rename {old_path}: {exc}") from exc

    def chmod(self, path: str, mode: int) -> None:
        """Change the permission bits of a path."""
        target = self._resolve(path)
        try:
            self._sftp.chmod(target, mode)
        except IOError as exc:
            raise SFTPError(f"could not chmod {path}: {exc}") from exc

    def utime(self, path: str, times: Tuple[float, float]) -> None:
        """Set the access and modification times of a path."""
        target = self._resolve(path)
        try:
            self._sftp.utime(target, times)
        except IOError as exc:
            raise SFTPError(f"could not set times on {path}: {exc}") from exc

    def symlink(self, source: str, target: str) -> None:
        """Create a symbolic link on the remote host."""
        resolved_target = self._resolve(target)
        try:
            self._sftp.symlink(source, resolved_target)
        except IOError as exc:
            raise SFTPError(f"could not create symlink {target}: {exc}") from exc

    def readlink(self, path: str) -> str:
        """Read the target of a symbolic link."""
        target = self._resolve(path)
        try:
            return self._sftp.readlink(target)
        except IOError as exc:
            raise SFTPError(f"could not read symlink {path}: {exc}") from exc

    def close(self) -> None:
        """Close the underlying SFTP session."""
        try:
            self._sftp.close()
        except Exception:  # noqa: BLE001 - best effort cleanup
            pass

    def __enter__(self) -> "SFTPClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


__all__ = ["FileInfo", "SFTPClient"]
