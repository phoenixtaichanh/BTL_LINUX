"""Path handling helpers with traversal and symlink safety.

The SCP and SFTP implementations in this project both accept remote paths that
originate from an untrusted peer.  A naive implementation that simply joins
the requested name onto the destination directory is vulnerable to:

* ``../`` traversal (``../../etc/shadow``),
* absolute path injection (``/etc/passwd``),
* symlink escape (a symlink inside the jail pointing outside of it).

The helpers here implement the defence in depth used throughout the project:
normalise, reject, then verify with ``realpath`` before any file is opened.
"""

from __future__ import annotations

import os
import posixpath
import re
from dataclasses import dataclass
from typing import Iterable, Optional

from .errors import ValidationError

#: Characters that are unsafe in a filename on at least one supported OS.
_UNSAFE_CHARS = re.compile(r'[\x00-\x1f\x7f<>:"\\|?*]')

#: Windows reserved device names (invalid on Windows, harmless elsewhere).
_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)

#: Maximum length of a single path component.
MAX_COMPONENT_LENGTH = 255


def validate_relative_name(name: str) -> str:
    """Validate a single path component received from a remote peer.

    Unlike :func:`sanitize_filename` this function *rejects* rather than
    rewrites suspicious input.  Silently turning ``../../etc/passwd`` into
    ``etc_passwd`` would hide an attack attempt, whereas an explicit error
    lets the operator see it in the logs.

    Args:
        name: The name as received from the peer.

    Returns:
        The validated name, unchanged.

    Raises:
        ValidationError: If the name is empty, contains a path separator,
            contains a ``..`` component, or contains a NUL byte.
    """
    if not name:
        raise ValidationError("file name must not be empty")
    if "\x00" in name:
        raise ValidationError("file name must not contain NUL bytes")
    if "/" in name or "\\" in name:
        raise ValidationError(
            f"file name must be a single path component, got {name!r}"
        )
    if name in (".", ".."):
        raise ValidationError(f"file name must not be a relative reference: {name!r}")
    if name.startswith(".."):
        raise ValidationError(f"file name must not start with '..': {name!r}")
    return name


def sanitize_filename(name: str, *, replacement: str = "_") -> str:
    """Return a version of *name* that is safe to use as a single path part.

    Directory separators and control characters are replaced, the result is
    trimmed of surrounding whitespace and dots, and reserved Windows device
    names are suffixed so the file remains usable if the download is later
    opened on Windows.
    """
    if not name:
        raise ValidationError("filename must not be empty")

    cleaned = _UNSAFE_CHARS.sub(replacement, name)
    # Treat both separators as separators regardless of the running platform.
    cleaned = cleaned.replace("/", replacement).replace("\\", replacement)
    # Parent directory references are removed outright rather than being
    # turned into a harmless looking name, so the result can never be
    # mistaken for a traversal.
    while ".." in cleaned:
        cleaned = cleaned.replace("..", replacement)
    cleaned = cleaned.strip().strip(".")
    if not cleaned:
        cleaned = "unnamed"

    stem = cleaned.split(".")[0].upper()
    if stem in _RESERVED_NAMES:
        cleaned = f"_{cleaned}"

    if len(cleaned) > MAX_COMPONENT_LENGTH:
        base, dot, ext = cleaned.rpartition(".")
        if dot and len(ext) < MAX_COMPONENT_LENGTH:
            keep = MAX_COMPONENT_LENGTH - len(ext) - 1
            cleaned = base[:keep] + "." + ext
        else:
            cleaned = cleaned[:MAX_COMPONENT_LENGTH]
    return cleaned


def normalize_remote_path(path: str, *, base: Optional[str] = None) -> str:
    """Normalise a remote POSIX path without touching the filesystem.

    Collapses redundant separators, resolves ``.`` and ``..`` segments and
    removes a trailing separator.  The result always starts with ``/``.

    Args:
        path: The path to normalise.
        base: Optional base directory that a relative *path* is resolved
            against.

    Returns:
        The normalised absolute path.

    Raises:
        ValidationError: If *path* is empty or not a string.
    """
    if path is None or not isinstance(path, str):
        raise ValidationError("path must be a string")
    if not path:
        raise ValidationError("path must not be empty")

    if base:
        path = posixpath.join(base, path)
    if not path.startswith("/"):
        path = "/" + path

    # Purely lexical normalisation: no filesystem access, so it is safe to run
    # against paths that do not exist yet.
    normalized = posixpath.normpath(path)
    if normalized != "/":
        normalized = normalized.rstrip("/")
    return normalized or "/"


def is_within(root: str, candidate: str) -> bool:
    """Return ``True`` if *candidate* is contained in *root*.

    Both arguments are normalised first.  The comparison is done on component
    boundaries so that ``/srv/data-old`` is *not* considered to be inside
    ``/srv/data``.
    """
    root_norm = normalize_remote_path(root)
    cand_norm = normalize_remote_path(candidate)
    if root_norm == "/":
        return True
    if cand_norm == root_norm:
        return True
    return cand_norm.startswith(root_norm + "/")


@dataclass(frozen=True)
class SafePath:
    """A resolved path that has been verified to stay inside a root directory.

    Instances are immutable and can only be produced by
    :meth:`SafePath.resolve`, which performs the containment check.  This makes
    it hard to accidentally use an unvalidated path later in the code.

    The class works with *native* filesystem paths rather than POSIX paths,
    because it has to interact with the real filesystem in order to resolve
    symlinks.  Remote paths are converted with
    :func:`remote_to_native` before they are passed in.
    """

    root: str
    path: str
    real_root: str

    @classmethod
    def resolve(
        cls,
        root: str,
        candidate: str,
        *,
        allow_absolute: bool = False,
        must_exist: bool = False,
    ) -> "SafePath":
        """Resolve *candidate* against *root* and verify containment.

        Args:
            root: The jail root that must contain the result.  This is a
                native filesystem path.
            candidate: The requested path.  It may use ``/`` as the separator
                regardless of the host platform.
            allow_absolute: When ``False`` (default) an absolute *candidate*
                is treated as relative to *root*, which prevents a peer from
                escaping the jail by sending an absolute path.
            must_exist: When ``True`` the path must already exist on disk.

        Returns:
            A validated :class:`SafePath`.

        Raises:
            ValidationError: If the resolved path escapes *root* or, when
                *must_exist* is set, does not exist.
        """
        if candidate is None or not isinstance(candidate, str):
            raise ValidationError("path must be a string")
        if not candidate:
            raise ValidationError("path must not be empty")
        if "\x00" in candidate:
            raise ValidationError("path must not contain NUL bytes")

        root_native = os.path.abspath(root)
        # The candidate always uses forward slashes, so it is normalised with
        # POSIX rules first and then translated to the native separator.
        candidate_posix = normalize_remote_path(candidate)
        relative = candidate_posix.lstrip("/")

        # A ".." component is rejected outright instead of being collapsed
        # away.  Collapsing it would keep the request inside the root, but it
        # would also hide the attempt from the operator.
        raw_parts = [p for p in candidate.replace("\\", "/").split("/") if p]
        if any(part == ".." for part in raw_parts):
            raise ValidationError(
                f"path {candidate!r} contains a parent directory reference"
            )

        if allow_absolute and os.path.isabs(candidate.replace("/", os.sep)):
            joined = os.path.abspath(candidate.replace("/", os.sep))
        else:
            joined = os.path.abspath(
                os.path.join(root_native, *[p for p in relative.split("/") if p])
            )

        # A lexical containment check catches an ordinary "..".  It runs
        # before realpath so that a path that does not exist yet can still be
        # validated.
        if not _is_within_real(root_native, joined):
            raise ValidationError(
                f"path {candidate!r} escapes the permitted root {root!r}"
            )

        real_root = os.path.realpath(root_native)
        real_path = os.path.realpath(joined)
        # realpath resolves symlinks, so a symlink pointing outside the jail
        # is caught here as well.
        if not _is_within_real(real_root, real_path):
            raise ValidationError(
                f"path {candidate!r} resolves outside the permitted root"
            )

        if must_exist and not os.path.exists(real_path):
            raise ValidationError(f"path {candidate!r} does not exist")

        return cls(root=root_native, path=joined, real_root=real_root)

    @property
    def name(self) -> str:
        """The final path component."""
        return os.path.basename(self.path)

    @property
    def parent(self) -> str:
        """The parent directory of :attr:`path`."""
        return os.path.dirname(self.path)

    def relative_to_root(self) -> str:
        """Return :attr:`path` relative to :attr:`root`.

        The result always uses forward slashes so that it can be sent to a
        remote peer.
        """
        if self.path == self.root:
            return ""
        prefix = self.root.rstrip(os.sep) + os.sep
        if self.path.startswith(prefix):
            return self.path[len(prefix):].replace(os.sep, "/")
        return self.path.replace(os.sep, "/")

    def child(self, name: str) -> str:
        """Return a sanitised child path inside this directory."""
        return os.path.join(self.path, sanitize_filename(name))


def _is_within_real(real_root: str, real_path: str) -> bool:
    """Containment check on already-resolved (symlink-free) paths."""
    real_root = os.path.normpath(real_root)
    real_path = os.path.normpath(real_path)
    if real_root == real_path:
        return True
    return real_path.startswith(os.path.join(real_root, ""))


def remote_to_native(path: str, root: str) -> str:
    """Convert a POSIX remote path into a native path inside *root*.

    The remote path is resolved against the native *root* using POSIX rules
    and then translated to the platform's separator.  The result is not
    checked for containment; use :meth:`SafePath.resolve` for that.
    """
    normalized = normalize_remote_path(path)
    relative = normalized.lstrip("/")
    return os.path.join(root, *[p for p in relative.split("/") if p])


def native_to_remote(path: str, root: str) -> str:
    """Convert a native path inside *root* back into a POSIX remote path."""
    relative = os.path.relpath(path, root).replace(os.sep, "/")
    if relative == ".":
        return "/"
    return "/" + relative


def relative_to(base: str, path: str) -> str:
    """Return *path* expressed relative to *base*.

    Falls back to the absolute path when *path* is not inside *base*.
    """
    base_norm = normalize_remote_path(base)
    path_norm = normalize_remote_path(path)
    if not is_within(base_norm, path_norm):
        return path_norm
    prefix = base_norm if base_norm.endswith("/") else base_norm + "/"
    if path_norm.startswith(prefix):
        return path_norm[len(prefix):]
    return ""


def ensure_within(root: str, candidates: Iterable[str]) -> None:
    """Raise :class:`ValidationError` if any candidate escapes *root*."""
    for candidate in candidates:
        SafePath.resolve(root, candidate)


__all__ = [
    "SafePath",
    "ensure_within",
    "is_within",
    "native_to_remote",
    "normalize_remote_path",
    "relative_to",
    "remote_to_native",
    "sanitize_filename",
    "validate_relative_name",
    "MAX_COMPONENT_LENGTH",
]
