"""Pure implementation of the legacy SCP (scp1) wire protocol.

The protocol is a small, line oriented framing that rides on top of an SSH
``exec`` channel.  It is deliberately separated from any transport so that it
can be unit tested without opening a socket.

Overview
--------

One side is the *source* (``scp -f``) and produces data, the other is the
*sink* (``scp -t``) and consumes it.  The sink always speaks first, sending a
single ``\\x00`` byte to announce it is ready.

Control messages are ASCII lines terminated by ``\\n``:

===========  ==========================================================
``C0644 12 f``  create file ``f`` with mode ``0644`` and 12 bytes of data
``D0755 0 dir``  begin directory ``dir``
``E``            end of directory
``T12345 0 ...`` modification / access times
===========  ==========================================================

Acknowledgements are a single byte:

===========  ==========================================================
``\\x00``      success
``\\x01``      warning, optionally followed by a text message
``\\x02``      fatal error, the connection must be closed
===========  ==========================================================

The protocol has no explicit framing for file *content*: the reader must
consume exactly the number of bytes announced by the preceding ``C`` message.
That is why every read in this module is length driven.
"""

from __future__ import annotations

import os
import posixpath
import stat
from dataclasses import dataclass
from enum import Enum
from typing import Iterator, List, Optional, Tuple

from ..utils.errors import SCPError, ValidationError

#: Byte sent by the sink to acknowledge success.
ACK_OK = b"\x00"
#: Byte sent by the sink to report a recoverable problem.
ACK_WARNING = b"\x01"
#: Byte sent by the sink to report an unrecoverable problem.
ACK_ERROR = b"\x02"

#: Marker the producer sends right after a file body to signal the end of the
#: data.  The reference implementation writes a single zero byte there
#: (``scp.c``: ``atomicio(vwrite, remout, "", 1)``) and the sink consumes it
#: with ``response()`` before acknowledging the file.
EOF_MARKER = b"\x00"

#: Maximum length of a single control message line (bytes).
MAX_MESSAGE_LENGTH = 64 * 1024

#: Maximum size of a single file that may be transferred (8 GiB).
MAX_FILE_SIZE = 8 * 1024 * 1024 * 1024


class MessageType(str, Enum):
    """The first character of an SCP control message."""

    FILE = "C"
    DIRECTORY = "D"
    END_DIRECTORY = "E"
    TIME = "T"


@dataclass(frozen=True)
class ScpMessage:
    """A decoded SCP control message."""

    type: MessageType
    mode: int = 0
    size: int = 0
    name: str = ""
    mtime: int = 0
    atime: int = 0

    @property
    def is_file(self) -> bool:
        """``True`` when this message announces a regular file."""
        return self.type is MessageType.FILE

    @property
    def is_directory(self) -> bool:
        """``True`` when this message announces a directory."""
        return self.type is MessageType.DIRECTORY

    @property
    def is_end_directory(self) -> bool:
        """``True`` when this message closes a directory."""
        return self.type is MessageType.END_DIRECTORY


def encode_file_message(mode: int, size: int, name: str) -> bytes:
    """Encode a ``C`` (create file) message.

    Args:
        mode: Permission bits of the file.
        size: Number of bytes of content that follow.
        name: File name.  Control characters and newlines are escaped using
            the caret notation that the reference implementation expects.

    Returns:
        The encoded message including its trailing newline.
    """
    _validate_name(name)
    if size < 0 or size > MAX_FILE_SIZE:
        raise ValidationError(f"invalid file size: {size}")
    return f"C{mode & 0o7777:04o} {size} {_escape_name(name)}\n".encode("utf-8")


def encode_directory_message(mode: int, name: str) -> bytes:
    """Encode a ``D`` (create directory) message."""
    _validate_name(name)
    return f"D{mode & 0o7777:04o} 0 {_escape_name(name)}\n".encode("utf-8")


def encode_end_directory_message() -> bytes:
    """Encode the ``E`` (end of directory) message."""
    return b"E\n"


def encode_time_message(mtime: float, atime: float) -> bytes:
    """Encode a ``T`` (times) message used by the ``-p`` flag."""
    return f"T{int(mtime)} 0 {int(atime)} 0\n".encode("utf-8")


def encode_ack(status: int, message: str = "") -> bytes:
    """Encode an acknowledgement byte with an optional text message."""
    if status == 0:
        return ACK_OK
    if status == 1:
        return ACK_WARNING + f"{message}\n".encode("utf-8")
    if status == 2:
        return ACK_ERROR + f"{message}\n".encode("utf-8")
    raise ValueError(f"invalid acknowledgement status: {status}")


def _validate_name(name: str) -> None:
    """Reject names that would break the line oriented framing."""
    if not name:
        raise ValidationError("file name must not be empty")
    if "\n" in name or "\r" in name:
        raise ValidationError("file name must not contain newlines")
    if "\x00" in name:
        raise ValidationError("file name must not contain NUL bytes")


def _escape_name(name: str) -> str:
    """Escape control characters in a name using the caret notation.

    The reference implementation escapes everything below ``0x20`` and
    ``0x7f``.  Tabs are left alone because they are harmless in a line based
    protocol and some implementations rely on them.
    """
    out = []
    for ch in name:
        code = ord(ch)
        if code < 0x20 or code == 0x7F:
            if ch == "\t":
                out.append(ch)
            else:
                out.append(f"^{chr(code + 64)}")
        else:
            out.append(ch)
    return "".join(out)


def _unescape_name(name: str) -> str:
    """Reverse :func:`_escape_name`.

    A literal ``^`` followed by an uppercase letter is treated as the escape
    form, matching the behaviour of the reference implementation which does
    not unescape on the receiving side.  We unescape so that round trips
    inside this project stay consistent.
    """
    out = []
    i = 0
    while i < len(name):
        ch = name[i]
        if ch == "^" and i + 1 < len(name):
            nxt = name[i + 1]
            if "A" <= nxt <= "Z":
                out.append(chr(ord(nxt) - 64))
                i += 2
                continue
            if nxt == "[":
                out.append("\x1b")
                i += 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def decode_message(line: bytes) -> ScpMessage:
    """Decode a single control message line.

    Args:
        line: The raw line, *without* the trailing newline.

    Returns:
        The decoded :class:`ScpMessage`.

    Raises:
        SCPError: If the line is not a well formed SCP message.
    """
    if not isinstance(line, (bytes, bytearray)):
        raise SCPError("control message must be bytes")
    text = bytes(line).decode("utf-8", errors="replace")
    text = text.rstrip("\n").rstrip("\r")

    if not text:
        raise SCPError("empty control message")
    kind = text[0]

    if kind == "E":
        return ScpMessage(type=MessageType.END_DIRECTORY)

    if kind == "T":
        # Format is "T<mtime> 0 <atime> 0".
        parts = text.split()
        if len(parts) < 1:
            raise SCPError(f"malformed time message: {text!r}")
        try:
            mtime = int(parts[0][1:])
            atime = int(parts[2]) if len(parts) > 2 else mtime
        except ValueError as exc:
            raise SCPError(f"malformed time message: {text!r}") from exc
        return ScpMessage(type=MessageType.TIME, mtime=mtime, atime=atime)

    if kind in ("C", "D"):
        # Format is "C0644 1234 some name with spaces".
        # The mode is embedded in the first token, the size is the second
        # token, and the remainder of the line is the name (which may itself
        # contain spaces).
        parts = text.split(" ", 2)
        if len(parts) != 3:
            raise SCPError(
                f"malformed {'create' if kind == 'C' else 'directory'} message: {text!r}"
            )
        try:
            mode = int(parts[0][1:], 8)
        except ValueError as exc:
            raise SCPError(f"malformed mode in message: {text!r}") from exc
        try:
            size = int(parts[1])
        except ValueError as exc:
            raise SCPError(f"malformed size in message: {text!r}") from exc
        name = _unescape_name(parts[2])
        if size < 0 or size > MAX_FILE_SIZE:
            raise SCPError(f"size out of range in message: {text!r}")
        if kind == "C":
            return ScpMessage(type=MessageType.FILE, mode=mode, size=size, name=name)
        return ScpMessage(type=MessageType.DIRECTORY, mode=mode, size=size, name=name)

    raise SCPError(f"unknown control message type: {kind!r}")


class ScpSink:
    """Receives files according to the SCP protocol.

    The sink is the side that runs ``scp -t``.  It acknowledges every control
    message and every file body, writing the received content into a
    destination directory.

    Every incoming name is resolved through
    :class:`btl.utils.paths.SafePath` so a malicious peer cannot write outside
    of the destination directory.
    """

    def __init__(
        self,
        destination: str,
        *,
        preserve_times: bool = False,
        preserve_mode: bool = True,
        follow_symlinks: bool = False,
    ) -> None:
        self.destination = os.path.abspath(destination)
        self.preserve_times = preserve_times
        self.preserve_mode = preserve_mode
        self.follow_symlinks = follow_symlinks
        self._pending_times: Optional[ScpMessage] = None
        self._directory_stack: List[str] = []

    # -- protocol driving ------------------------------------------------

    def receive(self, read_line, read_exactly, write) -> List[str]:
        """Consume a stream of SCP messages.

        Args:
            read_line: Callable returning the next control line as ``bytes``
                without the trailing newline, or ``None`` at end of stream.
            read_exactly: Callable taking a byte count and returning exactly
                that many bytes.
            write: Callable taking ``bytes`` used to send acknowledgements.

        Returns:
            The list of relative paths that were written.
        """
        # The sink announces readiness first.
        write(ACK_OK)

        written: List[str] = []
        # The protocol is a flat stream, so the sink has to remember which
        # directory it is currently inside.  The "D" and "E" messages
        # bracket the contents of a directory.
        self._directory_stack = []

        while True:
            line = read_line()
            if line is None:
                break
            message = decode_message(line)

            if message.type is MessageType.TIME:
                self._pending_times = message
                write(ACK_OK)
                continue

            if message.type is MessageType.END_DIRECTORY:
                # The end of the outermost directory terminates the whole
                # transfer; the reference implementation stops reading at
                # that point instead of waiting for more input.
                if self._directory_stack:
                    self._directory_stack.pop()
                write(ACK_OK)
                if not self._directory_stack:
                    break
                continue

            if message.type is MessageType.DIRECTORY:
                self._create_directory(message, write)
                continue

            # File
            write(ACK_OK)
            try:
                path = self._resolve_target(message.name)
                self._receive_file(message, path, read_exactly, write)
            except (ValidationError, SCPError, OSError) as exc:
                write(encode_ack(2, str(exc)))
                raise SCPError(f"failed to receive {message.name!r}: {exc}") from exc
            written.append(path)
            if self.preserve_times and self._pending_times is not None:
                self._apply_times(path, self._pending_times)
            self._pending_times = None
        return written

    def _receive_file(self, message, path, read_exactly, write) -> None:
        """Stream the body of a file to disk, then acknowledge it.

        The producer marks the end of the body with a single zero byte, which
        has to be consumed before the acknowledgement is sent so that the two
        sides stay in sync.
        """
        remaining = message.size
        with open(path, "wb") as handle:
            while remaining > 0:
                chunk = read_exactly(min(remaining, 64 * 1024))
                if not chunk:
                    raise SCPError(
                        f"unexpected end of stream, {remaining} bytes missing"
                    )
                handle.write(chunk)
                remaining -= len(chunk)

        if self.preserve_mode:
            try:
                os.chmod(path, message.mode & 0o7777)
            except OSError:
                pass

        # Consume the end-of-file marker the producer sends after the body.
        marker = read_exactly(1)
        if marker and marker[0:1] != EOF_MARKER:
            raise SCPError(f"unexpected end-of-file marker: {marker!r}")

        write(ACK_OK)

    def _create_directory(self, message, write) -> None:
        """Create the announced directory and acknowledge it."""
        try:
            path = self._resolve_target(message.name, create_dirs=True)
            os.makedirs(path, exist_ok=True)
            if self.preserve_mode:
                try:
                    os.chmod(path, message.mode & 0o7777)
                except OSError:
                    pass
        except (ValidationError, OSError) as exc:
            write(encode_ack(2, str(exc)))
            raise SCPError(f"failed to create directory {message.name!r}: {exc}") from exc
        write(ACK_OK)
        # Everything that follows belongs to this directory until the
        # matching "E" message arrives.
        self._directory_stack.append(message.name)

    # -- helpers ----------------------------------------------------------

    def _resolve_target(self, name: str, create_dirs: bool = False) -> str:
        """Resolve *name* inside the destination directory.

        The name is validated strictly: any attempt to escape the destination
        (via ``..`` or an absolute path) raises :class:`ValidationError`
        instead of being silently rewritten, so the attempt shows up in the
        logs instead of being hidden.

        The name is resolved against the directory that is currently open,
        which the protocol signals with the "D" and "E" messages.
        """
        from ..utils.paths import SafePath, validate_relative_name

        safe_name = validate_relative_name(name)
        base = os.path.join(self.destination, *self._directory_stack)
        resolved = SafePath.resolve(base, safe_name, allow_absolute=False)
        target = resolved.path

        if create_dirs:
            os.makedirs(target, exist_ok=True)
        else:
            parent = os.path.dirname(target)
            if parent and not os.path.isdir(parent):
                os.makedirs(parent, exist_ok=True)

        # Refuse to follow a symlink that points outside the destination.
        if not self.follow_symlinks and os.path.islink(target):
            if not os.path.realpath(target).startswith(
                os.path.join(os.path.realpath(self.destination), "")
            ):
                raise ValidationError(f"refusing to write through symlink: {name!r}")
        return target

    def _apply_times(self, path: str, message: ScpMessage) -> None:
        """Restore modification and access times onto *path*."""
        try:
            os.utime(path, (message.atime, message.mtime))
        except OSError:
            pass


class ScpSource:
    """Produces files according to the SCP protocol.

    The source is the side that runs ``scp -f``.  It waits for the sink's
    ready byte, then walks the requested path sending control messages.
    """

    def __init__(
        self,
        source: str,
        *,
        recursive: bool = False,
        preserve_times: bool = False,
        preserve_mode: bool = True,
    ) -> None:
        self.source = os.path.abspath(source)
        self.recursive = recursive
        self.preserve_times = preserve_times
        self.preserve_mode = preserve_mode

    def send(self, read_byte, write) -> None:
        """Push the source tree to the peer.

        Args:
            read_byte: Callable returning the next acknowledgement byte.
            write: Callable taking ``bytes`` used to send control messages.
        """
        ack = read_byte()
        if ack != ACK_OK:
            raise SCPError(f"peer refused the transfer: {ack!r}")

        if os.path.isdir(self.source):
            if not self.recursive:
                raise SCPError(
                    f"{self.source} is a directory, recursive transfer required"
                )
            self._send_directory(self.source, write, read_byte)
        else:
            self._send_file(self.source, os.path.basename(self.source), write, read_byte)

    def _send_directory(self, path: str, write, read_byte) -> None:
        """Recursively send a directory tree.

        Each control message is acknowledged by the peer before the next one
        is emitted, so the acknowledgement must be read before continuing.
        """
        info = os.stat(path)
        write(encode_directory_message(stat.S_IMODE(info.st_mode), os.path.basename(path)))
        self._expect_ack(read_byte)

        for entry in sorted(os.listdir(path)):
            full = os.path.join(path, entry)
            if os.path.isdir(full) and not os.path.islink(full):
                self._send_directory(full, write, read_byte)
            elif os.path.isfile(full):
                self._send_file(full, entry, write, read_byte)

        write(encode_end_directory_message())
        self._expect_ack(read_byte)

    def _send_file(self, path: str, name: str, write, read_byte) -> None:
        """Send a single regular file."""
        info = os.stat(path)
        size = info.st_size
        if self.preserve_times:
            write(encode_time_message(info.st_mtime, info.st_atime))
            self._expect_ack(read_byte)
        mode = stat.S_IMODE(info.st_mode) if self.preserve_mode else 0o644
        write(encode_file_message(mode, size, name))
        self._expect_ack(read_byte)

        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(64 * 1024)
                if not chunk:
                    break
                write(chunk)

        # Mark the end of the body, then wait for the peer to confirm that it
        # consumed the content.
        write(EOF_MARKER)
        self._expect_ack(read_byte)

    @staticmethod
    def _expect_ack(read_byte) -> None:
        """Read and validate a single acknowledgement byte."""
        ack = read_byte()
        if ack == ACK_OK:
            return
        if ack is None or ack == b"":
            raise SCPError("peer closed the connection unexpectedly")
        if ack[0:1] == ACK_WARNING:
            raise SCPError(f"peer reported a warning: {ack[1:]!r}")
        if ack[0:1] == ACK_ERROR:
            raise SCPError(f"peer reported an error: {ack[1:]!r}")
        raise SCPError(f"unexpected acknowledgement byte: {ack!r}")


def build_source_tree(
    root: str,
    *,
    recursive: bool = True,
    preserve_times: bool = False,
) -> Iterator[Tuple[str, bool, int, float]]:
    """Yield ``(relative_path, is_dir, size, mtime)`` for everything under *root*.

    This helper is used by the client to build the manifest of a transfer and
    by the tests to verify the sender walks the tree in a deterministic order.
    """
    root = os.path.abspath(root)
    if os.path.isfile(root):
        yield os.path.basename(root), False, os.path.getsize(root), os.path.getmtime(root)
        return

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        filenames.sort()
        for name in dirnames:
            full = os.path.join(dirpath, name)
            yield os.path.relpath(full, root).replace(os.sep, "/"), True, 0, os.path.getmtime(full)
            if not recursive:
                dirnames.remove(name)
        for name in filenames:
            full = os.path.join(dirpath, name)
            yield os.path.relpath(full, root).replace(os.sep, "/"), False, os.path.getsize(full), os.path.getmtime(full)


def join_remote(base: str, name: str) -> str:
    """Join a remote base directory and a relative name using POSIX rules."""
    return posixpath.join(base or "/", name)


__all__ = [
    "ACK_ERROR",
    "ACK_OK",
    "ACK_WARNING",
    "EOF_MARKER",
    "MAX_FILE_SIZE",
    "MAX_MESSAGE_LENGTH",
    "MessageType",
    "ScpMessage",
    "ScpSink",
    "ScpSource",
    "build_source_tree",
    "decode_message",
    "encode_ack",
    "encode_directory_message",
    "encode_end_directory_message",
    "encode_file_message",
    "encode_time_message",
    "join_remote",
]
