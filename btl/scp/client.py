"""SCP client and server built on the project SSH transport.

The client speaks the scp1 protocol to a remote ``scp -t`` process and can
also pull files by driving a remote ``scp -f`` process.  The server exposes a
``scp -t`` sink over an SSH channel, which is what a peer needs to push files
into this host.
"""

from __future__ import annotations

import os
import posixpath
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

import paramiko

from ..ssh.connection import SSHConnection
from ..utils.errors import SCPError, ValidationError
from ..utils.logging import get_logger
from .protocol import (
    ACK_ERROR,
    ACK_OK,
    ACK_WARNING,
    EOF_MARKER,
    MAX_FILE_SIZE,
    MessageType,
    ScpSink,
    decode_message,
    encode_file_message,
    encode_time_message,
)

logger = get_logger("scp.client")


@dataclass
class TransferResult:
    """Summary of a completed transfer."""

    transferred: List[str]
    bytes_transferred: int = 0
    direction: str = "put"

    @property
    def count(self) -> int:
        """Number of files transferred."""
        return len(self.transferred)


class ChannelReader:
    """A buffered reader over an SSH channel.

    The SCP protocol mixes line oriented control messages with length driven
    file bodies on a *single* byte stream.  Both have to be served from the
    same buffer, otherwise bytes that arrive together with a control line
    would be lost between the two readers.
    """

    def __init__(self, channel: paramiko.Channel, block_size: int = 32 * 1024) -> None:
        self.channel = channel
        self.block_size = block_size
        self._buffer = bytearray()

    def _fill(self) -> bool:
        """Read more bytes into the buffer; return ``False`` at end of stream."""
        chunk = self.channel.recv(self.block_size)
        if not chunk:
            return False
        self._buffer.extend(chunk)
        return True

    def read_line(self) -> Optional[bytes]:
        """Read one newline terminated line, or ``None`` at end of stream."""
        while True:
            index = self._buffer.find(b"\n")
            if index >= 0:
                line = bytes(self._buffer[:index])
                del self._buffer[: index + 1]
                return line
            if not self._fill():
                if self._buffer:
                    line = bytes(self._buffer)
                    self._buffer.clear()
                    return line
                return None

    def read_exactly(self, count: int) -> bytes:
        """Read exactly *count* bytes, or fewer at end of stream."""
        while len(self._buffer) < count:
            if not self._fill():
                break
        chunk = bytes(self._buffer[:count])
        del self._buffer[: len(chunk)]
        return chunk

    def read_byte(self) -> bytes:
        """Read a single byte, or an empty result at end of stream."""
        return self.read_exactly(1)


class SCPClient:
    """Copy files to and from a remote host over SSH using the scp protocol.

    The client drives the remote side by asking it to run ``scp -f`` (source
    mode, when downloading) or ``scp -t`` (sink mode, when uploading).
    """

    def __init__(
        self,
        connection: SSHConnection,
        *,
        remote_scp_path: str = "scp",
        block_size: int = 32 * 1024,
        timeout: Optional[float] = None,
    ) -> None:
        self.connection = connection
        self.remote_scp_path = remote_scp_path
        self.block_size = block_size
        self.timeout = timeout

    # -- helpers ---------------------------------------------------------

    def _open_channel(self) -> paramiko.Channel:
        """Open a session channel with a receive timeout applied."""
        channel = self.connection.open_session()
        if self.timeout is not None:
            channel.settimeout(self.timeout)
        return channel

    def _make_reader(self, channel: paramiko.Channel) -> ChannelReader:
        """Return a buffered reader over *channel*."""
        return ChannelReader(channel, self.block_size)

    def _make_line_reader(self, channel: paramiko.Channel) -> Callable[[], Optional[bytes]]:
        """Return a callable that reads one newline terminated line."""
        reader = self._make_reader(channel)
        return reader.read_line

    def _make_byte_reader(self, channel: paramiko.Channel) -> Callable[[], bytes]:
        """Return a callable that reads a single acknowledgement byte."""
        reader = self._make_reader(channel)
        return reader.read_byte

    def _quote_remote(self, path: str) -> str:
        """Quote a remote path for safe use inside a shell command."""
        if not path:
            raise ValidationError("remote path must not be empty")
        # The remote command is interpreted by the remote shell, so the path
        # is wrapped in single quotes and embedded quotes are escaped.
        return "'" + path.replace("'", "'\\''") + "'"

    # -- upload ----------------------------------------------------------

    def put(
        self,
        local_path: str,
        remote_path: str,
        *,
        recursive: bool = False,
        preserve_times: bool = False,
        preserve_mode: bool = True,
    ) -> TransferResult:
        """Upload a local file or directory to the remote host.

        Args:
            local_path: The local file or directory to send.
            remote_path: The destination path on the remote host.
            recursive: Recurse into directories.
            preserve_times: Send the original modification times.
            preserve_mode: Send the original permission bits.

        Returns:
            A :class:`TransferResult` describing the transfer.
        """
        local_path = os.path.abspath(local_path)
        if not os.path.exists(local_path):
            raise ValidationError(f"local path does not exist: {local_path}")

        is_dir = os.path.isdir(local_path)
        if is_dir and not recursive:
            raise ValidationError(
                f"{local_path} is a directory; pass recursive=True to copy it"
            )

        target = remote_path
        if is_dir and not target.endswith("/"):
            target = target + "/"

        command = f"{self.remote_scp_path} -t"
        if preserve_times:
            command += " -p"
        if is_dir:
            command += " -r"
        command += f" {self._quote_remote(target)}"

        channel = self._open_channel()
        try:
            channel.exec_command(command)
            self._sink_to_peer(local_path, channel, recursive, preserve_times, preserve_mode)
        finally:
            channel.close()

        return TransferResult(
            transferred=[os.path.basename(local_path)], direction="put"
        )

    def _sink_to_peer(
        self,
        local_path: str,
        channel: paramiko.Channel,
        recursive: bool,
        preserve_times: bool,
        preserve_mode: bool,
    ) -> None:
        """Act as the SCP source, pushing *local_path* to the peer."""
        read_byte = self._make_byte_reader(channel)
        write = channel.sendall

        # The remote sink announces readiness with a single zero byte before
        # it accepts anything.  That byte is *not* an acknowledgement of a
        # control message, so it has to be consumed separately; otherwise the
        # first acknowledgement would be off by one.
        ready = read_byte()
        if not ready:
            raise SCPError("the remote peer closed the connection unexpectedly")
        if ready[0:1] == ACK_ERROR:
            raise SCPError(f"the remote peer refused the transfer: {ready[1:]!r}")
        if ready[0:1] != ACK_OK:
            raise SCPError(f"unexpected ready byte from the peer: {ready!r}")

        if os.path.isdir(local_path):
            self._send_directory(
                local_path, channel, read_byte, write, preserve_times, preserve_mode
            )
        else:
            self._send_file(
                local_path,
                os.path.basename(local_path),
                channel,
                read_byte,
                write,
                preserve_times,
                preserve_mode,
            )

    def _send_file(
        self,
        path: str,
        name: str,
        channel: paramiko.Channel,
        read_byte,
        write,
        preserve_times: bool,
        preserve_mode: bool,
    ) -> None:
        """Send one regular file and wait for its acknowledgement."""
        info = os.stat(path)
        size = info.st_size
        if size > MAX_FILE_SIZE:
            raise SCPError(f"file is too large to transfer: {path}")

        if preserve_times:
            write(encode_time_message(info.st_mtime, info.st_atime))
            self._expect_ack(read_byte)

        mode = 0o644
        if preserve_mode:
            mode = info.st_mode & 0o7777
        write(encode_file_message(mode, size, name))
        self._expect_ack(read_byte)

        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(self.block_size)
                if not chunk:
                    break
                write(chunk)

        # Mark the end of the body, then wait for the peer to confirm.
        write(EOF_MARKER)
        self._expect_ack(read_byte)

    def _send_directory(
        self,
        path: str,
        channel: paramiko.Channel,
        read_byte,
        write,
        preserve_times: bool,
        preserve_mode: bool,
    ) -> None:
        """Recursively send a directory."""
        from .protocol import encode_directory_message, encode_end_directory_message

        info = os.stat(path)
        mode = info.st_mode & 0o7777 if preserve_mode else 0o755
        write(encode_directory_message(mode, os.path.basename(path)))
        self._expect_ack(read_byte)

        for entry in sorted(os.listdir(path)):
            full = os.path.join(path, entry)
            if os.path.islink(full):
                continue
            if os.path.isdir(full):
                self._send_directory(
                    full, channel, read_byte, write, preserve_times, preserve_mode
                )
            elif os.path.isfile(full):
                self._send_file(
                    full, entry, channel, read_byte, write, preserve_times, preserve_mode
                )

        write(encode_end_directory_message())
        self._expect_ack(read_byte)

    def _make_byte_reader(self, channel: paramiko.Channel) -> Callable[[], bytes]:
        """Return a callable that reads a single acknowledgement byte."""

        def read_byte() -> bytes:
            data = channel.recv(1)
            return data

        return read_byte

    def _expect_ack(self, read_byte) -> None:
        """Read and validate one acknowledgement byte."""
        ack = read_byte()
        if not ack:
            raise SCPError("peer closed the connection unexpectedly")
        if ack[0:1] == ACK_OK:
            return
        if ack[0:1] == ACK_WARNING:
            raise SCPError(f"peer reported a warning: {ack[1:]!r}")
        if ack[0:1] == ACK_ERROR:
            raise SCPError(f"peer reported an error: {ack[1:]!r}")
        raise SCPError(f"unexpected acknowledgement: {ack!r}")

    # -- download --------------------------------------------------------

    def get(
        self,
        remote_path: str,
        local_path: str,
        *,
        recursive: bool = False,
        preserve_times: bool = False,
    ) -> TransferResult:
        """Download a file or directory from the remote host.

        Args:
            remote_path: The path on the remote host.
            local_path: Where to write the downloaded content locally.  For a
                single file this is the name of the file itself; for a
                recursive download it is the directory that receives the
                tree.
            recursive: Recurse into remote directories.
            preserve_times: Restore the original modification times.

        Returns:
            A :class:`TransferResult` describing the transfer.
        """
        command = f"{self.remote_scp_path} -f"
        if preserve_times:
            command += " -p"
        if recursive:
            command += " -r"
        command += f" {self._quote_remote(remote_path)}"

        channel = self._open_channel()
        try:
            channel.exec_command(command)

            local_path = os.path.abspath(local_path)

            # The sink resolves every incoming name against its destination
            # directory, so the destination has to be a directory.  When a
            # single file is requested the directory is the parent of the
            # requested name, and the file keeps the name the caller asked
            # for instead of the name the server happens to use.
            destination, rename_to = self._prepare_destination(
                local_path, remote_path, recursive
            )
            os.makedirs(destination, exist_ok=True)

            # One reader for the whole stream: control lines and file bodies
            # share the same byte stream.
            reader = self._make_reader(channel)

            sink = ScpSink(destination, preserve_times=preserve_times)

            # The remote process runs in source mode (``scp -f``), which
            # waits for the sink's ready byte before sending anything.  The
            # sink emits that byte itself, so no byte must be consumed from
            # the remote side beforehand.
            written = sink.receive(reader.read_line, reader.read_exactly, channel.sendall)
        finally:
            channel.close()

        written = self._apply_rename(written, destination, rename_to)
        return TransferResult(transferred=written, direction="get")

    def _prepare_destination(
        self, local_path: str, remote_path: str, recursive: bool
    ) -> "Tuple[str, Optional[str]]":
        """Work out the destination directory and the final file name.

        Args:
            local_path: The absolute path the caller asked for.
            remote_path: The path that is being fetched from the server.
            recursive: Whether the transfer recurses into directories.

        Returns:
            A tuple of the destination directory and the name the single
            downloaded file has to be renamed to, or ``None`` when no rename
            is needed.
        """
        if recursive:
            # A recursive download always produces a tree, so the requested
            # path is the directory that receives it.
            return local_path, None

        if os.path.isdir(local_path):
            # An existing directory receives the file under the name the
            # server uses.
            return local_path, None

        # A single file: the sink writes into the parent directory and the
        # result is renamed to the requested name afterwards.
        parent = os.path.dirname(local_path) or os.getcwd()
        return parent, os.path.basename(local_path)

    def _apply_rename(
        self, written: "List[str]", destination: str, rename_to: Optional[str]
    ) -> "List[str]":
        """Rename the downloaded file to the requested name.

        Args:
            written: The paths that the sink produced.
            destination: The destination directory.
            rename_to: The final name, or ``None`` when nothing has to be
                renamed.

        Returns:
            The list of paths, with the rename applied.
        """
        if not rename_to or not written:
            return written

        source = written[0]
        target = os.path.join(destination, rename_to)
        if os.path.abspath(source) == os.path.abspath(target):
            return written

        try:
            if os.path.exists(target):
                os.remove(target)
            os.replace(source, target)
        except OSError:
            # The file was transferred successfully; only the rename failed.
            logger.warning("could not rename %s to %s", source, target)
            return written

        written = [target] + written[1:]
        return written


class SCPServer:
    """Accepts files pushed to this host by a remote peer.

    The server acts as the SCP sink (``scp -t``).  It is normally driven over
    an SSH channel that was created by an inbound SSH connection.
    """

    def __init__(
        self,
        destination: str,
        *,
        preserve_times: bool = False,
        preserve_mode: bool = True,
        allowed_extensions: Optional[List[str]] = None,
        max_file_size: int = MAX_FILE_SIZE,
    ) -> None:
        self.destination = os.path.abspath(destination)
        self.preserve_times = preserve_times
        self.preserve_mode = preserve_mode
        self.allowed_extensions = (
            [ext.lower() for ext in allowed_extensions] if allowed_extensions else None
        )
        self.max_file_size = max_file_size
        os.makedirs(self.destination, exist_ok=True)

    def handle_channel(self, channel: paramiko.Channel) -> List[str]:
        """Serve one SCP session on *channel*.

        Args:
            channel: The SSH channel the peer is using.

        Returns:
            The list of absolute paths that were written.
        """
        reader = ChannelReader(channel)

        sink = ScpSink(
            self.destination,
            preserve_times=self.preserve_times,
            preserve_mode=self.preserve_mode,
        )

        # The extension policy is enforced while the control messages are
        # decoded, before the file body is accepted, so an unacceptable file
        # never reaches the disk.
        def guarded_read_line() -> Optional[bytes]:
            line = reader.read_line()
            if line is None:
                return None
            self._check_line(line)
            return line

        written = sink.receive(guarded_read_line, reader.read_exactly, channel.sendall)
        return written

    def _check_line(self, line: bytes) -> None:
        """Apply the extension policy to a control message.

        Raises:
            ValidationError: If the announced file type is not allowed.
        """
        if not self.allowed_extensions:
            return

        try:
            message = decode_message(line)
        except SCPError:
            # A malformed message is handled by the sink, which reports it
            # to the peer in the proper protocol way.
            return

        if message.type is not MessageType.FILE:
            return

        _, ext = posixpath.splitext(message.name)
        if ext.lower() not in self.allowed_extensions:
            raise ValidationError(
                f"file type {ext!r} is not allowed (allowed: "
                f"{', '.join(self.allowed_extensions)})"
            )

    def _make_line_reader(self, channel: paramiko.Channel):
        """Return a callable that reads one newline terminated line."""
        reader = ChannelReader(channel)
        return reader.read_line

    def _make_reader(self, channel: paramiko.Channel):
        """Return a callable that reads exactly *n* bytes."""
        reader = ChannelReader(channel)
        return reader.read_exactly


__all__ = ["ChannelReader", "SCPClient", "SCPServer", "TransferResult"]
