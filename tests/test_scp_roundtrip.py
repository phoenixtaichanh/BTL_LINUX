"""Round trip tests between the SCP source and the SCP sink.

The SCP protocol is strictly lock stepped: the source sends one control
message and waits for its acknowledgement before sending the next one.  A
test harness therefore has to drive both halves concurrently, which is what
these tests do with a pair of blocking pipes and two threads.

This mirrors a real SSH channel closely enough to exercise the protocol.
"""

from __future__ import annotations

import os
import queue
import sys
import threading


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from btl.scp.protocol import (  # noqa: E402
    ScpSink,
    ScpSource,
)


class BytePipe:
    """A blocking, unidirectional byte pipe.

    Bytes written to one end become readable at the other end.  A reader
    that asks for more bytes than are available blocks until they arrive.
    """

    def __init__(self) -> None:
        self._queue: "queue.Queue[bytes]" = queue.Queue()
        self._buffer = bytearray()
        self._eof = False

    def write(self, data: bytes) -> None:
        """Write *data* to the pipe."""
        self._queue.put(data)

    def close(self) -> None:
        """Signal that no more data will be written."""
        self._queue.put(b"")

    def _fill(self) -> bool:
        """Read the next chunk from the queue; ``False`` at end of stream."""
        chunk = self._queue.get()
        if not chunk:
            self._eof = True
            return False
        self._buffer.extend(chunk)
        return True

    def read(self, count: int) -> bytes:
        """Read up to *count* bytes, blocking until at least one is available."""
        while not self._buffer:
            if not self._fill():
                return b""
        chunk = bytes(self._buffer[:count])
        del self._buffer[:count]
        return chunk

    def read_byte(self) -> bytes:
        """Read exactly one byte, blocking until it arrives."""
        return self.read(1)

    def read_line(self):
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


class Channel:
    """The two pipes that connect a source and a sink."""

    def __init__(self) -> None:
        self.to_sink = BytePipe()
        self.to_source = BytePipe()


def run_transfer(source_path: str, destination: str, *, recursive: bool = True):
    """Run a full source to sink transfer and return the written paths."""
    channel = Channel()
    source = ScpSource(source_path, recursive=recursive)
    sink = ScpSink(destination)

    errors: "list[BaseException]" = []

    def run_sink() -> None:
        try:
            sink.receive(
                channel.to_sink.read_line,
                channel.to_sink.read,
                channel.to_source.write,
            )
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller
            errors.append(exc)
        finally:
            channel.to_source.close()

    thread = threading.Thread(target=run_sink, daemon=True)
    thread.start()

    try:
        # The sink announces readiness with a single zero byte, which the
        # source consumes before sending anything.
        source.send(channel.to_source.read_byte, channel.to_sink.write)
    finally:
        channel.to_sink.close()
        thread.join(timeout=10)

    if errors:
        raise errors[0]
    return channel


class TestRoundTrip:
    def test_single_file(self, tmp_path):
        src = tmp_path / "hello.txt"
        src.write_bytes(b"hello world")

        dest = tmp_path / "dest"
        dest.mkdir()

        run_transfer(str(src), str(dest), recursive=False)

        assert (dest / "hello.txt").read_bytes() == b"hello world"

    def test_empty_file(self, tmp_path):
        src = tmp_path / "empty.txt"
        src.write_bytes(b"")

        dest = tmp_path / "dest"
        dest.mkdir()

        run_transfer(str(src), str(dest), recursive=False)

        assert (dest / "empty.txt").read_bytes() == b""

    def test_file_with_binary_content(self, tmp_path):
        src = tmp_path / "binary.bin"
        payload = bytes(range(256)) * 8
        src.write_bytes(payload)

        dest = tmp_path / "dest"
        dest.mkdir()

        run_transfer(str(src), str(dest), recursive=False)

        assert (dest / "binary.bin").read_bytes() == payload

    def test_large_file(self, tmp_path):
        src = tmp_path / "large.bin"
        payload = os.urandom(300 * 1024)
        src.write_bytes(payload)

        dest = tmp_path / "dest"
        dest.mkdir()

        run_transfer(str(src), str(dest), recursive=False)

        assert (dest / "large.bin").read_bytes() == payload

    def test_directory_tree(self, tmp_path):
        tree = tmp_path / "tree"
        (tree / "sub" / "deeper").mkdir(parents=True)
        (tree / "a.txt").write_bytes(b"aaa")
        (tree / "sub" / "b.txt").write_bytes(b"bb")
        (tree / "sub" / "deeper" / "c.txt").write_bytes(b"c")

        dest = tmp_path / "dest"
        dest.mkdir()

        run_transfer(str(tree), str(dest))

        assert (dest / "tree" / "a.txt").read_bytes() == b"aaa"
        assert (dest / "tree" / "sub" / "b.txt").read_bytes() == b"bb"
        assert (dest / "tree" / "sub" / "deeper" / "c.txt").read_bytes() == b"c"

    def test_files_land_in_the_right_directory(self, tmp_path):
        tree = tmp_path / "tree"
        (tree / "sub").mkdir(parents=True)
        (tree / "top.txt").write_bytes(b"top")
        (tree / "sub" / "nested.txt").write_bytes(b"nested")

        dest = tmp_path / "dest"
        dest.mkdir()

        run_transfer(str(tree), str(dest))

        # The nested file must be inside "sub", not next to the top level one.
        assert (dest / "tree" / "top.txt").exists()
        assert (dest / "tree" / "sub" / "nested.txt").exists()
        assert not (dest / "tree" / "nested.txt").exists()

    def test_file_with_a_space_in_the_name(self, tmp_path):
        src = tmp_path / "my file.txt"
        src.write_bytes(b"spaced")

        dest = tmp_path / "dest"
        dest.mkdir()

        run_transfer(str(src), str(dest), recursive=False)

        assert (dest / "my file.txt").read_bytes() == b"spaced"

    def test_multiple_files_in_one_directory(self, tmp_path):
        tree = tmp_path / "tree"
        tree.mkdir()
        for index in range(5):
            (tree / f"file{index}.txt").write_bytes(f"content{index}".encode())

        dest = tmp_path / "dest"
        dest.mkdir()

        run_transfer(str(tree), str(dest))

        for index in range(5):
            assert (dest / "tree" / f"file{index}.txt").read_bytes() == (
                f"content{index}".encode()
            )

    def test_a_directory_that_is_empty(self, tmp_path):
        tree = tmp_path / "tree"
        (tree / "empty").mkdir(parents=True)

        dest = tmp_path / "dest"
        dest.mkdir()

        run_transfer(str(tree), str(dest))

        assert (dest / "tree" / "empty").is_dir()
