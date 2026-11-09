"""Tests for the SCP client and server using an in-memory channel.

The tests use a small fake channel that implements the parts of the
``paramiko.Channel`` interface the SCP code relies on.  This exercises the
real client and server code paths without needing a network connection.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from btl.scp.client import SCPServer  # noqa: E402
from btl.scp.protocol import ACK_OK, EOF_MARKER  # noqa: E402
from btl.utils.errors import ValidationError  # noqa: E402


class FakeChannel:
    """A minimal stand-in for ``paramiko.Channel``.

    The data is delivered in *segments*, the way TCP delivers packets.  The
    test provides the segments, so a control message and the file body that
    follows it can be delivered separately, which is what happens on a real
    connection.
    """

    def __init__(self, *segments: bytes) -> None:
        self._segments = [bytearray(s) for s in segments]
        self._index = 0
        self.written = bytearray()

    def recv(self, size: int) -> bytes:
        while self._index < len(self._segments):
            segment = self._segments[self._index]
            if segment:
                chunk = bytes(segment[:size])
                del segment[:size]
                return chunk
            self._index += 1
        return b""

    def sendall(self, data: bytes) -> None:
        self.written.extend(data)

    def close(self) -> None:
        pass

    def settimeout(self, timeout) -> None:
        pass


class TestSCPServerPolicy:
    def test_accepts_a_file(self, tmp_path):
        dest = tmp_path / "dest"
        server = SCPServer(str(dest))

        # The control message and the file body arrive as separate segments.
        channel = FakeChannel(b"C0644 5 hello.txt\n", b"hello" + EOF_MARKER)

        written = server.handle_channel(channel)
        assert len(written) == 1
        assert (dest / "hello.txt").read_bytes() == b"hello"

    def test_rejects_a_disallowed_extension(self, tmp_path):
        dest = tmp_path / "dest"
        server = SCPServer(str(dest), allowed_extensions=[".txt"])

        channel = FakeChannel(b"C0644 5 evil.sh\n", b"hello" + EOF_MARKER)

        with pytest.raises(ValidationError):
            server.handle_channel(channel)

        assert not (dest / "evil.sh").exists()

    def test_allows_a_permitted_extension(self, tmp_path):
        dest = tmp_path / "dest"
        server = SCPServer(str(dest), allowed_extensions=[".txt"])

        channel = FakeChannel(b"C0644 5 ok.txt\n", b"hello" + EOF_MARKER)

        written = server.handle_channel(channel)
        assert len(written) == 1

    def test_the_extension_check_is_case_insensitive(self, tmp_path):
        dest = tmp_path / "dest"
        server = SCPServer(str(dest), allowed_extensions=[".txt"])

        channel = FakeChannel(b"C0644 5 OK.TXT\n", b"hello" + EOF_MARKER)

        written = server.handle_channel(channel)
        assert len(written) == 1

    def test_no_policy_accepts_everything(self, tmp_path):
        dest = tmp_path / "dest"
        server = SCPServer(str(dest))

        channel = FakeChannel(b"C0644 5 any.bin\n", b"hello" + EOF_MARKER)

        written = server.handle_channel(channel)
        assert len(written) == 1

    def test_rejects_a_traversal_attempt(self, tmp_path):
        dest = tmp_path / "dest"
        server = SCPServer(str(dest))

        channel = FakeChannel(b"C0644 5 ../evil.txt\n", b"hello" + EOF_MARKER)

        with pytest.raises(Exception):
            server.handle_channel(channel)

        assert not (tmp_path / "evil.txt").exists()

    def test_sends_the_ready_byte_first(self, tmp_path):
        dest = tmp_path / "dest"
        server = SCPServer(str(dest))

        channel = FakeChannel(b"C0644 5 hello.txt\n", b"hello" + EOF_MARKER)
        server.handle_channel(channel)

        # The sink always announces readiness with a single zero byte.
        assert channel.written[0:1] == ACK_OK

    def test_creates_a_directory(self, tmp_path):
        dest = tmp_path / "dest"
        server = SCPServer(str(dest))

        channel = FakeChannel(b"D0755 0 sub\n", b"E\n")

        server.handle_channel(channel)
        assert (dest / "sub").is_dir()

    def test_receives_a_nested_file(self, tmp_path):
        dest = tmp_path / "dest"
        server = SCPServer(str(dest))

        channel = FakeChannel(
            b"D0755 0 sub\n",
            b"C0644 3 a.txt\n",
            b"abc" + EOF_MARKER,
            b"E\n",
        )

        server.handle_channel(channel)
        assert (dest / "sub" / "a.txt").read_bytes() == b"abc"


class TestDownloadDestination:
    """The destination of a download has to be prepared correctly.

    The SCP sink resolves every incoming name against its destination
    *directory*.  A single file download therefore has to be written into
    the parent directory and renamed afterwards, otherwise the requested
    name would end up being a directory.
    """

    def _client(self):
        from btl.scp.client import SCPClient

        return SCPClient.__new__(SCPClient)

    def test_a_single_file_is_written_into_its_parent(self, tmp_path):
        target = tmp_path / "wanted.txt"
        destination, rename = self._client()._prepare_destination(
            str(target), "/srv/remote.txt", recursive=False
        )
        assert destination == str(tmp_path)
        assert rename == "wanted.txt"

    def test_an_existing_directory_keeps_the_server_name(self, tmp_path):
        destination, rename = self._client()._prepare_destination(
            str(tmp_path), "/srv/remote.txt", recursive=False
        )
        assert destination == str(tmp_path)
        assert rename is None

    def test_a_recursive_download_uses_the_directory_as_is(self, tmp_path):
        destination, rename = self._client()._prepare_destination(
            str(tmp_path / "tree"), "/srv/tree", recursive=True
        )
        assert destination == str(tmp_path / "tree")
        assert rename is None

    def test_the_downloaded_file_is_renamed(self, tmp_path):
        source = tmp_path / "remote.txt"
        source.write_text("data")
        target = tmp_path / "wanted.txt"

        written = self._client()._apply_rename(
            [str(source)], str(tmp_path), "wanted.txt"
        )

        assert written == [str(target)]
        assert target.read_text() == "data"
        assert not source.exists()
