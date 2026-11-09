"""Unit tests for the pure SCP protocol codec."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from btl.scp.protocol import (  # noqa: E402
    ACK_ERROR,
    ACK_OK,
    ACK_WARNING,
    MessageType,
    ScpSink,
    ScpSource,
    decode_message,
    encode_ack,
    encode_directory_message,
    encode_end_directory_message,
    encode_file_message,
    encode_time_message,
)
from btl.utils.errors import SCPError  # noqa: E402


class TestEncoding:
    def test_encode_file_message(self):
        assert encode_file_message(0o644, 12, "a.txt") == b"C0644 12 a.txt\n"

    def test_encode_directory_message(self):
        assert encode_directory_message(0o755, "docs") == b"D0755 0 docs\n"

    def test_encode_end_directory(self):
        assert encode_end_directory_message() == b"E\n"

    def test_encode_time_message(self):
        assert encode_time_message(1000.7, 2000.2) == b"T1000 0 2000 0\n"

    def test_encode_ack(self):
        assert encode_ack(0) == ACK_OK
        assert encode_ack(1, "warn") == ACK_WARNING + b"warn\n"
        assert encode_ack(2, "boom") == ACK_ERROR + b"boom\n"

    def test_encode_rejects_invalid_status(self):
        with pytest.raises(ValueError):
            encode_ack(7)


class TestDecoding:
    def test_decode_file(self):
        msg = decode_message(b"C0644 299 group")
        assert msg.type is MessageType.FILE
        assert msg.mode == 0o644
        assert msg.size == 299
        assert msg.name == "group"

    def test_decode_directory(self):
        msg = decode_message(b"D0755 0 docs")
        assert msg.type is MessageType.DIRECTORY
        assert msg.mode == 0o755
        assert msg.name == "docs"

    def test_decode_end_directory(self):
        msg = decode_message(b"E")
        assert msg.type is MessageType.END_DIRECTORY

    def test_decode_time(self):
        msg = decode_message(b"T1183828267 0 1183828267 0")
        assert msg.type is MessageType.TIME
        assert msg.mtime == 1183828267
        assert msg.atime == 1183828267

    def test_decode_name_with_spaces(self):
        msg = decode_message(b"C0644 10 my file name.txt")
        assert msg.name == "my file name.txt"
        assert msg.size == 10

    def test_decode_escaped_name(self):
        msg = decode_message(b"C0644 10 bad^Jname.txt")
        assert msg.name == "bad\nname.txt"

    def test_decode_rejects_unknown_type(self):
        with pytest.raises(SCPError):
            decode_message(b"X0644 10 name")

    def test_decode_rejects_bad_mode(self):
        with pytest.raises(SCPError):
            decode_message(b"C09ZZ 10 name")

    def test_decode_rejects_bad_size(self):
        with pytest.raises(SCPError):
            decode_message(b"C0644 abc name")

    def test_decode_rejects_oversize(self):
        with pytest.raises(SCPError):
            decode_message(b"C0644 99999999999999999999 name")

    def test_decode_rejects_empty(self):
        with pytest.raises(SCPError):
            decode_message(b"")

    def test_roundtrip_escaped(self):
        original = "weird\tname^with.txt"
        encoded = encode_file_message(0o644, 1, original)
        decoded = decode_message(encoded.rstrip(b"\n"))
        assert decoded.name == original


class TestScpSink:
    def test_receives_single_file(self, tmp_path):
        dest = tmp_path / "dest"
        dest.mkdir()
        sink = ScpSink(str(dest))

        lines = [b"C0644 5 hello.txt"]
        payloads = [b"hello"]

        def read_line():
            return lines.pop(0) if lines else None

        def read_exactly(n):
            return payloads.pop(0) if payloads else b""

        sent = []
        written = sink.receive(read_line, read_exactly, sent.append)

        assert written == [str(dest / "hello.txt")]
        assert (dest / "hello.txt").read_bytes() == b"hello"
        assert sent[0] == ACK_OK
        assert sent[-1] == ACK_OK

    def test_rejects_path_traversal(self, tmp_path):
        dest = tmp_path / "dest"
        dest.mkdir()
        outside = tmp_path / "evil.txt"
        sink = ScpSink(str(dest))

        lines = [b"C0644 5 ../evil.txt"]
        payloads = [b"hello"]

        def read_line():
            return lines.pop(0) if lines else None

        def read_exactly(n):
            return payloads.pop(0) if payloads else b""

        sent = []
        with pytest.raises(SCPError):
            sink.receive(read_line, read_exactly, sent.append)

        assert not outside.exists()

    def test_rejects_absolute_path(self, tmp_path):
        dest = tmp_path / "dest"
        dest.mkdir()
        sink = ScpSink(str(dest))

        lines = [b"C0644 5 /etc/passwd"]
        payloads = [b"hello"]

        def read_line():
            return lines.pop(0) if lines else None

        def read_exactly(n):
            return payloads.pop(0) if payloads else b""

        sent = []
        with pytest.raises(SCPError):
            sink.receive(read_line, read_exactly, sent.append)

    def test_rejects_truncated_body(self, tmp_path):
        dest = tmp_path / "dest"
        dest.mkdir()
        sink = ScpSink(str(dest))

        lines = [b"C0644 100 short.txt"]
        payloads = [b"only-ten-b"]

        def read_line():
            return lines.pop(0) if lines else None

        def read_exactly(n):
            return payloads.pop(0) if payloads else b""

        sent = []
        with pytest.raises(SCPError):
            sink.receive(read_line, read_exactly, sent.append)


class TestScpSource:
    def test_sends_single_file(self, tmp_path):
        src = tmp_path / "hello.txt"
        src.write_bytes(b"hello world")

        source = ScpSource(str(src))
        sent = []
        acks = [ACK_OK] * 10

        source.send(lambda: acks.pop(0), sent.append)

        assert any(s.startswith(b"C") and s.endswith(b" hello.txt\n") for s in sent)
        assert b"hello world" in sent

    def test_sends_directory_recursively(self, tmp_path):
        tree = tmp_path / "tree"
        (tree / "sub").mkdir(parents=True)
        (tree / "a.txt").write_bytes(b"aaa")
        (tree / "sub" / "b.txt").write_bytes(b"bb")

        source = ScpSource(str(tree), recursive=True)
        sent = []
        acks = [ACK_OK] * 50

        source.send(lambda: acks.pop(0), sent.append)

        assert any(s.startswith(b"D") and s.endswith(b" tree\n") for s in sent)
        assert any(s.startswith(b"D") and s.endswith(b" sub\n") for s in sent)
        assert b"E\n" in sent
        assert b"aaa" in sent
        assert b"bb" in sent

    def test_refuses_directory_without_recursive(self, tmp_path):
        tree = tmp_path / "tree"
        tree.mkdir()

        source = ScpSource(str(tree), recursive=False)
        acks = [ACK_OK]
        with pytest.raises(SCPError):
            source.send(lambda: acks.pop(0), lambda b: None)

    def test_refuses_when_peer_rejects(self, tmp_path):
        src = tmp_path / "a.txt"
        src.write_bytes(b"x")
        source = ScpSource(str(src))
        with pytest.raises(SCPError):
            source.send(lambda: ACK_ERROR + b"no\n", lambda b: None)
