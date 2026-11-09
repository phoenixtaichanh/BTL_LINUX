"""Tests for the path safety helpers."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from btl.utils.errors import ValidationError  # noqa: E402
from btl.utils.paths import (  # noqa: E402
    SafePath,
    is_within,
    normalize_remote_path,
    relative_to,
    sanitize_filename,
    validate_relative_name,
)


class TestNormalizeRemotePath:
    def test_absolute_path(self):
        assert normalize_remote_path("/srv/data") == "/srv/data"

    def test_collapses_separators(self):
        assert normalize_remote_path("/srv//data///files") == "/srv/data/files"

    def test_resolves_dot(self):
        assert normalize_remote_path("/srv/./data") == "/srv/data"

    def test_resolves_parent(self):
        assert normalize_remote_path("/srv/data/../logs") == "/srv/logs"

    def test_strips_trailing_slash(self):
        assert normalize_remote_path("/srv/data/") == "/srv/data"

    def test_root_stays_root(self):
        assert normalize_remote_path("/") == "/"

    def test_relative_is_made_absolute(self):
        assert normalize_remote_path("srv/data") == "/srv/data"

    def test_base_is_applied(self):
        assert normalize_remote_path("file.txt", base="/srv/data") == "/srv/data/file.txt"

    def test_rejects_empty(self):
        with pytest.raises(ValidationError):
            normalize_remote_path("")

    def test_rejects_none(self):
        with pytest.raises(ValidationError):
            normalize_remote_path(None)


class TestIsWithin:
    def test_direct_child(self):
        assert is_within("/srv/data", "/srv/data/file.txt")

    def test_same_path(self):
        assert is_within("/srv/data", "/srv/data")

    def test_outside(self):
        assert not is_within("/srv/data", "/srv/other/file.txt")

    def test_sibling_prefix_is_outside(self):
        # "/srv/data-old" must not be considered inside "/srv/data".
        assert not is_within("/srv/data", "/srv/data-old/file.txt")

    def test_parent_is_outside(self):
        assert not is_within("/srv/data", "/srv")

    def test_root_contains_everything(self):
        assert is_within("/", "/etc/passwd")


class TestSanitizeFilename:
    def test_strips_separators(self):
        assert "/" not in sanitize_filename("a/b")
        assert "\\" not in sanitize_filename("a\\b")

    def test_strips_traversal(self):
        result = sanitize_filename("../../etc/passwd")
        assert ".." not in result
        assert "/" not in result

    def test_removes_control_characters(self):
        assert sanitize_filename("a\x00b") == "a_b"

    def test_preserves_normal_name(self):
        assert sanitize_filename("report.pdf") == "report.pdf"

    def test_escapes_reserved_windows_name(self):
        assert sanitize_filename("CON").startswith("_")

    def test_truncates_long_name(self):
        assert len(sanitize_filename("x" * 500)) <= 255

    def test_rejects_empty(self):
        with pytest.raises(ValidationError):
            sanitize_filename("")


class TestValidateRelativeName:
    def test_accepts_normal_name(self):
        assert validate_relative_name("file.txt") == "file.txt"

    def test_rejects_parent_traversal(self):
        with pytest.raises(ValidationError):
            validate_relative_name("../evil")

    def test_rejects_slash(self):
        with pytest.raises(ValidationError):
            validate_relative_name("dir/file.txt")

    def test_rejects_backslash(self):
        with pytest.raises(ValidationError):
            validate_relative_name("dir\\file.txt")

    def test_rejects_absolute(self):
        with pytest.raises(ValidationError):
            validate_relative_name("/etc/passwd")

    def test_rejects_dot(self):
        with pytest.raises(ValidationError):
            validate_relative_name(".")

    def test_rejects_empty(self):
        with pytest.raises(ValidationError):
            validate_relative_name("")

    def test_rejects_nul(self):
        with pytest.raises(ValidationError):
            validate_relative_name("a\x00b")


class TestSafePath:
    def test_resolves_inside_root(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        result = SafePath.resolve(str(root), "sub/file.txt")
        assert result.path.endswith(os.path.join("sub", "file.txt"))
        assert result.path.startswith(str(root))

    def test_absolute_is_confined_to_root(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        result = SafePath.resolve(str(root), "/etc/passwd")
        assert result.path.startswith(str(root))

    def test_rejects_escape(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        with pytest.raises(ValidationError):
            SafePath.resolve(str(root), "../../etc/passwd")

    def test_rejects_symlink_escape(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        outside = tmp_path / "outside.txt"
        outside.write_text("secret")
        link = root / "link.txt"
        try:
            os.symlink(outside, link)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are not supported here")
        with pytest.raises(ValidationError):
            SafePath.resolve(str(root), "link.txt")

    def test_relative_to_root(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        result = SafePath.resolve(str(root), "sub/file.txt")
        assert result.relative_to_root() == "sub/file.txt"

    def test_name_and_parent(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        result = SafePath.resolve(str(root), "sub/file.txt")
        assert result.name == "file.txt"
        assert result.parent.endswith(os.path.join("root", "sub"))

    def test_must_exist(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        with pytest.raises(ValidationError):
            SafePath.resolve(str(root), "missing.txt", must_exist=True)

    def test_rejects_nul(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        with pytest.raises(ValidationError):
            SafePath.resolve(str(root), "a\x00b")


class TestRelativeTo:
    def test_inside(self):
        assert relative_to("/srv/data", "/srv/data/file.txt") == "file.txt"

    def test_outside_falls_back(self):
        assert relative_to("/srv/data", "/etc/passwd") == "/etc/passwd"
