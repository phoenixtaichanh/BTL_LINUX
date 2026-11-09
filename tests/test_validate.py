"""Tests for the sshd configuration validator."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from btl.security.sshd_config import SSHDPolicy  # noqa: E402
from btl.security.validate import (  # noqa: E402
    ALLOWED_DIRECTIVES,
    known_directives,
    parse_config,
    validate_config,
)
from btl.utils.errors import ConfigError  # noqa: E402


class TestParseConfig:
    def test_parses_directives(self):
        directives = parse_config("Port 2222\nPasswordAuthentication no\n")
        assert directives[0][0] == "port"
        assert directives[0][1] == "2222"
        assert directives[1][0] == "passwordauthentication"

    def test_skips_comments_and_blanks(self):
        directives = parse_config("# a comment\n\nPort 22\n")
        assert len(directives) == 1

    def test_skips_match_markers(self):
        directives = parse_config("Match User alice\n    ChrootDirectory /x\n")
        assert directives[0][0] == "chrootdirectory"

    def test_records_line_numbers(self):
        directives = parse_config("# c\nPort 22\n")
        assert directives[0][2] == 2


class TestValidateConfig:
    def test_accepts_the_generated_config(self):
        assert validate_config(SSHDPolicy().to_config()) == []

    def test_accepts_the_generated_match_block(self):
        block = SSHDPolicy().to_sftp_match_block(["alice"])
        assert validate_config(block) == []

    def test_rejects_an_unknown_directive(self):
        with pytest.raises(ConfigError) as excinfo:
            validate_config("Frobnicate yes\n")
        assert "unknown directive" in str(excinfo.value)

    def test_rejects_a_removed_directive(self):
        # UsePrivilegeSeparation was deprecated in OpenSSH 7.5 and makes
        # sshd refuse to start on some versions.
        with pytest.raises(ConfigError):
            validate_config("UsePrivilegeSeparation yes\n")

    def test_rejects_a_nonexistent_directive(self):
        # LoginFailedAttempts does not exist in any OpenSSH release.
        with pytest.raises(ConfigError):
            validate_config("LoginFailedAttempts 3\n")

    def test_rejects_a_version_specific_directive(self):
        # PerSourcePenalties only exists from OpenSSH 9.8 onwards.
        with pytest.raises(ConfigError):
            validate_config("PerSourcePenalties yes\n")

    def test_rejects_a_bad_value(self):
        with pytest.raises(ConfigError) as excinfo:
            validate_config("PasswordAuthentication maybe\n")
        assert "expected one of" in str(excinfo.value)

    def test_accepts_case_insensitive_values(self):
        assert validate_config("LogLevel VERBOSE\n") == []
        assert validate_config("LogLevel verbose\n") == []

    def test_accepts_multiple_values(self):
        assert validate_config("AllowGroups sshusers ops\n") == []

    def test_rejects_a_bad_value_in_a_list(self):
        # "PermitTTY" only accepts yes or no.
        with pytest.raises(ConfigError):
            validate_config("PermitTTY maybe\n")

    def test_accepts_free_form_lists(self):
        # AllowGroups takes arbitrary group names, so it is not validated
        # against a fixed set.
        assert validate_config("AllowGroups sshusers ops\n") == []

    def test_reports_the_line_number(self):
        with pytest.raises(ConfigError) as excinfo:
            validate_config("Port 22\nFrobnicate yes\n")
        assert "line 2" in str(excinfo.value)

    def test_the_generated_config_uses_only_known_directives(self):
        allowed = set(ALLOWED_DIRECTIVES)
        for keyword, _, _ in parse_config(SSHDPolicy().to_config()):
            assert keyword in allowed


class TestKnownDirectives:
    def test_lists_the_allowed_directives(self):
        directives = known_directives()
        assert "permitrootlogin" in directives
        assert "passwordauthentication" in directives

    def test_does_not_contain_the_removed_directive(self):
        assert "useprivilegeseparation" not in ALLOWED_DIRECTIVES
