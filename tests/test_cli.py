"""Tests for the CLI, the provisioning scripts and the key loading helpers."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from btl.cli import _parse_args, _split_remote_spec, build_parser, main  # noqa: E402
from btl.provision.provisioner import (  # noqa: E402
    BANNER_TEXT,
    JAIL_BASE,
    ProvisionPlan,
    SSH_GROUP,
    build_admin_script,
    build_apply_script,
    build_install_script,
    build_sftp_script,
    scp_upload_script,
)
from btl.security.sshd_config import SSHDPolicy  # noqa: E402
from btl.utils.errors import AuthError, ConfigError  # noqa: E402


class TestParser:
    def test_all_subcommands_exist(self):
        parser = build_parser()
        actions = [
            action
            for action in parser._actions
            if getattr(action, "choices", None) and "ssh" in (action.choices or {})
        ]
        assert actions, "no subcommands were registered"
        choices = set(actions[0].choices.keys())
        assert {
            "ssh",
            "scp",
            "sftp",
            "hostkey",
            "audit",
            "render",
            "provision",
            "gui",
        } <= choices

    def test_ssh_takes_a_positional_host(self):
        args = build_parser().parse_args(["ssh", "example.com", "uptime"])
        assert args.host == "example.com"
        assert args.command == "uptime"

    def test_provision_takes_host_as_an_option(self):
        args = build_parser().parse_args(
            ["provision", "--host", "example.com", "--admin-users", "alice"]
        )
        assert args.host == "example.com"
        assert args.admin_users == "alice"

    def test_scp_has_no_conflicting_short_option(self):
        args = build_parser().parse_args(
            ["scp", "example.com", "local.txt", "remote.txt"]
        )
        assert args.port == 22
        assert args.recursive is False

    def test_render_parses_groups(self):
        args = build_parser().parse_args(
            ["render", "sshd", "--groups", "ops,sshusers"]
        )
        assert args.groups == "ops,sshusers"

    def test_the_gui_binds_to_the_loopback_address_by_default(self):
        args = build_parser().parse_args(["gui"])
        assert args.host == "127.0.0.1"
        assert args.port == 8765
        assert args.open is False

    def test_the_gui_accepts_an_address_and_a_port(self):
        args = build_parser().parse_args(
            ["gui", "--host", "0.0.0.0", "--port", "9000", "--open"]
        )
        assert args.host == "0.0.0.0"
        assert args.port == 9000
        assert args.open is True


class TestIntermixedArguments:
    """Options may follow the positional arguments.

    ``argparse`` stops assigning positionals when it meets an option, so
    ``btl ssh host -u user uptime`` used to fail with "unrecognized
    arguments".  That is the natural way to write an SSH command line, so
    the parser has to cope with it.
    """

    def _parse(self, argv):
        return _parse_args(build_parser(), list(argv))

    def test_ssh_with_options_before_the_command(self):
        args = self._parse(["ssh", "example.com", "-u", "alice", "uptime"])
        assert args.host == "example.com"
        assert args.user == "alice"
        assert args.command == "uptime"

    def test_ssh_with_options_after_the_command(self):
        args = self._parse(["ssh", "example.com", "uptime", "-u", "alice"])
        assert args.host == "example.com"
        assert args.user == "alice"
        assert args.command == "uptime"

    def test_ssh_without_a_command(self):
        args = self._parse(["ssh", "example.com", "-u", "alice", "--info"])
        assert args.host == "example.com"
        assert args.command is None
        assert args.info is True

    def test_scp_with_options_in_the_middle(self):
        args = self._parse(
            ["scp", "example.com", "-u", "alice", "./a.txt", "/home/alice/"]
        )
        assert args.host == "example.com"
        assert args.local_path == "./a.txt"
        assert args.remote_path == "/home/alice/"

    def test_scp_recursive_with_options_in_the_middle(self):
        args = self._parse(
            ["scp", "example.com", "-u", "alice", "-r", "./data", "/home/alice/"]
        )
        assert args.local_path == "./data"
        assert args.remote_path == "/home/alice/"
        assert args.recursive is True

    def test_sftp_upload_with_options_in_the_middle(self):
        args = self._parse(
            ["sftp", "example.com", "-u", "bob", "--upload", "./a.txt", "/upload/a.txt"]
        )
        assert args.host == "example.com"
        assert args.local_path == "./a.txt"
        assert args.remote_path == "/upload/a.txt"
        assert args.upload is True

    def test_hostkey_with_the_option_after_the_host(self):
        args = self._parse(
            ["hostkey", "add", "example.com", "--key-file", "./host.pub"]
        )
        assert args.action == "add"
        assert args.hostname == "example.com"
        assert args.key_file == "./host.pub"

    def test_too_many_leftovers_are_rejected(self):
        with pytest.raises(SystemExit):
            self._parse(["ssh", "example.com", "one", "two", "three"])


class TestProvisionPlan:
    def _plan(self):
        plan = ProvisionPlan()
        plan.admin_users = ["alice"]
        plan.sftp_users = ["bob"]
        return plan

    def test_requires_an_account(self):
        with pytest.raises(ConfigError):
            ProvisionPlan().validate()

    def test_renders_every_file(self):
        plan = self._plan()
        scripts = plan.render_scripts()
        assert "/etc/ssh/sshd_config.d/00-btl-hardening.conf" in scripts
        assert "/etc/ssh/sshd_config.d/10-btl-sftp.conf" in scripts
        assert "/etc/fail2ban/jail.d/btl-sshd.local" in scripts
        assert "/etc/audit/rules.d/50-btl.rules" in scripts
        assert "/etc/ssh/banner.txt" in scripts

    def test_sshd_file_contains_the_hardening_directives(self):
        content = self._plan().render_scripts()[
            "/etc/ssh/sshd_config.d/00-btl-hardening.conf"
        ]
        assert "PermitRootLogin no" in content
        assert "PasswordAuthentication no" in content
        assert f"AllowGroups {SSH_GROUP}" in content

    def test_sftp_file_contains_the_match_block(self):
        content = self._plan().render_scripts()[
            "/etc/ssh/sshd_config.d/10-btl-sftp.conf"
        ]
        assert "Match User bob" in content
        assert f"ChrootDirectory {JAIL_BASE}/bob" in content
        assert "ForceCommand internal-sftp" in content

    def test_banner_is_not_empty(self):
        assert len(BANNER_TEXT.strip()) > 20


class TestScripts:
    def _plan(self):
        plan = ProvisionPlan()
        plan.admin_users = ["alice"]
        plan.sftp_users = ["bob"]
        return plan

    def test_admin_script_creates_the_group(self):
        script = build_admin_script(self._plan())
        assert f"getent group {SSH_GROUP}" in script
        assert "groupadd" in script
        assert "usermod -aG" in script
        assert "passwd -l" in script

    def test_admin_script_is_idempotent(self):
        script = build_admin_script(self._plan())
        # The user is only created when the account does not exist yet.
        assert "if ! id -u" in script

    def test_sftp_script_sets_the_ownership(self):
        script = build_sftp_script(self._plan())
        assert f"chown root:root {JAIL_BASE}/bob" in script
        assert f"chown bob:bob {JAIL_BASE}/bob/upload" in script
        assert "chmod 700" in script
        assert "chmod 755" in script

    def test_install_script_installs_the_packages(self):
        script = build_install_script()
        for package in ("openssh-server", "fail2ban", "ufw", "auditd"):
            assert package in script

    def test_apply_script_validates_before_reloading(self):
        script = build_apply_script(self._plan())
        # The validation has to come before the reload.
        assert script.index("sshd -t") < script.index("systemctl reload ssh")

    def test_upload_script_uses_a_heredoc(self):
        script = scp_upload_script("some content\nwith lines", "/etc/example.conf")
        assert script.startswith("cat > /tmp/btl_upload <<'")
        assert "some content" in script

    def test_upload_script_moves_the_file_into_place(self):
        # Without the final move the configuration would stay in /tmp and
        # never reach the path sshd actually reads.
        script = scp_upload_script("content", "/etc/ssh/sshd_config.d/00-btl.conf")
        assert "install -m 644 /tmp/btl_upload /etc/ssh/sshd_config.d/00-btl.conf" in script
        assert script.index("cat >") < script.index("install -m")

    def test_install_script_does_not_enable_ufw(self):
        # ufw's default incoming policy is "deny".  Enabling it before the
        # SSH rule exists would cut every remote session off.
        script = build_install_script()
        assert "systemctl enable --now ufw" not in script

    def test_admin_script_installs_the_public_keys(self):
        # Without a key the account is unusable: the password is locked and
        # password authentication is disabled.
        plan = self._plan()
        plan.admin_public_keys["alice"] = ["ssh-ed25519 AAAA test@example"]
        script = build_admin_script(plan)
        assert "authorized_keys" in script
        assert "ssh-ed25519 AAAA test@example" in script
        assert script.index("passwd -l") < script.index("authorized_keys")

    def test_admin_script_keeps_the_provisioning_account(self):
        plan = self._plan()
        plan.keep_access_user = "operator"
        script = build_admin_script(plan)
        assert f"usermod -aG {SSH_GROUP} operator" in script

    def test_sftp_script_adds_the_account_to_the_allowed_group(self):
        # AllowGroups refuses an account that is not a member, and the
        # refusal happens before the Match block is read.
        script = build_sftp_script(self._plan())
        assert f"usermod -aG {SSH_GROUP} bob" in script

    def test_sftp_script_installs_the_public_keys(self):
        plan = self._plan()
        plan.sftp_public_keys["bob"] = ["ssh-ed25519 AAAA sftp@example"]
        script = build_sftp_script(plan)
        assert "authorized_keys" in script
        assert "ssh-ed25519 AAAA sftp@example" in script

    def test_admin_script_merges_the_keys_instead_of_appending(self):
        # Appending blindly would duplicate the entries on every run, which
        # breaks the idempotence requirement of the provisioning.
        plan = self._plan()
        plan.admin_public_keys["alice"] = ["ssh-ed25519 AAAA test@example"]
        script = build_admin_script(plan)
        assert "sort -u" in script
        assert ">> \"$home_dir/.ssh/authorized_keys.new\"" in script

    def test_sftp_script_merges_the_keys_instead_of_appending(self):
        plan = self._plan()
        plan.sftp_public_keys["bob"] = ["ssh-ed25519 AAAA sftp@example"]
        script = build_sftp_script(plan)
        assert "sort -u" in script


class TestCliRender:
    def test_render_sshd_exits_cleanly(self, capsys):
        code = main(["render", "sshd"])
        assert code == 0
        assert "PermitRootLogin no" in capsys.readouterr().out
    def test_render_fail2ban(self, capsys):
        assert main(["render", "fail2ban"]) == 0
        assert "[sshd]" in capsys.readouterr().out

    def test_render_firewall(self, capsys):
        assert main(["render", "firewall"]) == 0
        assert "ufw" in capsys.readouterr().out

    def test_render_audit(self, capsys):
        assert main(["render", "audit"]) == 0
        assert "audit" in capsys.readouterr().out

    def test_render_sshd_sftp(self, capsys):
        assert main(["render", "sshd-sftp", "--sftp-users", "bob"]) == 0
        assert "Match User bob" in capsys.readouterr().out


class TestConsoleEncoding:
    def test_write_output_survives_a_narrow_console(self):
        # The Windows console still uses a legacy code page, so UTF-8 output
        # from a remote host would raise UnicodeEncodeError.
        import io

        from btl.cli import _write_output

        stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
        _write_output("xin chào\n", stream)
        assert True  # the call must not raise
    def test_write_output_passes_plain_text_through(self):
        import io

        from btl.cli import _write_output

        buffer = io.BytesIO()
        stream = io.TextIOWrapper(buffer, encoding="utf-8", newline="")
        _write_output("hello\n", stream)
        stream.flush()
        assert buffer.getvalue() == b"hello\n"


class TestServerInfoCompatibility:
    def test_negotiated_value_reads_the_modern_attributes(self):
        from btl.ssh.connection import _negotiated_value

        class FakeTransport:
            remote_cipher = "aes128-ctr"
            remote_mac = "hmac-sha2-256"

        transport = FakeTransport()
        assert _negotiated_value(transport, "cipher") == "aes128-ctr"
        assert _negotiated_value(transport, "mac") == "hmac-sha2-256"

    def test_negotiated_value_falls_back_to_the_legacy_accessors(self):
        from btl.ssh.connection import _negotiated_value

        class FakeTransport:
            def cipher(self):
                return ("chacha20-poly1305@openssh.com", "chacha20-poly1305@openssh.com", 256, "")

            def mac(self):
                return ("hmac-sha2-512-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", 256, "")

        transport = FakeTransport()
        assert _negotiated_value(transport, "cipher") == "chacha20-poly1305@openssh.com"
        assert _negotiated_value(transport, "mac") == "hmac-sha2-512-etm@openssh.com"

    def test_server_key_types_uses_the_negotiated_type(self):
        from btl.ssh.connection import _server_key_types

        class FakeTransport:
            host_key_type = "ssh-ed25519"

        assert _server_key_types(FakeTransport()) == ["ssh-ed25519"]

    def test_hostkey_list_on_an_empty_store(self, capsys, tmp_path):
        code = main(
            ["hostkey", "list", "--known-hosts", str(tmp_path / "kh")]
        )
        assert code == 0
        assert "No host keys" in capsys.readouterr().out


class TestRemoteSpec:
    """The ``[user@]host:path`` form used for remote paths."""

    def test_a_plain_path_is_kept(self):
        assert _split_remote_spec("/etc/passwd") == ("", "/etc/passwd")

    def test_a_user_at_host_spec_is_split(self):
        assert _split_remote_spec("bob@server:/etc/passwd") == (
            "bob@server",
            "/etc/passwd",
        )

    def test_a_host_only_spec_is_split(self):
        assert _split_remote_spec("server:/etc/passwd") == (
            "server",
            "/etc/passwd",
        )

    def test_an_empty_path_becomes_the_root(self):
        assert _split_remote_spec("bob@server:") == ("bob@server", "/")

    def test_a_windows_drive_letter_is_not_a_host(self):
        assert _split_remote_spec(r"C:\Users\me\file.txt") == (
            "",
            r"C:\Users\me\file.txt",
        )


class TestHostKeyPolicyBridge:
    """The Paramiko missing-host-key hook has to defer to the project policy.

    Paramiko consults its missing-host-key policy *during* the handshake.  A
    plain ``RejectPolicy`` would therefore refuse every host before the
    project's own policy could accept it, which made
    ``--auto-accept-host-key`` and ``btl hostkey add`` unusable.
    """

    def _policy(self, tmp_path, auto_accept):
        from btl.ssh.connection import _StrictMissingHostKeyPolicy
        from btl.ssh.hostkeys import HostKeyPolicy, KnownHostsStore

        store = KnownHostsStore(str(tmp_path / "known_hosts"))
        return _StrictMissingHostKeyPolicy(
            HostKeyPolicy(store, auto_accept=auto_accept), 22
        )

    def _key(self):
        import base64
        import os as _os

        def _string(raw: bytes) -> bytes:
            return len(raw).to_bytes(4, "big") + raw

        blob = _string(b"ssh-ed25519") + _string(_os.urandom(32))
        body = base64.b64encode(blob).decode("ascii")

        class _Key:
            def get_name(self):
                return "ssh-ed25519"

            def get_base64(self):
                return body

        return _Key()

    def test_an_unknown_key_is_accepted_when_auto_accept_is_on(self, tmp_path):
        policy = self._policy(tmp_path, auto_accept=True)
        policy.missing_host_key(None, "server", self._key())

    def test_an_unknown_key_is_refused_by_default(self, tmp_path):
        from btl.utils.errors import HostKeyError

        policy = self._policy(tmp_path, auto_accept=False)
        with pytest.raises(HostKeyError):
            policy.missing_host_key(None, "server", self._key())


class TestKeyLoading:
    def test_load_public_key_from_a_public_file(self, tmp_path):
        from btl.ssh.connection import load_public_key

        # A well formed Ed25519 public key line.  The base64 body has to be
        # the SSH wire format blob (the key type followed by the 32 byte
        # public key), so it is generated rather than written by hand.
        import base64
        import os as _os

        def _string(raw: bytes) -> bytes:
            return len(raw).to_bytes(4, "big") + raw

        blob = _string(b"ssh-ed25519") + _string(_os.urandom(32))
        body = base64.b64encode(blob).decode("ascii")
        public = f"ssh-ed25519 {body} test\n"
        path = tmp_path / "host.pub"
        path.write_text(public)

        key = load_public_key(str(path))
        assert key.get_name() == "ssh-ed25519"

    def test_load_public_key_rejects_garbage(self, tmp_path):
        from btl.ssh.connection import load_public_key

        path = tmp_path / "bad.pub"
        path.write_text("this is not a key\n")
        with pytest.raises(AuthError):
            load_public_key(str(path))

    def test_load_public_key_accepts_the_known_hosts_layout(self, tmp_path):
        # "ssh-keyscan" writes the host name first, then the key type.
        from btl.ssh.connection import load_public_key

        import base64
        import os as _os

        def _string(raw: bytes) -> bytes:
            return len(raw).to_bytes(4, "big") + raw

        blob = _string(b"ssh-ed25519") + _string(_os.urandom(32))
        body = base64.b64encode(blob).decode("ascii")
        path = tmp_path / "scan.pub"
        path.write_text(f"192.168.118.128 ssh-ed25519 {body}\n")

        key = load_public_key(str(path))
        assert key.get_name() == "ssh-ed25519"

    def test_load_client_key_rejects_garbage(self, tmp_path):
        from btl.ssh.connection import load_client_key

        path = tmp_path / "bad.key"
        path.write_text("not a private key\n")
        with pytest.raises(AuthError):
            load_client_key(str(path))


class TestSSHDPolicyRoundTrip:
    def test_every_baseline_directive_appears_in_the_config(self):
        from btl.security.sshd_config import BASELINE

        config = SSHDPolicy().to_config().lower()
        for directive in BASELINE:
            assert directive in config, f"{directive} is missing from the config"
