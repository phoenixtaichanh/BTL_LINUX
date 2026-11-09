"""Tests for the hardening configuration and the host key store."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from btl.security.defense import (  # noqa: E402
    AuditPolicy,
    Fail2BanPolicy,
    FirewallPolicy,
)
from btl.security.sshd_config import (  # noqa: E402
    ALIASES,
    BASELINE,
    SSHDPolicy,
    audit_config,
    summarize,
)
from btl.ssh.hostkeys import (  # noqa: E402
    HostKeyPolicy,
    HostKeyStatus,
    KnownHostsStore,
    format_known_hosts,
)
from btl.utils.errors import ConfigError, HostKeyError  # noqa: E402


class TestSSHDPolicy:
    def test_renders_expected_directives(self):
        config = SSHDPolicy(port=2222).to_config()
        assert "Port 2222" in config
        assert "PermitRootLogin no" in config
        assert "PasswordAuthentication no" in config
        assert "PubkeyAuthentication yes" in config
        assert "AllowGroups sshusers" in config
        assert "MaxAuthTries 3" in config
        assert "X11Forwarding no" in config
        assert "AllowTcpForwarding no" in config

    def test_disables_password_and_keyboard_interactive(self):
        config = SSHDPolicy().to_config()
        assert "PasswordAuthentication no" in config
        assert "KbdInteractiveAuthentication no" in config
        assert "ChallengeResponseAuthentication no" in config

    def test_allow_users_and_groups(self):
        policy = SSHDPolicy(allowed_users=["alice"], allowed_groups=["sshusers", "ops"])
        config = policy.to_config()
        assert "AllowUsers alice" in config
        assert "AllowGroups sshusers ops" in config

    def test_rejects_invalid_port(self):
        with pytest.raises(ConfigError):
            SSHDPolicy(port=0).to_config()

    def test_requires_a_whitelist(self):
        with pytest.raises(ConfigError):
            SSHDPolicy(allowed_groups=[], allowed_users=[]).to_config()

    def test_match_block_for_sftp_users(self):
        block = SSHDPolicy().to_sftp_match_block(["alice", "bob"])
        assert "Match User alice" in block
        assert "ChrootDirectory /opt/sftp-jails/alice" in block
        assert "ForceCommand internal-sftp" in block
        assert "PermitTTY no" in block
        assert block.rstrip().endswith("Match all")

    def test_match_block_without_users(self):
        block = SSHDPolicy().to_sftp_match_block([])
        assert "Match User" not in block


class TestBaselineConsistency:
    """The baseline and the policy must not drift apart.

    ``btl audit`` compares a live server against :data:`BASELINE`, while
    ``btl provision`` writes :class:`SSHDPolicy`.  If a directive is present
    in one but not the other, the audit either misses a real weakness or
    reports a false alarm.
    """

    def test_every_baseline_directive_is_emitted_by_the_policy(self):
        config = SSHDPolicy().to_config()
        emitted = {
            line.split(" ", 1)[0].strip().lower()
            for line in config.splitlines()
            if line.strip() and not line.strip().startswith("#")
        }
        missing = sorted(set(BASELINE) - emitted)
        assert not missing, (
            "the policy does not emit these baseline directives: "
            f"{', '.join(missing)}"
        )

    def test_the_baseline_matches_the_generated_configuration(self):
        # The generated configuration is the source of truth: feeding it to
        # the auditor must report a fully compliant server.
        effective = {}
        for line in SSHDPolicy().to_config().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            keyword, _, value = line.partition(" ")
            effective[keyword.lower()] = value.strip()

        findings = audit_config(effective)
        counts = summarize(findings)
        assert counts.get("missing", 0) == 0, findings
        assert counts.get("weak", 0) == 0, findings

    def test_the_baseline_covers_the_critical_directives(self):
        for directive in (
            "permitrootlogin",
            "passwordauthentication",
            "pubkeyauthentication",
            "allowgroups",
            "allowtcpforwarding",
            "maxauthtries",
        ):
            assert directive in BASELINE

    def test_every_alias_points_at_a_baseline_directive(self):
        # An alias of a directive that is not in the baseline could never be
        # satisfied, which would produce a permanent false alarm.
        for alias, canonical in ALIASES.items():
            assert canonical in BASELINE, (
                f"the alias {alias!r} points at {canonical!r}, which is not "
                "part of the baseline"
            )

    def test_a_canonical_name_satisfies_the_deprecated_alias(self):
        # OpenSSH 10.x only prints the canonical name in 'sshd -T', so the
        # auditor has to accept it for the deprecated spelling.
        effective = dict(BASELINE)
        effective.pop("challengeresponseauthentication")
        effective["kbdinteractiveauthentication"] = "no"

        findings = audit_config(effective)
        counts = summarize(findings)
        assert counts.get("missing", 0) == 0, findings


class TestAudit:
    def test_compliant_config_passes(self):
        findings = audit_config(dict(BASELINE))
        counts = summarize(findings)
        assert counts.get("ok") == len(BASELINE)
        assert counts.get("weak", 0) == 0
        assert counts.get("missing", 0) == 0

    def test_detects_weak_directive(self):
        effective = dict(BASELINE)
        effective["passwordauthentication"] = "yes"
        findings = audit_config(effective)
        weak = [f for f in findings if f["status"] == "weak"]
        assert len(weak) == 1
        assert weak[0]["directive"] == "passwordauthentication"
        assert weak[0]["expected"] == "no"
        assert weak[0]["actual"] == "yes"

    def test_detects_missing_directive(self):
        effective = dict(BASELINE)
        del effective["maxauthtries"]
        findings = audit_config(effective)
        missing = [f for f in findings if f["status"] == "missing"]
        assert len(missing) == 1
        assert missing[0]["directive"] == "maxauthtries"

    def test_case_insensitive(self):
        effective = {k: v.upper() for k, v in BASELINE.items()}
        counts = summarize(audit_config(effective))
        assert counts.get("weak", 0) == 0


class TestFail2BanPolicy:
    def test_renders_sshd_jail(self):
        config = Fail2BanPolicy(port=2222).to_config()
        assert "[sshd]" in config
        assert "enabled  = true" in config
        assert "port     = 2222" in config
        assert "mode     = aggressive" in config

    def test_includes_recidive_jail(self):
        assert "[recidive]" in Fail2BanPolicy().to_config()

    def test_can_disable_recidive(self):
        assert "[recidive]" not in Fail2BanPolicy(enable_recidive=False).to_config()


class TestFirewallPolicy:
    def test_renders_ufw_script(self):
        script = FirewallPolicy(ssh_port=2222).to_script()
        assert "ufw default deny incoming" in script
        assert "ufw --force enable" in script

    def test_the_ssh_rule_is_a_plain_allow_by_default(self):
        # 'ufw limit' rejects more than six new connections per thirty
        # seconds, which blocks a legitimate burst of administrative
        # sessions and silently breaks the end to end test.
        script = FirewallPolicy(ssh_port=22).to_script()
        assert "ufw allow 22/tcp" in script
        assert "ufw limit 22/tcp" not in script

    def test_the_rate_limit_has_to_be_asked_for(self):
        script = FirewallPolicy(ssh_port=22, rate_limit_ssh=True).to_script()
        assert "ufw limit 22/tcp" in script

    def test_additional_ports(self):
        script = FirewallPolicy(ssh_port=22, allowed_tcp=[8080]).to_script()
        assert "ufw allow 8080/tcp" in script


class TestAuditPolicy:
    def test_renders_rules(self):
        rules = AuditPolicy().to_rules()
        assert "-w /etc/ssh/sshd_config -p wa -k btl_sshd_config" in rules
        assert "-w /etc/passwd -p wa -k btl_identity" in rules
        assert "btl_root_commands" in rules


class TestKnownHostsStore:
    def test_empty_store(self, tmp_path):
        store = KnownHostsStore(str(tmp_path / "known_hosts"))
        assert store.load() == []
        assert store.verify("host", 22, "ssh-ed25519", "AAAA") is HostKeyStatus.UNKNOWN

    def test_add_and_find(self, tmp_path):
        store = KnownHostsStore(str(tmp_path / "known_hosts"))
        store.add("server1", "ssh-ed25519", "AAAAB3Nz")
        entries = store.find("server1")
        assert len(entries) == 1
        assert entries[0].key_data == "AAAAB3Nz"

    def test_verify_matched(self, tmp_path):
        store = KnownHostsStore(str(tmp_path / "known_hosts"))
        store.add("server1", "ssh-ed25519", "AAAAB3Nz")
        assert (
            store.verify("server1", 22, "ssh-ed25519", "AAAAB3Nz")
            is HostKeyStatus.MATCHED
        )

    def test_verify_changed(self, tmp_path):
        store = KnownHostsStore(str(tmp_path / "known_hosts"))
        store.add("server1", "ssh-ed25519", "AAAAB3Nz")
        assert (
            store.verify("server1", 22, "ssh-ed25519", "DIFFERENT")
            is HostKeyStatus.CHANGED
        )

    def test_remove(self, tmp_path):
        store = KnownHostsStore(str(tmp_path / "known_hosts"))
        store.add("server1", "ssh-ed25519", "AAAAB3Nz")
        assert store.remove("server1") == 1
        assert store.find("server1") == []

    def test_non_default_port_formatting(self, tmp_path):
        store = KnownHostsStore(str(tmp_path / "known_hosts"))
        store.add("server1", "ssh-ed25519", "AAAAB3Nz", port=2222)
        entries = store.load()
        assert entries[0].hostname == "[server1]:2222"
        assert store.find("server1", 2222)

    def test_ignores_comments_and_blanks(self, tmp_path):
        path = tmp_path / "known_hosts"
        path.write_text("# a comment\n\nserver1 ssh-ed25519 AAAAB3Nz\n")
        store = KnownHostsStore(str(path))
        assert len(store.load()) == 1


class TestHostKeyPolicy:
    class _FakeKey:
        def __init__(self, name="ssh-ed25519", data="AAAAB3Nz"):
            self._name = name
            self._data = data

        def get_name(self):
            return self._name

        def get_base64(self):
            return self._data

    def test_unknown_key_is_rejected_by_default(self, tmp_path):
        policy = HostKeyPolicy(KnownHostsStore(str(tmp_path / "kh")))
        with pytest.raises(HostKeyError):
            policy.check("server1", 22, self._FakeKey())

    def test_unknown_key_can_be_auto_accepted(self, tmp_path):
        store = KnownHostsStore(str(tmp_path / "kh"))
        policy = HostKeyPolicy(store, auto_accept=True)
        policy.check("server1", 22, self._FakeKey())
        assert len(store.find("server1")) == 1

    def test_changed_key_is_always_fatal(self, tmp_path):
        store = KnownHostsStore(str(tmp_path / "kh"))
        store.add("server1", "ssh-ed25519", "ORIGINAL")
        policy = HostKeyPolicy(store, auto_accept=True)
        with pytest.raises(HostKeyError) as excinfo:
            policy.check("server1", 22, self._FakeKey(data="TAMPERED"))
        assert "CHANGED" in str(excinfo.value)

    def test_unsupported_key_type(self, tmp_path):
        policy = HostKeyPolicy(KnownHostsStore(str(tmp_path / "kh")))
        with pytest.raises(HostKeyError):
            policy.check("server1", 22, self._FakeKey(name="ssh-dss"))

    def test_matched_key_passes(self, tmp_path):
        store = KnownHostsStore(str(tmp_path / "kh"))
        store.add("server1", "ssh-ed25519", "AAAAB3Nz")
        policy = HostKeyPolicy(store)
        status = policy.check("server1", 22, self._FakeKey())
        assert status is HostKeyStatus.MATCHED


class TestFormatKnownHosts:
    def test_default_port(self):
        assert format_known_hosts("server1") == "server1"

    def test_custom_port(self):
        assert format_known_hosts("server1", 2222) == "[server1]:2222"
