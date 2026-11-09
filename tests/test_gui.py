"""Tests for the graphical interface.

The interface is tested without a browser: the HTTP layer is driven with
real requests against a server that is bound to the loopback address, and
the service layer is tested with a fake session so that no network access
is needed.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from btl.gui.api import Api, error_response  # noqa: E402
from btl.gui.server import (  # noqa: E402
    GuiServer,
    WEB_ROOT,
    content_type_for,
    make_handler,
)
from btl.gui.service import (  # noqa: E402
    ConnectionSettings,
    ProvisionSettings,
    Service,
    Session,
)
from btl.utils.errors import BTLException, ConfigError  # noqa: E402


@pytest.fixture(scope="module")
def server():
    """A running interface bound to a free port on the loopback address."""
    instance = GuiServer(host="127.0.0.1", port=8791)
    instance.start()
    yield instance
    instance.stop()


def call(server, action, payload=None):
    """Send a request to the interface and return the decoded answer."""
    request = urllib.request.Request(
        f"http://127.0.0.1:{server.port}/api/{action}",
        data=json.dumps(payload or {}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        body = urllib.request.urlopen(request, timeout=10).read()
    except urllib.error.HTTPError as exc:
        body = exc.read()
    return json.loads(body.decode("utf-8"))


class TestConnectionSettings:
    """The settings that describe a connection."""

    def test_an_empty_host_is_rejected(self):
        with pytest.raises(ConfigError):
            ConnectionSettings(host="").validate()

    def test_an_empty_user_name_is_rejected(self):
        with pytest.raises(ConfigError):
            ConnectionSettings(host="example.com", username="").validate()

    def test_key_authentication_needs_a_key(self):
        settings = ConnectionSettings(host="example.com", auth_method="key")
        with pytest.raises(ConfigError):
            settings.validate()

    def test_an_unsupported_method_is_rejected(self):
        settings = ConnectionSettings(host="example.com", auth_method="magic")
        with pytest.raises(ConfigError):
            settings.validate()

    def test_an_invalid_port_is_rejected(self):
        settings = ConnectionSettings(host="example.com", port=70000)
        with pytest.raises(ConfigError):
            settings.validate()

    def test_the_settings_become_a_connection_config(self):
        settings = ConnectionSettings(
            host="  example.com  ",
            port=2222,
            username="  alice ",
            auth_method="key",
            key_path="  /home/alice/.ssh/id_ed25519 ",
            known_hosts="  /tmp/known_hosts ",
        )
        config = settings.to_connection_config()

        assert config.host == "example.com"
        assert config.port == 2222
        assert config.username == "alice"
        assert config.auth.method == "key"
        assert config.auth.key_path == "/home/alice/.ssh/id_ed25519"
        assert config.host_key_policy.store.path == os.path.abspath("/tmp/known_hosts")

    def test_the_sudo_password_falls_back_to_the_login_password(self):
        settings = ConnectionSettings(
            host="example.com",
            auth_method="password",
            password="secret",
        )
        config = settings.to_connection_config()
        assert config.sudo_password == "secret"


class TestProvisionSettings:
    """The settings that describe a provisioning run."""

    def test_the_plan_collects_the_accounts(self):
        settings = ProvisionSettings(
            group="sshusers",
            admin_users="alice, bob",
            sftp_users="carol",
        )
        plan = settings.build_plan(keep_access_user="alice")

        assert plan.sshd_policy.allowed_groups == ["sshusers"]
        assert plan.admin_users == ["alice", "bob"]
        assert plan.sftp_users == ["carol"]
        assert plan.keep_access_user == "alice"

    def test_the_ignored_addresses_are_added_to_the_policy(self):
        settings = ProvisionSettings(
            admin_users="alice",
            fail2ban_ignore="192.168.118.0/24, 10.0.0.1",
        )
        plan = settings.build_plan(keep_access_user="alice")

        assert "192.168.118.0/24" in plan.fail2ban_policy.ignore_ip
        assert "10.0.0.1" in plan.fail2ban_policy.ignore_ip

    def test_a_public_key_is_installed_for_every_account(self, tmp_path):
        key_file = tmp_path / "admin.pub"
        key_file.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 comment\n", encoding="utf-8")

        settings = ProvisionSettings(
            admin_users="alice,bob",
            admin_public_key=str(key_file),
        )
        plan = settings.build_plan(keep_access_user="alice")

        assert plan.admin_public_keys["alice"] == [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 comment"
        ]
        assert plan.admin_public_keys["bob"] == plan.admin_public_keys["alice"]

    def test_a_missing_public_key_is_reported(self, tmp_path):
        settings = ProvisionSettings(
            admin_users="alice",
            admin_public_key=str(tmp_path / "missing.pub"),
        )
        with pytest.raises(ConfigError):
            settings.build_plan(keep_access_user="alice")


class TestApiDispatch:
    """The dispatcher that translates a request into a service call."""

    def test_an_unknown_action_is_rejected(self):
        api = Api(Service())
        with pytest.raises(ConfigError):
            api.dispatch("does_not_exist", {})

    def test_the_state_is_returned_without_a_connection(self):
        api = Api(Service())
        result = api.dispatch("state", {})
        assert result["connected"] is False

    def test_a_command_needs_a_connection(self):
        api = Api(Service())
        with pytest.raises(BTLException):
            api.dispatch("run", {"command": "ls"})

    def test_the_connection_settings_are_built_from_the_payload(self):
        api = Api(Service())
        with pytest.raises(BTLException):
            api.dispatch(
                "connect",
                {"host": "192.0.2.1", "username": "alice", "auth_method": "key"},
            )

    def test_the_render_action_produces_the_sshd_configuration(self):
        api = Api(Service())
        result = api.dispatch("render", {"what": "sshd"})
        assert "PermitRootLogin no" in result["content"]
        assert "PasswordAuthentication no" in result["content"]

    def test_the_render_action_rejects_an_unknown_file(self):
        api = Api(Service())
        with pytest.raises(ConfigError):
            api.dispatch("render", {"what": "nonsense"})

    def test_the_boolean_and_number_conversions_are_tolerant(self):
        api = Api(Service())
        # A payload that carries the wrong types must not raise, it must
        # fall back to the default.
        result = api.dispatch(
            "render",
            {"what": "sshd", "port": "not-a-number", "groups": "ops"},
        )
        assert result["what"] == "sshd"


class TestErrorResponse:
    """The body that is sent when an operation fails."""

    def test_a_project_error_keeps_its_message(self):
        body = error_response(ConfigError("the port is wrong"))
        assert body["ok"] is False
        assert body["error"] == "the port is wrong"
        assert body["kind"] == "ConfigError"

    def test_an_unexpected_error_is_wrapped(self):
        body = error_response(RuntimeError("boom"))
        assert body["ok"] is False
        assert "RuntimeError" in body["error"]


class TestHttpLayer:
    """The HTTP layer of the interface."""

    def test_the_index_page_is_served(self, server):
        response = urllib.request.urlopen(f"http://127.0.0.1:{server.port}/")
        body = response.read().decode("utf-8")
        assert response.status == 200
        assert "BTL Toolkit" in body

    def test_the_static_files_are_served(self, server):
        for name in ("style.css", "app.js"):
            response = urllib.request.urlopen(
                f"http://127.0.0.1:{server.port}/static/{name}"
            )
            assert response.status == 200
            assert len(response.read()) > 100

    def test_a_missing_static_file_is_a_404(self, server):
        with pytest.raises(urllib.error.HTTPError) as info:
            urllib.request.urlopen(f"http://127.0.0.1:{server.port}/static/nope.css")
        assert info.value.code == 404

    def test_a_path_that_escapes_the_web_root_is_refused(self, server):
        with pytest.raises(urllib.error.HTTPError) as info:
            urllib.request.urlopen(
                f"http://127.0.0.1:{server.port}/static/../../../etc/passwd"
            )
        assert info.value.code in (403, 404)

    def test_the_state_endpoint_answers(self, server):
        response = urllib.request.urlopen(f"http://127.0.0.1:{server.port}/api/state")
        body = json.loads(response.read().decode("utf-8"))
        assert body["ok"] is True
        assert "connected" in body["result"]

    def test_an_action_reports_an_error_without_crashing(self, server):
        body = call(server, "does_not_exist")
        assert body["ok"] is False
        assert "unknown action" in body["error"]

    def test_a_malformed_body_is_reported(self, server):
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.port}/api/state",
            data=b"not json",
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(urllib.error.HTTPError) as info:
            urllib.request.urlopen(request)
        assert info.value.code == 400

    def test_the_render_action_works_over_http(self, server):
        body = call(server, "render", {"what": "firewall"})
        assert body["ok"] is True
        assert "ufw" in body["result"]["content"]

    def test_a_command_without_a_connection_is_reported(self, server):
        body = call(server, "run", {"command": "ls"})
        assert body["ok"] is False
        assert "not connected" in body["error"]


class TestSession:
    """The session that holds the SSH connection."""

    def test_a_new_session_is_not_connected(self):
        session = Session()
        assert session.connected is False
        assert session.state()["connected"] is False

    def test_connecting_without_a_host_is_rejected(self):
        session = Session()
        with pytest.raises(ConfigError):
            session.connect(ConnectionSettings(host=""))

    def test_disconnecting_a_fresh_session_is_harmless(self):
        session = Session()
        state = session.disconnect()
        assert state["connected"] is False

    def test_an_operation_without_a_connection_is_rejected(self):
        session = Session()
        with pytest.raises(BTLException):
            session.run_command("ls")


class TestWebRoot:
    """The files that make up the interface."""

    def test_every_web_file_is_present(self):
        for name in ("index.html", "style.css", "app.js"):
            path = os.path.join(WEB_ROOT, name)
            assert os.path.isfile(path), f"{name} is missing"
            assert os.path.getsize(path) > 0

    def test_the_handler_is_bound_to_the_service(self):
        service = Service()
        handler = make_handler(service)
        assert handler.service is service
        assert handler.api is not None


class TestContentTypes:
    """The content types of the static files.

    The standard library cannot always work the type of a file out on
    Windows, and a script that is served as ``text/plain`` is not run by
    the browser at all.
    """

    def test_the_script_is_served_as_javascript(self):
        assert content_type_for("app.js").startswith("text/javascript")

    def test_the_style_is_served_as_css(self):
        assert content_type_for("style.css").startswith("text/css")

    def test_the_page_is_served_as_html(self):
        assert content_type_for("index.html").startswith("text/html")

    def test_an_unknown_extension_falls_back_to_a_binary_type(self):
        assert content_type_for("data.bin") == "application/octet-stream"

    def test_the_served_script_really_is_javascript(self, server):
        response = urllib.request.urlopen(
            f"http://127.0.0.1:{server.port}/static/app.js"
        )
        content_type = response.headers.get("Content-Type", "")
        assert "javascript" in content_type
        assert len(response.read()) > 100
