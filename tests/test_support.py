from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask

from logscan_web.storage import ScanStore
from logscan_web.support import DISCORD_USER_AGENT, _discord_request, create_support_blueprint


class SupportConsoleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.store = ScanStore(self.temporary.name)
        result = SimpleNamespace(
            filename="discord-example.log",
            recommendations=[
                {"severity": "critical", "title": "Traceback"},
                {"severity": "warning", "title": "Old setting"},
            ],
            metadata={
                "size_bytes": 2048,
                "line_count": 123,
                "kometa_version": "2.5.0",
                "kometa_branch": "develop",
                "runtime_platform": "Linux",
                "installation_method": "Docker",
                "complete": True,
            },
            overview={
                "uploaded_by": "Support Person",
                "uploaded_by_id": "42",
                "message_url": "https://discord.com/channels/1/2/3",
            },
            categories=[],
        )
        self.scan_id, self.delete_token = self.store.create("discord-example.log", b"log", result)
        self.app = Flask(__name__, template_folder=str(Path(__file__).parents[1] / "logscan_web" / "templates"))
        self.app.secret_key = "test-secret"
        self.app.config.update(
            TESTING=True,
            DISCORD_CLIENT_ID="client",
            DISCORD_CLIENT_SECRET="secret",
            DISCORD_GUILD_ID="guild",
            DISCORD_SUPPORT_ROLE_IDS={"support-role"},
            DISCORD_REDIRECT_URI="https://example.test/support/callback",
            LOGSCAN_SECRET_KEY="test-secret",
        )
        self.app.register_blueprint(create_support_blueprint(self.store, 48 * 60 * 60))

        @self.app.get("/scan/<scan_id>")
        def result_page(scan_id):
            return scan_id

        self.client = self.app.test_client()

    def tearDown(self):
        self.temporary.cleanup()

    def authorize_session(self):
        with self.client.session_transaction() as support_session:
            support_session["support_authorized_at"] = 9999999999
            support_session["support_user"] = {
                "id": "42",
                "username": "Support Person",
                "avatar": "",
            }

    def test_inventory_requires_discord_sign_in(self):
        response = self.client.get("/support/logs")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/support/login", response.location)

    def test_authorize_uses_required_scopes_and_safe_destination(self):
        response = self.client.get("/support/authorize?next=//attacker.example")
        self.assertEqual(response.status_code, 302)
        self.assertIn("scope=identify+guilds.members.read", response.location)
        with self.client.session_transaction() as support_session:
            self.assertEqual(support_session["oauth_next"], "/support/logs")
            self.assertTrue(support_session["oauth_state"])

    @patch("logscan_web.support._discord_get")
    @patch("logscan_web.support._discord_token", return_value="access-token")
    def test_callback_allows_configured_role(self, _token, discord_get):
        discord_get.side_effect = [
            {"id": "42", "username": "helper", "global_name": "Support Person", "avatar": None},
            {"roles": ["support-role"]},
        ]
        with self.client.session_transaction() as support_session:
            support_session["oauth_state"] = "state"
            support_session["oauth_next"] = "/support/logs"
        response = self.client.get("/support/callback?state=state&code=code")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/support/logs")
        with self.client.session_transaction() as support_session:
            self.assertEqual(support_session["support_user"]["id"], "42")

    @patch("logscan_web.support._discord_get")
    @patch("logscan_web.support._discord_token", return_value="access-token")
    def test_callback_denies_member_without_configured_role(self, _token, discord_get):
        discord_get.side_effect = [
            {"id": "9", "username": "member", "avatar": None},
            {"roles": ["other-role"]},
        ]
        with self.client.session_transaction() as support_session:
            support_session["oauth_state"] = "state"
        response = self.client.get("/support/callback?state=state&code=code")
        self.assertEqual(response.status_code, 403)
        self.assertIn("does not have a configured support role", response.get_data(as_text=True))

    def test_missing_configuration_is_logged_without_secret_values(self):
        roles = self.app.config["DISCORD_SUPPORT_ROLE_IDS"]
        self.app.config["DISCORD_SUPPORT_ROLE_IDS"] = set()
        try:
            with self.assertLogs(self.app.logger, level="WARNING") as captured:
                response = self.client.get("/support/logs")
        finally:
            self.app.config["DISCORD_SUPPORT_ROLE_IDS"] = roles
        self.assertEqual(response.status_code, 503)
        message = "\n".join(captured.output)
        self.assertIn("DISCORD_SUPPORT_ROLE_IDS", message)
        self.assertNotIn(self.app.config["DISCORD_CLIENT_SECRET"], message)

    def test_inventory_is_searchable_and_never_exposes_delete_secret(self):
        self.authorize_session()
        response = self.client.get("/support/logs?q=Support+Person&severity=critical")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("discord-example.log", body)
        self.assertIn("Navigate", body)
        self.assertIn(f"/scan/{self.scan_id}#viewer=config", body)
        self.assertNotIn(self.delete_token, body)
        self.assertNotIn("delete_token_hash", body)

    @patch("logscan_web.support.urlopen")
    def test_discord_requests_send_explicit_user_agent(self, mocked_urlopen):
        response = mocked_urlopen.return_value.__enter__.return_value
        response.read.return_value = b'{}'
        _discord_request("/users/@me", headers={"Authorization": "Bearer token"})
        sent_request = mocked_urlopen.call_args.args[0]
        self.assertEqual(sent_request.get_header("User-agent"), DISCORD_USER_AGENT)
        self.assertEqual(sent_request.get_header("Authorization"), "Bearer token")
    def test_navigation_menu_loads_positioning_script(self):
        template = Path("logscan_web/templates/support_logs.html").read_text(encoding="utf-8")
        script = Path("logscan_web/static/support_logs.js").read_text(encoding="utf-8")
        self.assertIn("support_logs.js", template)
        self.assertIn("positionDestinationMenu", script)
        self.assertIn("getBoundingClientRect", script)
        self.assertIn("menu.style.left", script)
        self.assertIn("menu.style.top", script)
        self.assertLess(template.index("support-actions-heading"), template.index("support-title"))
        css = Path("logscan_web/static/styles.css").read_text(encoding="utf-8")
        self.assertIn(".support-actions-heading, .support-actions { position: sticky", css)
        self.assertIn("severity == 'schema' or row.counts[severity]", template)
        self.assertIn("Expires in", template)
        self.assertIn("Kometa / Environment", template)
        self.assertNotIn("sort_link('updated_at','Updated')", template)

if __name__ == "__main__":
    unittest.main()
