from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask

from logscan_web.storage import ScanStore
from logscan_web.support import create_support_blueprint


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


if __name__ == "__main__":
    unittest.main()
