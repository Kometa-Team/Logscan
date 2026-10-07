from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import URLError

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
                "quickstart_run": True,
                "quickstart_version": "0.10.6-build7",
                "quickstart_branch": "develop",
                "complete": True,
                "schema_validation_count": 3,
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

    def test_analysis_replacement_preserves_scan_identity_and_source_log(self):
        before = self.store.get(self.scan_id)
        log_before = self.store.log_path(self.scan_id).read_bytes()
        replacement = SimpleNamespace(
            filename="discord-example.log",
            recommendations=[{"id": "new-rule", "severity": "advice", "title": "New result"}],
            metadata={"analysis_version": 1, "counts": {"advice": 1}},
            overview={"finding_count": 1},
            categories=[{"key": "advice"}],
        )

        self.assertTrue(self.store.replace_analysis(self.scan_id, replacement))
        after = self.store.get(self.scan_id)

        self.assertEqual(after["id"], before["id"])
        self.assertEqual(after["created_at"], before["created_at"])
        self.assertEqual(after["delete_token_hash"], before["delete_token_hash"])
        self.assertEqual(after["metadata"]["analysis_version"], 1)
        self.assertEqual(after["recommendations"][0]["id"], "new-rule")
        self.assertEqual(self.store.log_path(self.scan_id).read_bytes(), log_before)

    def test_startup_migration_versions_and_reprocesses_retained_scans(self):
        source = Path("logscan_web/app.py").read_text(encoding="utf-8")

        self.assertIn("ANALYSIS_VERSION = 3", source)
        self.assertIn('if (record.get("metadata") or {}).get("analysis_version") != ANALYSIS_VERSION', source)
        self.assertIn("scan_archive_path(record.get(\"filename\") or \"kometa.log\", path)", source)
        self.assertIn("backfill_scan_analysis()", source)
        self.assertIn("backfill_schema_validation_counts()", source)
        self.assertIn('name="retained-scan-migration"', source)

    def test_concurrent_metadata_updates_are_serialized(self):
        failures = []

        def update(index):
            try:
                self.store.update_metadata(self.scan_id, **{f"migration_value_{index}": index})
            except Exception as exc:
                failures.append(exc)

        workers = [threading.Thread(target=update, args=(index,)) for index in range(12)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()

        self.assertEqual(failures, [])
        metadata = self.store.get(self.scan_id)["metadata"]
        for index in range(12):
            self.assertEqual(metadata[f"migration_value_{index}"], index)

    def authorize_session(self):
        with self.client.session_transaction() as support_session:
            support_session["support_authorized_at"] = 9999999999
            support_session["support_user"] = {
                "id": "42",
                "username": "Support Person",
                "avatar": "",
            }

    def test_account_session_remains_authorized_for_30_days(self):
        with self.app.test_request_context("/"):
            from flask import session
            from logscan_web.support import discord_session_user

            session["discord_user"] = {"id": "42"}
            session["support_authorized_at"] = time.time() - (29 * 24 * 60 * 60)
            self.assertIsNotNone(discord_session_user())
            session["support_authorized_at"] = time.time() - (31 * 24 * 60 * 60)
            self.assertIsNone(discord_session_user())

    def test_support_role_is_revalidated_once_per_request(self):
        self.app.config["DISCORD_BOT_TOKEN"] = "bot-secret"
        with self.app.test_request_context("/"):
            from flask import session
            from logscan_web.support import support_session_authorized

            session["discord_user"] = {"id": "42"}
            session["support_authorized_at"] = time.time()
            session["support_access"] = True
            with patch("logscan_web.support._discord_request", return_value={"roles": ["support-role"]}) as request:
                self.assertTrue(support_session_authorized())
                self.assertTrue(support_session_authorized())
                request.assert_called_once_with(
                    "/guilds/guild/members/42",
                    headers={"Authorization": "Bot bot-secret"},
                )

    def test_newly_granted_support_role_is_recognized_without_signing_in_again(self):
        self.app.config["DISCORD_BOT_TOKEN"] = "bot-secret"
        with self.app.test_request_context("/"):
            from flask import session
            from logscan_web.support import support_session_authorized

            session["discord_user"] = {"id": "42"}
            session["support_authorized_at"] = time.time()
            session["support_access"] = False
            with patch("logscan_web.support._discord_request", return_value={"roles": ["support-role"]}):
                self.assertTrue(support_session_authorized())

    def test_live_role_removal_and_discord_errors_fail_closed(self):
        self.app.config["DISCORD_BOT_TOKEN"] = "bot-secret"
        with self.app.test_request_context("/"):
            from flask import session
            from logscan_web.support import support_session_authorized

            session["discord_user"] = {"id": "42"}
            session["support_authorized_at"] = time.time()
            session["support_access"] = True
            with patch("logscan_web.support._discord_request", return_value={"roles": []}):
                self.assertFalse(support_session_authorized())
        with self.app.test_request_context("/"):
            from flask import session
            from logscan_web.support import support_session_authorized

            session["discord_user"] = {"id": "42"}
            session["support_authorized_at"] = time.time()
            session["support_access"] = True
            with patch("logscan_web.support._discord_request", side_effect=URLError("offline")):
                self.assertFalse(support_session_authorized())

    def test_support_role_without_bot_token_expires_after_eight_hours(self):
        with self.app.test_request_context("/"):
            from flask import session
            from logscan_web.support import support_session_authorized

            session["discord_user"] = {"id": "42"}
            session["support_authorized_at"] = time.time()
            session["support_access"] = True
            session["support_role_verified_at"] = time.time() - (7 * 60 * 60)
            self.assertTrue(support_session_authorized())
            session["support_role_verified_at"] = time.time() - (9 * 60 * 60)
            self.assertFalse(support_session_authorized())

    def test_stale_support_role_remains_a_navigation_hint_and_requires_oauth_refresh(self):
        with self.app.test_request_context("/"):
            from flask import session
            from logscan_web.support import support_role_refresh_required, support_session_role_hint

            session["discord_user"] = {"id": "42"}
            session["support_authorized_at"] = time.time() - (2 * 24 * 60 * 60)
            session["support_access"] = True
            session["support_role_verified_at"] = time.time() - (9 * 60 * 60)

            self.assertTrue(support_session_role_hint())
            self.assertTrue(support_role_refresh_required())

    def test_bot_revalidation_does_not_require_oauth_refresh_link(self):
        self.app.config["DISCORD_BOT_TOKEN"] = "bot-secret"
        with self.app.test_request_context("/"):
            from flask import session
            from logscan_web.support import support_role_refresh_required

            session["discord_user"] = {"id": "42"}
            session["support_authorized_at"] = time.time() - (2 * 24 * 60 * 60)
            session["support_access"] = True
            session["support_role_verified_at"] = time.time() - (9 * 60 * 60)

            self.assertFalse(support_role_refresh_required())

    def test_regular_user_console_only_lists_owned_uploads(self):
        with self.client.session_transaction() as support_session:
            support_session["support_authorized_at"] = 9999999999
            support_session["support_access"] = False
            support_session["discord_user"] = {"id": "someone-else", "username": "Other", "avatar": ""}
        body = self.client.get("/support/logs").get_data(as_text=True)
        self.assertIn("My uploads", body)
        self.assertNotIn("discord-example.log", body)
        self.assertEqual(self.client.post(f"/support/logs/{self.scan_id}/delete").status_code, 404)

        with self.client.session_transaction() as support_session:
            support_session["discord_user"] = {"id": "42", "username": "Support Person", "avatar": ""}
        body = self.client.get("/support/logs").get_data(as_text=True)
        self.assertIn("discord-example.log", body)
        self.assertIn("My uploads", body)
        self.assertNotIn(">Support Console</a>", body)
        response = self.client.post(f"/support/logs/{self.scan_id}/delete")
        self.assertEqual(response.status_code, 302)
        self.assertIsNone(self.store.get(self.scan_id))

    def test_support_member_defaults_to_personal_uploads_and_can_open_all_logs(self):
        with self.client.session_transaction() as support_session:
            support_session["support_authorized_at"] = 9999999999
            support_session["support_access"] = True
            support_session["discord_user"] = {"id": "support-99", "username": "Helper", "avatar": ""}
        personal = self.client.get("/support/logs").get_data(as_text=True)
        self.assertIn("My uploads", personal)
        self.assertNotIn("discord-example.log", personal)
        self.assertIn("view=all", personal)
        all_logs = self.client.get("/support/logs?view=all").get_data(as_text=True)
        self.assertIn("Support console", all_logs)
        self.assertIn("discord-example.log", all_logs)
        self.assertIn("view=mine", all_logs)

    def test_sign_in_page_explains_account_benefits_without_requiring_login(self):
        body = self.client.get("/support/login").get_data(as_text=True)
        self.assertIn("Keep your scans together", body)
        self.assertIn("find, search, reopen, and delete your retained web and Discord uploads", body)
        self.assertIn("Anonymous scanning remains available", body)
        self.assertIn("expire automatically after 48 hours", body)

    def test_inventory_requires_discord_sign_in(self):
        response = self.client.get("/support/logs")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/support/login", response.location)

    def test_authorize_uses_required_scopes_and_safe_destination(self):
        response = self.client.get("/support/authorize?next=//attacker.example")
        self.assertEqual(response.status_code, 302)
        self.assertIn("scope=identify+guilds.members.read", response.location)
        with self.client.session_transaction() as support_session:
            self.assertEqual(support_session["oauth_next"], "/support/logs?view=mine")
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
            self.assertEqual(support_session["discord_user"]["id"], "42")
            self.assertTrue(support_session["support_access"])
            self.assertTrue(support_session.permanent)
            self.assertIn("support_role_verified_at", support_session)

    @patch("logscan_web.support._discord_get")
    @patch("logscan_web.support._discord_token", return_value="access-token")
    def test_callback_allows_member_without_support_console_role(self, _token, discord_get):
        discord_get.side_effect = [
            {"id": "9", "username": "member", "avatar": None},
            {"roles": ["other-role"]},
        ]
        with self.client.session_transaction() as support_session:
            support_session["oauth_state"] = "state"
        response = self.client.get("/support/callback?state=state&code=code")
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as support_session:
            self.assertEqual(support_session["discord_user"]["id"], "9")
            self.assertFalse(support_session["support_access"])

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
        self.assertIn('class="site-nav-account"', body)
        self.assertIn("Support Person", body)
        self.assertIn('class="site-nav-signout"', body)
        self.assertIn('class="support-launcher"', body)
        self.assertIn("QS 0.10.6-build7", body)
        self.assertIn("Quickstart 0.10.6-build7", body)
        self.assertIn(f"/scan/{self.scan_id}#viewer=config", body)
        self.assertIn("Schema <span>3</span>", body)
        self.assertIn('data-findings="5"', body)
        self.assertIn('<option value="all">All</option>', body)
        all_rows = self.client.get("/support/logs?page_size=all").get_data(as_text=True)
        self.assertIn('<option value="all" selected>All</option>', all_rows)
        self.assertNotIn(self.delete_token, body)
        self.assertNotIn("delete_token_hash", body)


    def test_inventory_filters_quickstart_and_direct_runs(self):
        direct_result = SimpleNamespace(
            filename="direct-example.log",
            recommendations=[],
            metadata={
                "size_bytes": 1024,
                "line_count": 50,
                "kometa_version": "2.5.1",
                "kometa_branch": "master",
                "quickstart_run": False,
                "complete": True,
            },
            overview={"uploaded_by": "Support Person", "uploaded_by_id": "42"},
            categories=[],
        )
        self.store.create("direct-example.log", b"log", direct_result)
        self.authorize_session()

        quickstart = self.client.get("/support/logs?launcher=quickstart").get_data(as_text=True)
        self.assertIn("discord-example.log", quickstart)
        self.assertNotIn("direct-example.log", quickstart)
        self.assertIn('<option value="quickstart" selected>Quickstart</option>', quickstart)
        self.assertIn("launcher=quickstart", quickstart)

        direct = self.client.get("/support/logs?launcher=direct").get_data(as_text=True)
        self.assertIn("direct-example.log", direct)
        self.assertNotIn("discord-example.log", direct)
        self.assertIn('<option value="direct" selected>Not Quickstart</option>', direct)

    def test_inventory_filters_kometa_branches(self):
        nightly_result = SimpleNamespace(
            filename="nightly-example.log",
            recommendations=[],
            metadata={
                "size_bytes": 1024,
                "line_count": 50,
                "kometa_version": "2.6.0-build1",
                "kometa_branch": "nightly",
                "quickstart_run": False,
                "complete": True,
            },
            overview={"uploaded_by": "Support Person", "uploaded_by_id": "42"},
            categories=[],
        )
        master_result = SimpleNamespace(
            filename="master-example.log",
            recommendations=[],
            metadata={
                "size_bytes": 1024,
                "line_count": 50,
                "kometa_version": "2.5.1 (Docker: master)",
                "kometa_branch": "unknown",
                "quickstart_run": False,
                "complete": True,
            },
            overview={"uploaded_by": "Support Person", "uploaded_by_id": "42"},
            categories=[],
        )
        self.store.create("nightly-example.log", b"log", nightly_result)
        self.store.create("master-example.log", b"log", master_result)
        self.authorize_session()

        develop = self.client.get("/support/logs?branch=develop").get_data(as_text=True)
        self.assertIn("discord-example.log", develop)
        self.assertNotIn("nightly-example.log", develop)
        self.assertNotIn("master-example.log", develop)
        self.assertIn('<option value="develop" selected>Develop</option>', develop)
        self.assertIn("branch=develop", develop)

        nightly = self.client.get("/support/logs?branch=nightly").get_data(as_text=True)
        self.assertIn("nightly-example.log", nightly)
        self.assertNotIn("discord-example.log", nightly)
        self.assertNotIn("master-example.log", nightly)
        self.assertIn('<option value="nightly" selected>Nightly</option>', nightly)

        master = self.client.get("/support/logs?branch=master").get_data(as_text=True)
        self.assertIn("master-example.log", master)
        self.assertNotIn("discord-example.log", master)
        self.assertNotIn("nightly-example.log", master)
        self.assertIn('<option value="master" selected>Master</option>', master)

    def test_schema_count_is_backed_by_persisted_validation_metadata(self):
        self.authorize_session()
        body = self.client.get("/support/logs?severity=schema").get_data(as_text=True)
        self.assertIn("discord-example.log", body)
        self.assertIn('<span class="severity-chip schema" title="Schema: 3">3</span>', body)
        self.assertIn('<span class="severity-chip error" title="Error: 0">0</span>', body)

    def test_inventory_counts_derived_schema_directive_advice(self):
        self.store.update_metadata(self.scan_id, schema_directive_missing=True)
        self.authorize_session()

        body = self.client.get("/support/logs?view=all").get_data(as_text=True)

        self.assertIn('<span class="severity-chip advice" title="Advice: 1">1</span>', body)
    @patch("logscan_web.support.urlopen")
    def test_discord_requests_send_explicit_user_agent(self, mocked_urlopen):
        response = mocked_urlopen.return_value.__enter__.return_value
        response.read.return_value = b'{}'
        _discord_request("/users/@me", headers={"Authorization": "Bearer token"})
        sent_request = mocked_urlopen.call_args.args[0]
        self.assertEqual(sent_request.get_header("User-agent"), DISCORD_USER_AGENT)
        self.assertEqual(sent_request.get_header("Authorization"), "Bearer token")

    def test_my_uploads_has_compact_uploader_but_support_console_does_not(self):
        self.authorize_session()
        personal = self.client.get("/support/logs").get_data(as_text=True)
        self.assertIn('class="primary-button support-upload-open"', personal)
        self.assertIn('id="support-upload-dialog"', personal)
        self.assertIn('id="support-upload-form"', personal)
        self.assertIn('id="support-log-file"', personal)
        self.assertIn('tabindex="0"', personal)

        support_console = self.client.get("/support/logs?view=all").get_data(as_text=True)
        self.assertNotIn('id="support-upload-dialog"', support_console)
        self.assertNotIn('class="primary-button support-upload-open"', support_console)

    def test_navigation_dialog_is_responsive_and_contextual(self):
        template = Path("logscan_web/templates/support_logs.html").read_text(encoding="utf-8")
        script = Path("logscan_web/static/support_logs.js").read_text(encoding="utf-8")
        self.assertIn("support_logs.js", template)
        self.assertIn('class="support-filter-panel"', template)
        self.assertNotIn('class="support-filter-panel" open', template)
        self.assertIn("Search and filters", template)
        self.assertIn("data-active-filters", template)
        self.assertIn('window.matchMedia("(max-width: 560px)")', script)
        self.assertIn('id="support-navigation-dialog"', template)
        self.assertIn('class="support-navigate"', template)
        self.assertIn('class="support-destination-options"', template)
        self.assertIn("links.replaceChildren", script)
        self.assertIn("dialog.showModal()", script)
        self.assertIn("event.target === dialog", script)
        self.assertIn("window.confirm", script)
        self.assertIn('sessionStorage.getItem("supportActiveScanJob")', script)
        self.assertIn('headers: { "X-Scan-Job-ID": jobId }', script)
        self.assertIn("completedUploadDestination", script)
        self.assertIn('id="support-select-all"', template)
        self.assertIn('id="support-bulk-delete-dialog"', template)
        self.assertIn('fetch("/support/logs/delete-selected"', script)
        self.assertIn("selectAllLogs.indeterminate", script)
        self.assertIn('data-view="{{ view_mode }}"', template)
        self.assertIn('deleteForm.dataset.view || "mine"', script)
        self.assertLess(template.index("support-actions-heading"), template.index("support-title"))
        css = Path("logscan_web/static/styles.css").read_text(encoding="utf-8")
        self.assertNotIn(".support-filter-panel > summary { display: none; }", css)
        self.assertIn(".support-filter-panel > summary { display: flex;", css)
        self.assertIn(".support-actions-heading, .support-actions { position: sticky", css)
        self.assertIn(".site-header-wide, .support-shell { width: calc(100% - 40px); max-width: none; }", css)
        self.assertNotIn("width: min(1600px, calc(100% - 40px))", css)
        self.assertIn("{% set wide_header = true %}", template)
        self.assertIn("severity == 'schema' or row.counts[severity]", template)
        self.assertIn('class="support-severities" aria-label="Finding counts"', template)
        self.assertIn('title="{{ severity|title }}: {{ row.counts[severity] }}"', template)
        self.assertNotIn("{% if row.counts[severity] %}<span class=\"severity-chip", template)
        self.assertIn("row.schema_count_available", template)
        self.assertIn("Unavailable", template)
        self.assertIn("Expires in", template)
        self.assertIn("Kometa / Environment", template)
        self.assertNotIn("sort_link('updated_at','Updated')", template)
        header = Path("logscan_web/templates/_site_header.html").read_text(encoding="utf-8")
        self.assertIn("site-header-wide", header)
        self.assertIn('href="/people"', header)
        self.assertIn('href="/analytics"', header)
        self.assertIn("site-nav-account", header)
        self.assertIn("support.logout", header)
        self.assertIn('class="header-my-uploads"', header)
        self.assertLess(header.index('class="header-my-uploads"'), header.index('<details class="site-nav">'))
        self.assertIn(".site-nav-primary-item { display: block; }", css)
        self.assertIn(".brand > span { display: inline;", css)
        self.assertNotIn(".brand > span { display: none; }", css)
        self.assertIn('<nav class="site-nav-external" aria-label="Kometa website">', header)
        self.assertLess(header.index("Support Console"), header.index("</nav>", header.index("Support Console")))
        self.assertGreater(header.index("utilities.kometa.wiki"), header.index("</nav>", header.index("Support Console")))
        self.assertIn('class="destination-{{ severity }}"', template)
        self.assertIn(".destination-critical { color: #fda4af; }", css)
        self.assertIn(".destination-schema, .support-destination-menu .destination-config", css)
        self.assertIn(".support-navigation-dialog::backdrop", css)
        self.assertIn("grid-template-columns: repeat(2,minmax(0,1fr))", css)
        self.assertIn("@media (max-width: 560px)", css)
        self.assertIn("width: 100%; min-height: 42px", css)

    def test_regular_user_can_bulk_delete_owned_logs(self):
        second = SimpleNamespace(
            filename="second-owned.log",
            recommendations=[],
            metadata={"size_bytes": 10, "line_count": 1, "complete": True},
            overview={"uploaded_by": "Support Person", "uploaded_by_id": "42"},
            categories=[],
        )
        second_id, _token = self.store.create("second-owned.log", b"log", second)
        with self.client.session_transaction() as support_session:
            support_session["support_authorized_at"] = 9999999999
            support_session["support_access"] = False
            support_session["discord_user"] = {"id": "42", "username": "Support Person", "avatar": ""}

        response = self.client.post(
            "/support/logs/delete-selected",
            json={"scan_ids": [self.scan_id, second_id, self.scan_id]},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["deleted"], 2)
        self.assertIsNone(self.store.get(self.scan_id))
        self.assertIsNone(self.store.get(second_id))

    def test_bulk_delete_is_atomic_for_unowned_selection(self):
        unowned = SimpleNamespace(
            filename="unowned.log",
            recommendations=[],
            metadata={"size_bytes": 10, "line_count": 1, "complete": True},
            overview={"uploaded_by": "Another User", "uploaded_by_id": "99"},
            categories=[],
        )
        unowned_id, _token = self.store.create("unowned.log", b"log", unowned)
        with self.client.session_transaction() as support_session:
            support_session["support_authorized_at"] = 9999999999
            support_session["support_access"] = False
            support_session["discord_user"] = {"id": "42", "username": "Support Person", "avatar": ""}

        response = self.client.post(
            "/support/logs/delete-selected",
            json={"scan_ids": [self.scan_id, unowned_id]},
        )

        self.assertEqual(response.status_code, 404)
        self.assertIsNotNone(self.store.get(self.scan_id))
        self.assertIsNotNone(self.store.get(unowned_id))

    def test_support_member_can_bulk_delete_across_owners(self):
        unowned = SimpleNamespace(
            filename="support-delete.log",
            recommendations=[],
            metadata={"size_bytes": 10, "line_count": 1, "complete": True},
            overview={"uploaded_by": "Another User", "uploaded_by_id": "99"},
            categories=[],
        )
        unowned_id, _token = self.store.create("support-delete.log", b"log", unowned)
        self.authorize_session()

        response = self.client.post(
            "/support/logs/delete-selected",
            json={"scan_ids": [self.scan_id, unowned_id]},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["deleted"], 2)
        self.assertIsNone(self.store.get(self.scan_id))
        self.assertIsNone(self.store.get(unowned_id))
    def test_support_member_can_delete_log_without_exposing_token(self):
        unauthorized = self.client.post(f"/support/logs/{self.scan_id}/delete")
        self.assertEqual(unauthorized.status_code, 302)
        self.assertIsNotNone(self.store.get(self.scan_id))

        self.authorize_session()
        with self.assertLogs(self.app.logger, level="WARNING") as captured:
            response = self.client.post(f"/support/logs/{self.scan_id}/delete")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/support/logs?view=mine")
        self.assertIsNone(self.store.get(self.scan_id))
        self.assertIn("user_id=42", "\n".join(captured.output))

if __name__ == "__main__":
    unittest.main()
