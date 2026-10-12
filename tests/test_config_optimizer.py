import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from logscan_web.config_optimizer import MAX_CONFIG_BYTES, optimize_config

CONFIG = """# yaml-language-server: $schema=https://example.test/schema.json
plex:
  url: '(redacted)'
  token: '(redacted)'
tmdb:
  apikey: '(redacted)'
libraries:
  Movies:
    settings:
      cache: true
      minimum_items: 5
  Shows:
    settings:
      cache: true
      minimum_items: 5
      timeout: 60
  Anime:
    settings:
      cache: true
      minimum_items: 10
"""


class ConfigOptimizerTests(unittest.TestCase):
    def assert_equivalent(self, original, result):
        self.assertEqual(result["status"], "optimized")
        self.assertEqual(yaml.safe_load(original), yaml.safe_load(result["optimized_config"]))

    def test_shared_settings_and_local_overrides(self):
        config = CONFIG.replace("minimum_items: 10", "minimum_items: 5")
        result = optimize_config(config)
        self.assert_equivalent(config, result)
        self.assertEqual(len(result["changes"]), 1)
        self.assertEqual(
            result["changes"][0]["locations"],
            [
                "config.libraries.Movies.settings",
                "config.libraries.Shows.settings",
                "config.libraries.Anime.settings",
            ],
        )
        self.assertIn("<<: *logscan_shared_1", result["optimized_config"])
        self.assertIn("timeout: 60", result["optimized_config"])
        self.assertIn("# yaml-language-server:", result["optimized_config"])
        self.assertIn("'(redacted)'", result["optimized_config"])
        self.assertIn("--- original.yml", result["diff"])
        self.assertIn("+++ anchored.yml", result["diff"])
        self.assertEqual(result["line_counts"]["before"], len(config.splitlines()))
        self.assertEqual(result["line_counts"]["after"], len(result["optimized_config"].splitlines()))
        self.assertEqual(result["line_counts"]["saved"], result["line_counts"]["before"] - result["line_counts"]["after"])

    def test_matching_keys_with_differing_override(self):
        config = "a:\n  settings: {cache: true, minimum_items: 5, timeout: 60}\nb:\n  settings: {cache: true, minimum_items: 10, timeout: 60}\n"
        result = optimize_config(config)
        self.assert_equivalent(config, result)
        self.assertIn("minimum_items: 10", result["optimized_config"])

    def test_source_only_keys_are_not_inherited(self):
        config = "a:\n  settings: {cache: true, minimum_items: 5, timeout: 60}\nb:\n  settings: {cache: true, minimum_items: 5}\n"
        self.assertEqual(optimize_config(config)["status"], "unchanged")

    def test_identical_ordered_lists_are_reused_without_deduplicating_items(self):
        config = (
            "a:\n  overlay_files: [{default: ribbon}, {default: ratings}, {default: ribbon}]\nb:\n  overlay_files: [{default: ribbon}, {default: ratings}, {default: ribbon}]\n"
        )
        result = optimize_config(config)
        self.assert_equivalent(config, result)
        self.assertIn("*logscan_shared_1", result["optimized_config"])
        self.assertEqual(len(yaml.safe_load(result["optimized_config"])["b"]["overlay_files"]), 3)

    def test_reordered_lists_are_not_combined(self):
        config = "a:\n  overlay_files: [ribbon, ratings]\nb:\n  overlay_files: [ratings, ribbon]\n"
        self.assertEqual(optimize_config(config)["status"], "unchanged")

    def test_lists_with_differently_ordered_nested_rules_are_not_aliased(self):
        config = "a:\n  rules: [{first: 1, second: 2}, end]\nb:\n  rules: [{second: 2, first: 1}, end]\n"
        result = optimize_config(config)
        if result["optimized_config"]:
            self.assertNotIn("rules: *", result["optimized_config"])

    def test_already_shared_aliases_do_not_create_new_suggestions(self):
        config = "a:\n  settings: &shared {cache: true, minimum_items: 5}\nb:\n  settings: *shared\n"
        self.assertEqual(optimize_config(config)["status"], "unchanged")

    def test_alias_expansion_is_bounded_before_loading_merges(self):
        lines = ["a: &a {one: 1, two: 2}"]
        previous = "a"
        for index in range(16):
            name = f"level{index}"
            lines.append(f"{name}: &{name} {{<<: [*{previous}, *{previous}]}}")
            previous = name
        with self.assertRaisesRegex(ValueError, "too complex"):
            optimize_config("\n".join(lines))

    def test_existing_anchor_and_merge_are_preserved(self):
        config = "base: &original {cache: true, minimum_items: 5}\na:\n  settings: {<<: *original, timeout: 60}\nb:\n  settings: {cache: true, minimum_items: 5}\nc:\n  settings: {cache: true, minimum_items: 5}\n"
        result = optimize_config(config)
        self.assert_equivalent(config, result)
        self.assertIn("&original", result["optimized_config"])
        self.assertIn("*original", result["optimized_config"])

    def test_new_anchor_names_do_not_collide(self):
        config = "base: &logscan_shared_1 {x: 1}\na:\n  settings: {cache: true, minimum_items: 5}\nb:\n  settings: {cache: true, minimum_items: 5}\n"
        result = optimize_config(config)
        self.assert_equivalent(config, result)
        self.assertEqual(result["changes"][0]["anchor"], "logscan_shared_2")

    def test_target_comments_are_not_lost(self):
        config = "a:\n  settings:\n    cache: true\n    minimum_items: 5\nb:\n  settings:\n    cache: true # keep this note\n    minimum_items: 5\n"
        result = optimize_config(config)
        self.assertEqual(result["status"], "unchanged")
        self.assertIsNone(result["optimized_config"])

    def test_no_repetition_does_not_reformat_original(self):
        result = optimize_config("settings: {cache: true, timeout: 60}\n")
        self.assertEqual(result["status"], "unchanged")
        self.assertEqual(result["diff"], "")
        self.assertEqual(result["line_counts"], {"before": 1, "after": 1, "saved": 0, "reduction_percent": 0.0})

    def test_line_count_growth_is_not_reported_as_savings(self):
        config = "a:\n  settings: {cache: true, minimum_items: 5}\nb:\n  settings: {cache: true, minimum_items: 5}\n"
        result = optimize_config(config)
        self.assertLess(result["line_counts"]["saved"], 0)
        self.assertLess(result["line_counts"]["reduction_percent"], 0)

    def test_bool_and_integer_are_not_equivalent(self):
        config = "a:\n  settings: {cache: true, timeout: 1}\nb:\n  settings: {cache: 1, timeout: true}\n"
        self.assertEqual(optimize_config(config)["status"], "unchanged")

    def test_yaml_11_values_keep_their_types(self):
        config = "a:\n  settings: {cache: yes, minimum_items: 05}\nb:\n  settings: {cache: yes, minimum_items: 05}\n"
        self.assert_equivalent(config, optimize_config(config))

    def test_ancestor_mapping_is_never_merged_into_its_child(self):
        config = "settings:\n  a: 1\n  b: 2\n  settings:\n    a: 1\n    b: 2\n    settings: null\n"
        self.assertEqual(optimize_config(config)["status"], "unchanged")

    def test_rejects_invalid_duplicate_recursive_and_unsafe_yaml(self):
        for config in ("", "a: [", "a: 1\na: 2", "a: &a [*a]", "a: !!python/object:foo {}", "[1, 2]", "---\na: 1\n---\nb: 2"):
            with self.subTest(config=config), self.assertRaises(ValueError):
                optimize_config(config)

    def test_rejects_excessive_size_and_depth(self):
        for config in ("a: " + "x" * MAX_CONFIG_BYTES, "a: " + "[" * 81 + "1" + "]" * 81):
            with self.assertRaises(ValueError):
                optimize_config(config)

    def test_equivalence_failure_blocks_download(self):
        from ruamel.yaml import YAML

        with patch.object(YAML, "dump", side_effect=lambda _self, stream: stream.write("changed: true\n")):
            with self.assertRaisesRegex(ValueError, "changed resolved values"):
                optimize_config(CONFIG)


class ConfigOptimizerApiTests(unittest.TestCase):
    def setUp(self):
        from logscan_web.storage import ScanStore

        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        with patch.dict("os.environ", {"SCAN_STORE": self.directory.name, "TMDB_API_KEY": ""}), patch("threading.Thread.start"):
            from logscan_web.app import create_app

            self.app = create_app()
            self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.store = ScanStore(self.directory.name)

    def save(self, config):
        content = "Redacted Config\n" + "\n".join(f"[config.py:1] [DEBUG] | {line} |" for line in config.splitlines())
        content += "\n[config.py:1] [DEBUG] | |\nInitializing cache database at /config/cache"
        result = SimpleNamespace(filename="optimize.log", recommendations=[], metadata={"counts": {"schema": 3}}, overview={}, categories=[])
        scan_id, _ = self.store.create(result.filename, content.encode(), result)
        return scan_id

    def test_review_does_not_modify_scan_config_or_counters(self):
        scan_id = self.save(CONFIG)
        before_record = self.store.get(scan_id)
        before_log = self.store.log_path(scan_id).read_bytes()
        response = self.client.post(f"/api/scans/{scan_id}/optimize-config")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "optimized")
        self.assertEqual(self.store.get(scan_id), before_record)
        self.assertEqual(self.store.log_path(scan_id).read_bytes(), before_log)
        download = self.client.get(f"/api/scans/{scan_id}/download/config")
        self.assertEqual(download.get_data(as_text=True), CONFIG.rstrip("\n"))

    def test_missing_or_expired_scan_returns_404(self):
        self.assertEqual(self.client.post("/api/scans/not-found/optimize-config").status_code, 404)

    def test_line_counts_match_normal_and_optimized_downloads(self):
        scan_id = self.save(CONFIG.split("\n", 1)[1])
        result = self.client.post(f"/api/scans/{scan_id}/optimize-config").get_json()
        original = self.client.get(f"/api/scans/{scan_id}/download/config").get_data(as_text=True)
        self.assertEqual(result["line_counts"]["before"], len(original.splitlines()))
        self.assertEqual(result["line_counts"]["after"], len(result["optimized_config"].splitlines()))
        self.assertIn("yaml-language-server", result["optimized_config"])

    def test_missing_and_invalid_configs_report_error(self):
        for config in ("", "a: ["):
            scan_id = self.save(config)
            response = self.client.post(f"/api/scans/{scan_id}/optimize-config")
            self.assertEqual(response.status_code, 400)
            self.assertIn("error", response.get_json())


if __name__ == "__main__":
    unittest.main()
