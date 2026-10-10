import unittest
from unittest.mock import patch

from logscan_web.recommendations import validate_redacted_config


SETTINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "libraries": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "properties": {
                    "settings": {
                        "type": "object",
                        "properties": {"timeout": {"type": "integer"}, "cache": {"type": "boolean"}},
                        "additionalProperties": False,
                    },
                },
            },
        },
    },
}


def validate_config(config, schema=SETTINGS_SCHEMA):
    lines = ["Redacted Config"]
    lines.extend(f"[config.py:1] [DEBUG] | {line} |" for line in config.splitlines())
    lines.extend(["[config.py:1] [DEBUG] | |", "Initializing cache database at /config/cache"])
    with patch("logscan_web.recommendations._load_config_schema", return_value=schema):
        return validate_redacted_config("\n".join(lines))


class SchemaAnchorTests(unittest.TestCase):
    def test_three_source_errors_reused_four_times_count_as_three(self):
        lines = [
            "anchors: &settings",
            "  collection_refresh: true",
            "  collection_update: true",
            "  show_separator_collections: true",
            "libraries:",
        ]
        for library in ("Movies", "Shows", "Anime", "Music"):
            lines.extend([f"  {library}:", "    settings:", "      <<: *settings"])
        failures = validate_config("\n".join(lines))
        self.assertEqual(len(failures), 3)
        self.assertEqual({failure["config_line"] for failure in failures}, {2, 3, 4})
        for failure in failures:
            setting = failure["path"].split(".")[-1]
            self.assertEqual(set(failure["paths"]), {
                f"libraries.{library}.settings.{setting}"
                for library in ("Movies", "Shows", "Anime", "Music")
            })

    def test_separate_copies_of_bad_settings_are_not_deduplicated(self):
        lines = ["libraries:"]
        for library in ("Movies", "Shows", "Anime", "Music"):
            lines.extend([
                f"  {library}:", "    settings:",
                "      collection_refresh: true",
                "      collection_update: true",
                "      show_separator_collections: true",
            ])
        failures = validate_config("\n".join(lines))
        self.assertEqual(len(failures), 12)
        self.assertEqual(len({failure["config_line"] for failure in failures}), 12)

    def test_shared_invalid_value_counts_once_for_direct_and_merged_aliases(self):
        failures = validate_config("\n".join([
            "anchors: &settings",
            "  timeout: true",
            "libraries:",
            "  Movies:", "    settings: *settings",
            "  Shows:", "    settings:", "      <<: *settings",
        ]))
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["config_line"], 2)
        self.assertEqual(failures[0]["paths"], [
            "libraries.Movies.settings.timeout", "libraries.Shows.settings.timeout",
        ])

    def test_explicit_invalid_override_counts_separately_from_shared_source(self):
        failures = validate_config("\n".join([
            "anchors: &settings",
            "  timeout: true",
            "libraries:",
            "  Movies:", "    settings: *settings",
            "  Shows:", "    settings:", "      <<: *settings", "      timeout: true",
        ]))
        self.assertEqual(len(failures), 2)
        self.assertEqual({failure["config_line"] for failure in failures}, {2, 9})

    def test_different_expectations_at_one_source_remain_distinct_issues(self):
        schema = {
            "type": "object",
            "properties": {
                "first": {"type": "integer"},
                "second": {"type": "number"},
            },
        }
        failures = validate_config("source: &value true\nfirst: *value\nsecond: *value", schema)
        self.assertEqual(len(failures), 2)
        self.assertEqual({failure["config_line"] for failure in failures}, {1})
        self.assertEqual({failure["path"] for failure in failures}, {"first", "second"})

    def test_multiple_bad_keys_on_one_flow_mapping_line_remain_distinct(self):
        failures = validate_config("\n".join([
            "anchors: &settings {collection_refresh: true, collection_update: true, show_separator_collections: true}",
            "libraries:", "  Movies:", "    settings: *settings",
        ]))
        self.assertEqual(len(failures), 3)
        self.assertEqual({failure["config_line"] for failure in failures}, {1})
        self.assertEqual(len({failure["config_column"] for failure in failures}), 3)

    def test_unknown_merged_settings_point_to_keys_in_anchor_definition(self):
        failures = validate_config("\n".join([
            "anchors:",
            "  settings: &settings",
            "    collection_refresh: true",
            "    collection_update: true",
            "    show_separator_collections: true",
            "libraries:",
            "  Movies:",
            "    settings:",
            "      <<: *settings",
        ]))
        self.assertEqual(len(failures), 3)
        for failure, setting, line in zip(failures, (
            "collection_refresh", "collection_update", "show_separator_collections",
        ), (3, 4, 5)):
            with self.subTest(setting=setting):
                self.assertEqual(failure["title"], f"Unknown setting: {setting}")
                self.assertEqual(failure["path"], f"libraries.Movies.settings.{setting}")
                self.assertEqual(failure["config_line"], line)
                self.assertEqual(failure["line"], line + 1)
                self.assertEqual(failure["config_column"], 5)
                self.assertEqual(failure["config_end_column"], 5 + len(setting))

    def test_invalid_value_in_nested_merged_anchor_points_to_value(self):
        failures = validate_config("\n".join([
            "anchors:",
            "  base: &base",
            "    timeout: true",
            "  settings: &settings",
            "    <<: *base",
            "    cache: true",
            "libraries:",
            "  Movies:",
            "    settings:",
            "      <<: *settings",
        ]))
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["path"], "libraries.Movies.settings.timeout")
        self.assertEqual(failures[0]["config_line"], 3)
        self.assertEqual(failures[0]["config_column"], 14)
        self.assertEqual(failures[0]["config_end_column"], 18)
        self.assertIn("integer", failures[0]["accepted"])

    def test_explicit_override_is_highlighted_instead_of_inherited_value(self):
        failures = validate_config("\n".join([
            "anchors: &settings",
            "  timeout: 60",
            "libraries:",
            "  Movies:",
            "    settings:",
            "      <<: *settings",
            "      timeout: false",
        ]))
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["config_line"], 7)
        self.assertEqual(failures[0]["config_column"], 16)
        self.assertEqual(failures[0]["config_end_column"], 21)

    def test_valid_override_does_not_report_unused_bad_anchor_value(self):
        self.assertEqual(validate_config("\n".join([
            "anchors: &settings",
            "  timeout: false",
            "libraries:",
            "  Movies:",
            "    settings:",
            "      <<: *settings",
            "      timeout: 60",
        ])), [])

    def test_merge_sequence_uses_the_winning_anchor_location(self):
        failures = validate_config("\n".join([
            "anchors:",
            "  first: &first",
            "    timeout: true",
            "  second: &second",
            "    timeout: 60",
            "libraries:",
            "  Movies:",
            "    settings:",
            "      <<: [*first, *second]",
        ]))
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["config_line"], 3)
        self.assertEqual(failures[0]["config_column"], 14)

    def test_direct_alias_still_points_to_its_definition(self):
        failures = validate_config("\n".join([
            "anchors: &settings",
            "  timeout: true",
            "libraries:",
            "  Movies:",
            "    settings: *settings",
        ]))
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["config_line"], 2)
        self.assertEqual(failures[0]["config_column"], 12)


if __name__ == "__main__":
    unittest.main()
