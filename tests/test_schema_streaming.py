import tempfile
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import patch

from logscan_web.recommendations import extract_redacted_config, has_yaml_language_server_directive, schema_branch_for_log, validate_redacted_config


class SchemaStreamingTests(unittest.TestCase):
    def test_file_and_string_validation_preserve_source_locations(self):
        lines = [
            "[kometa.py:1] [INFO] | Version: 2.5.3 (Docker: nightly) |",
            "[config.py:1] [DEBUG] | Redacted Config |",
            "[config.py:2] [DEBUG] | # yaml-language-server: $schema=https://example.test/schema |",
            "[config.py:3] [DEBUG] | timeout: true |",
            "[config.py:4] [DEBUG] | |",
            "Initializing cache database at /config/cache",
            "[kometa.py:2] [INFO] | unrelated later output |",
        ]
        schema = {"type": "object", "properties": {"timeout": {"type": "integer"}}}
        for ending in ("\n", "\r\n", "\r"):
            text = ending.join(lines)
            with self.subTest(ending=ending), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "meta.log"
                path.write_bytes(text.encode())
                with patch("logscan_web.recommendations._load_config_schema", return_value=schema):
                    expected = validate_redacted_config(text)
                    with patch.object(Path, "read_text", side_effect=AssertionError("Full log reads are not allowed")):
                        self.assertEqual(validate_redacted_config(path), expected)
                        self.assertEqual(extract_redacted_config(path), extract_redacted_config(text))
                        self.assertEqual(schema_branch_for_log(path), "develop")
                        self.assertTrue(has_yaml_language_server_directive(path))
                self.assertEqual(expected[0]["line"], 4)

    def test_version_channels_and_newest_version_keep_existing_semantics(self):
        for text, expected in (
            ("Version: 2.5.3", "master"),
            ("Version: 2.5.3\nNewest Version: 2.5.4 (nightly)", "develop"),
            ("vErSiOn: 2.5.3 (Docker: develop)", "develop"),
            ("Nightly mentioned outside a version line", "master"),
        ):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "meta.log"
                path.write_text(text, encoding="utf-8")
                self.assertEqual(schema_branch_for_log(text), expected)
                self.assertEqual(schema_branch_for_log(path), expected)

    def test_large_file_does_not_materialize_the_log_or_all_its_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "meta.log"
            with path.open("wb") as target:
                target.write(b"Version: 2.5.3\nRedacted Config\n[config.py:1] [DEBUG] | timeout: 60 |\n[config.py:2] [DEBUG] | |\nInitializing cache database at /cache\n")
                chunk = b"[kometa.py:1] [DEBUG] | unrelated output |\n" * 1024
                for _ in range(256):
                    target.write(chunk)
                target.write(b"Newest Version: 2.5.4 (Docker: nightly)\n")
            tracemalloc.start()
            try:
                self.assertEqual(extract_redacted_config(path), ("timeout: 60", [3]))
                self.assertFalse(has_yaml_language_server_directive(path))
                self.assertEqual(schema_branch_for_log(path), "develop")
                _current, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            self.assertLess(peak, 1024 * 1024)

    def test_file_decoding_matches_replacement_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "meta.log"
            data = b"bad byte: \xff\nRedacted Config\n[config.py:1] [DEBUG] | name: \xff |\n[config.py:2] [DEBUG] | |\n"
            path.write_bytes(data)
            self.assertEqual(extract_redacted_config(path), extract_redacted_config(data.decode("utf-8", errors="replace")))


if __name__ == "__main__":
    unittest.main()
