import tempfile
import unittest
from pathlib import Path

import gui_setup


class GuiSetupTests(unittest.TestCase):
    def write(self, root: Path, content: str) -> Path:
        path = root / "settings.json"
        path.write_text(content, encoding="utf-8")
        return path

    def test_sets_key_in_empty_object(self):
        text, changed = gui_setup.set_jsonc_key("{}\n", "remote.SSH.path", "/opt/sshotp")
        self.assertTrue(changed)
        self.assertEqual(text, '{ "remote.SSH.path": "/opt/sshotp" }\n')

    def test_inserts_key_and_keeps_comments(self):
        original = '{\n    // keep me\n    "editor.fontSize": 14\n}\n'
        text, changed = gui_setup.set_jsonc_key(original, "remote.SSH.path", "/opt/sshotp")
        self.assertTrue(changed)
        self.assertIn("// keep me", text)
        self.assertIn('"editor.fontSize": 14', text)
        self.assertIn('"remote.SSH.path": "/opt/sshotp"', text)

    def test_updates_existing_key_and_is_idempotent(self):
        original = '{\n    "remote.SSH.path": "old-ssh",\n    "a": 1\n}\n'
        text, changed = gui_setup.set_jsonc_key(original, "remote.SSH.path", "/opt/sshotp")
        self.assertTrue(changed)
        self.assertIn('"remote.SSH.path": "/opt/sshotp"', text)
        self.assertIn('"a": 1', text)
        again, changed_again = gui_setup.set_jsonc_key(text, "remote.SSH.path", "/opt/sshotp")
        self.assertFalse(changed_again)
        self.assertEqual(again, text)

    def test_windows_path_is_escaped(self):
        text, changed = gui_setup.set_jsonc_key("{\n}\n", "remote.SSH.path", r"C:\ssh otp\sshotp.cmd")
        self.assertTrue(changed)
        self.assertIn("C:\\\\ssh otp\\\\sshotp.cmd", text)

    def test_print_only_does_not_write(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = self.write(root, '{\n    "a": 1\n}\n')
            before = path.read_text(encoding="utf-8")
            changed, backup = gui_setup.update_settings(path, "/opt/sshotp", dry_run=True)
            self.assertTrue(changed)
            self.assertIsNone(backup)
            self.assertEqual(path.read_text(encoding="utf-8"), before)

    def test_update_writes_backup_and_keeps_other_keys(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = self.write(root, '{\n    "a": 1\n}\n')
            changed, backup = gui_setup.update_settings(path, "/opt/sshotp")
            self.assertTrue(changed)
            self.assertIsNotNone(backup)
            self.assertTrue(Path(backup).exists())
            content = path.read_text(encoding="utf-8")
            self.assertIn('"remote.SSH.path": "/opt/sshotp"', content)
            self.assertIn('"a": 1', content)


if __name__ == "__main__":
    unittest.main()
