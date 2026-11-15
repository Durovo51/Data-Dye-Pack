"""The lock password reads its new name first and still takes the old one."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from dyepack import drive

NEW, OLD = "DYEPACK_LOCK_PASSWORD", "DYEPACK_VAULT_PASSWORD"


class LockPasswordTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.env = self.tmp / ".env"

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def read(self, text, environ=None):
        self.env.write_text(text)
        with mock.patch.dict(os.environ, environ or {}):
            for key in (NEW, OLD):
                if key not in (environ or {}):
                    os.environ.pop(key, None)
            return drive.vault_password(self.env)

    def test_new_name_in_the_file(self):
        self.assertEqual(self.read(f"{NEW}=new pass\n"), "new pass")

    def test_old_name_still_works(self):
        self.assertEqual(self.read(f"{OLD}=old pass\n"), "old pass")

    def test_new_name_wins_over_the_old_one(self):
        self.assertEqual(self.read(f"{OLD}=old pass\n{NEW}=new pass\n"), "new pass")

    def test_empty_new_line_falls_back_to_the_old_one(self):
        self.assertEqual(self.read(f"{NEW}=\n{OLD}=old pass\n"), "old pass")

    def test_environment_comes_before_the_file(self):
        self.assertEqual(self.read(f"{NEW}=from file\n", {NEW: "from env"}), "from env")
        self.assertEqual(self.read(f"{NEW}=from file\n", {OLD: "old env"}), "old env")

    def test_nothing_set_gives_none(self):
        self.assertIsNone(self.read(f"{NEW}=\n{OLD}=\n"))
        self.assertIsNone(drive.vault_password(self.tmp / "missing.env"))


if __name__ == "__main__":
    unittest.main()
