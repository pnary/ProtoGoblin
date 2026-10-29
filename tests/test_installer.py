"""
Unit tests for install_to_steam.sh deployment check and update functionality.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALL_SCRIPT = os.path.join(SCRIPT_DIR, "install_to_steam.sh")


class TestInstallToSteam(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.dest_dir = self.tmp_dir.name
        self.tool_dir = os.path.join(self.dest_dir, "ProtoGoblin-local")
        self.home = os.path.join(self.dest_dir, "home")
        os.makedirs(self.home)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def run_installer(self, *args):
        cmd = [
            INSTALL_SCRIPT,
            "--dest", self.dest_dir,
            *args
        ]
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env={**os.environ, "HOME": self.home})

    def test_check_when_not_deployed(self):
        res = self.run_installer("--check")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("No existing ProtoGoblin deployment found", res.stdout)

    def test_check_and_update_lifecycle(self):
        # 1. Populate mock deployment directory with base proton structure
        os.makedirs(os.path.join(self.tool_dir, "files", "bin"), exist_ok=True)
        with open(os.path.join(self.tool_dir, "proton"), "w") as f:
            f.write("#!/bin/sh\necho old")
        with open(os.path.join(self.tool_dir, "compatibilitytool.vdf"), "w") as f:
            f.write('"compatibilitytools" { "compat_tools" { "ProtoGoblin-local" {} } }')

        # 2. Check should report outdated components
        res_check1 = self.run_installer("--check")
        self.assertNotEqual(res_check1.returncode, 0)
        self.assertIn("outdated component(s)", res_check1.stdout)

        # 3. Running default installer should detect existing deployment and update it
        res_update = self.run_installer()
        self.assertEqual(res_update.returncode, 0, f"Update failed: {res_update.stderr}")
        self.assertIn("Detected existing ProtoGoblin deployment", res_update.stdout)
        self.assertIn("Existing ProtoGoblin deployment successfully updated!", res_update.stdout)

        # 4. Check should now report fully up to date
        res_check2 = self.run_installer("--check")
        self.assertEqual(res_check2.returncode, 0, f"Check failed: {res_check2.stderr}")
        self.assertIn("ProtoGoblin deployment is fully up to date", res_check2.stdout)

        # 5. Subsequent run without modifications should report already up to date
        res_noop = self.run_installer()
        self.assertEqual(res_noop.returncode, 0)
        self.assertIn("Existing deployment is already up to date", res_noop.stdout)

        # 6. Tamper with a file and verify update fixes it
        with open(os.path.join(self.tool_dir, "protogoblin.py"), "w") as f:
            f.write("# tampered")
        res_check3 = self.run_installer("--check")
        self.assertNotEqual(res_check3.returncode, 0)
        self.assertIn("protogoblin.py", res_check3.stdout)

        res_fix = self.run_installer("--update")
        self.assertEqual(res_fix.returncode, 0)
        self.assertIn("Existing ProtoGoblin deployment successfully updated!", res_fix.stdout)

        res_check4 = self.run_installer("--check")
        self.assertEqual(res_check4.returncode, 0)
        self.assertIn("ProtoGoblin deployment is fully up to date", res_check4.stdout)

    def test_mangohud_content_changes_are_detected(self):
        os.makedirs(self.tool_dir)
        (Path(self.tool_dir) / "proton").write_text("old")
        self.assertEqual(self.run_installer("--update").returncode, 0)
        library = Path(self.tool_dir) / "files/lib/x86_64-linux-gnu/libMangoHud.so"
        library.write_bytes(b"stale binary")
        checked = self.run_installer("--check")
        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("libMangoHud.so", checked.stdout)
        self.assertEqual(self.run_installer("--update").returncode, 0)
        bundled = Path(SCRIPT_DIR) / "share/protogoblin/mangohud/lib64/libMangoHud.so"
        self.assertEqual(library.read_bytes(), bundled.read_bytes())
        self.assertFalse((Path(self.home) / ".local").exists())


if __name__ == "__main__":
    unittest.main()
