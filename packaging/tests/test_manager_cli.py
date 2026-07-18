import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
SDK_BUILD = REPO / "ipa_sdk_pc" / "build-release-gates" / "release"
SDK_LIBRARY = SDK_BUILD / "ipa-src" / "hw" / "linux" / "libipa.so"


class ManagerCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_dir = Path(tempfile.mkdtemp(prefix="ipad-manager-cli-"))
        subprocess.run(
            [
                "cmake",
                "-S",
                str(REPO / "ipad_host_app"),
                "-B",
                str(cls.build_dir),
                "-DCMAKE_BUILD_TYPE=Release",
                "-DENABLE_DEBUG=OFF",
                f"-DIPAD_SDK_ROOT={REPO / 'ipa_sdk_pc'}",
                f"-DIPA_LIBRARY={SDK_LIBRARY}",
            ],
            check=True,
        )
        subprocess.run(
            ["cmake", "--build", str(cls.build_dir), "--parallel", "2"],
            check=True,
        )
        cls.manager = cls.build_dir / "ipad_host_app"
        if not cls.manager.exists():
            cls.manager = cls.build_dir / "ipad-manager"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.build_dir, ignore_errors=True)

    def run_manager(self, *args):
        env = os.environ.copy()
        env.pop("DISPLAY", None)
        env.pop("WAYLAND_DISPLAY", None)
        return subprocess.run(
            [str(self.manager), *map(str, args)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
        )

    def test_help_does_not_require_display(self):
        result = self.run_manager("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--config", result.stdout)

    def test_version_does_not_require_display(self):
        result = self.run_manager("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"IPAd Manager 1\.1\.0")

    def test_invalid_config_fails_without_opening_gui(self):
        invalid = self.build_dir / "invalid.json"
        invalid.write_text("{not-json", encoding="utf-8")
        result = self.run_manager("--check-config", invalid)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("GTK", result.stderr)
        self.assertNotIn("未知参数", result.stderr)
        self.assertIn("config", (result.stdout + result.stderr).lower())


if __name__ == "__main__":
    unittest.main()
