import os
from pathlib import Path
import subprocess
import unittest


REPO = Path(__file__).resolve().parents[2]
EXPECTED = {
    line.strip()
    for line in (REPO / "packaging/tests/fixtures/expected_deb_layout.txt").read_text(encoding="utf-8").splitlines()
    if line.strip()
}


class DebPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("IPAD_DEB")
        candidates = [Path(configured)] if configured else sorted((REPO / "dist").glob("ipad-manager_*_amd64.deb"))
        if not candidates or not candidates[-1].is_file():
            raise AssertionError("Set IPAD_DEB to a built ipad-manager amd64 package")
        cls.deb = candidates[-1]

    def command(self, *args):
        return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout

    def test_deb_contains_required_layout(self):
        listing = self.command("dpkg-deb", "--contents", str(self.deb))
        for expected in EXPECTED:
            self.assertIn("." + expected, listing, expected)

    def test_control_declares_runtime_dependencies(self):
        depends = self.command("dpkg-deb", "--field", str(self.deb), "Depends")
        for dependency in ("libgtk-3-0", "libcurl4", "libssl3", "libpcsclite1", "libpaho-mqtt1.3"):
            self.assertIn(dependency, depends)

    def test_config_is_a_conffile(self):
        listing = self.command("dpkg-deb", "--info", str(self.deb))
        self.assertIn(" conffiles", listing)

    def test_package_identity(self):
        self.assertEqual(self.command("dpkg-deb", "--field", str(self.deb), "Package").strip(), "ipad-manager")
        self.assertEqual(self.command("dpkg-deb", "--field", str(self.deb), "Architecture").strip(), "amd64")


if __name__ == "__main__":
    unittest.main()
