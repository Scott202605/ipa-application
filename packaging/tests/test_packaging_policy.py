from pathlib import Path
import unittest


REPO = Path(__file__).resolve().parents[2]
WINDOWS_PACKAGING = REPO / "packaging" / "windows"
EXPECTED_LAYOUT = (
    REPO / "packaging" / "tests" / "fixtures" / "expected_deb_layout.txt"
)


class PackagingPolicyTests(unittest.TestCase):
    def _windows_text(self) -> str:
        files = sorted(WINDOWS_PACKAGING.glob("*"))
        if not files:
            self.skipTest("Windows packaging scripts are introduced in Task 6")
        return "\n".join(
            path.read_text(encoding="utf-8", errors="replace") for path in files
        )

    def test_windows_scripts_always_select_ubuntu_root(self):
        text = self._windows_text()
        self.assertIn("--distribution", text)
        self.assertIn("Ubuntu", text)
        self.assertIn("--user", text)
        self.assertIn("root", text)

    def test_windows_scripts_never_unregister_or_delete_distro(self):
        text = self._windows_text().lower()
        self.assertNotIn("wsl --unregister", text)
        self.assertNotIn("wsl.exe --unregister", text)
        self.assertNotIn("wslconfig /u", text)

    def test_deb_uses_private_sdk_path(self):
        expected = EXPECTED_LAYOUT.read_text(encoding="utf-8")
        self.assertIn("/usr/lib/ipad-manager/libipa.so", expected)
        self.assertNotIn("/usr/lib/libipa.so", expected)


if __name__ == "__main__":
    unittest.main()
