import re
import unittest
from pathlib import Path
from urllib.parse import unquote


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
README = REPOSITORY_ROOT / "README.md"


class ReadmeCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = README.read_bytes()
        cls.text = cls.raw.decode("utf-8")

    def test_is_clean_utf8_without_known_mojibake(self):
        self.assertNotIn("\ufffd", self.text)
        for marker in ("馃", "鈹", "锛", "绋嬪簭"):
            self.assertNotIn(marker, self.text)

    def test_describes_current_product_delivery(self):
        required = (
            "IPAd Manager 1.1.0",
            "ipad-manager_<version>_amd64.deb",
            "IPAd-Manager-Setup-<version>-x64.exe",
            "ipad-manager-health --json",
            "ipad-manager-diagnostics",
            "WSL2",
            "WSLg",
            "Signed=false",
            "SHA256SUMS",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, self.text)

    def test_describes_sdk_contract_and_honest_capabilities(self):
        required = (
            "ipa_init_library",
            "ipa_deinit_library",
            "libipa.so",
            "Available",
            "Environment-dependent",
            "Not implemented",
            "eNotImpl",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, self.text)

    def test_does_not_recommend_legacy_product_entry_points(self):
        self.assertNotIn("一键启动", self.text)
        self.assertNotIn("./ipad_host_app", self.text)

    def test_repository_relative_links_exist(self):
        links = re.findall(r"\[[^\]]+\]\(([^)]+)\)", self.text)
        for link in links:
            target = link.strip().strip("<>").split("#", 1)[0]
            if not target or re.match(r"^(?:https?://|mailto:)", target):
                continue
            path = REPOSITORY_ROOT / unquote(target)
            with self.subTest(link=link):
                self.assertTrue(path.exists(), f"Missing README link target: {link}")


if __name__ == "__main__":
    unittest.main()
