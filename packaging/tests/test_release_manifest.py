import json
import os
from pathlib import Path
import unittest


REPO = Path(__file__).resolve().parents[2]
DIST = Path(os.environ.get("IPAD_DIST", REPO / "dist"))


class ReleaseManifestTests(unittest.TestCase):
    def test_release_directory_contains_required_artifacts(self):
        metadata = json.loads((DIST / "release.json").read_text(encoding="utf-8-sig"))
        version = metadata["version"]
        required = {
            f"ipad-manager_{version}_amd64.deb",
            f"IPAd-Manager-Setup-{version}-x64.exe",
            f"IPAd-Manager-Setup-{version}-x64.json",
            "SHA256SUMS",
            "BUILD_METADATA.txt",
            "DEPENDENCIES.lock.txt",
            "install-manifest.json",
            "release.json",
        }
        self.assertTrue(required.issubset({path.name for path in DIST.iterdir()}))

    def test_release_commit_matches_requested_commit(self):
        metadata = json.loads((DIST / "release.json").read_text(encoding="utf-8-sig"))
        expected = os.environ.get("IPAD_GIT_COMMIT")
        if expected:
            self.assertEqual(metadata["git_commit"], expected)


if __name__ == "__main__":
    unittest.main()
