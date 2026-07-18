import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
HEALTH = REPO / "packaging" / "linux" / "ipad-manager-health"


class HealthToolTests(unittest.TestCase):
    def test_health_json_has_stable_schema_and_check_ids(self):
        with tempfile.TemporaryDirectory(prefix="ipad-health-") as root:
            env = os.environ.copy()
            env["IPAD_ROOT"] = root
            result = subprocess.run(
                [str(HEALTH), "--json"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                check=False,
            )
            data = json.loads(result.stdout)
            self.assertEqual(data["schema_version"], 1)
            self.assertEqual(
                {item["id"] for item in data["checks"]},
                {"files", "manifest", "architecture", "linkage", "abi", "config", "gui"},
            )
            self.assertTrue(all(item["status"] in {"pass", "warn", "fail"} for item in data["checks"]))
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
