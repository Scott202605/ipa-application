import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
DIAGNOSTICS = REPO / "packaging" / "linux" / "ipad-manager-diagnostics"


class DiagnosticsRedactionTests(unittest.TestCase):
    def test_diagnostics_redacts_secret_values(self):
        with tempfile.TemporaryDirectory(prefix="ipad-diag-") as tmp:
            root = Path(tmp) / "root"
            config_dir = root / "etc" / "ipad-manager"
            log_dir = root / "var" / "log" / "ipad-manager"
            config_dir.mkdir(parents=True)
            log_dir.mkdir(parents=True)
            secret = "unique-secret-8429"
            (config_dir / "config.json").write_text(
                json.dumps(
                    {
                        "hostname": "example.invalid",
                        "password": secret,
                        "activation_code": f"LPA:1${secret}",
                        "nested": {"client_key": secret},
                    }
                ),
                encoding="utf-8",
            )
            (log_dir / "manager.log").write_text(f"password={secret}\n", encoding="utf-8")
            output = Path(tmp) / "diagnostics.tar.gz"
            env = os.environ.copy()
            env["IPAD_ROOT"] = str(root)
            result = subprocess.run(
                [str(DIAGNOSTICS), str(output)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            with tarfile.open(output, "r:gz") as archive:
                extracted = "\n".join(
                    archive.extractfile(member).read().decode("utf-8", errors="replace")
                    for member in archive.getmembers()
                    if member.isfile()
                )
            self.assertNotIn(secret, extracted)
            self.assertIn("<redacted>", extracted)
            self.assertIn("example.invalid", extracted)


if __name__ == "__main__":
    unittest.main()
