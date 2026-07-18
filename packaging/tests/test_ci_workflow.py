import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ubuntu-build.yml"


class UbuntuBuildWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_inspects_current_manager_binary(self):
        self.assertIn("ipad_host_app/build/ipad-manager", self.workflow)
        self.assertNotIn("ipad_host_app/build/ipad_host_app", self.workflow)

    def test_smoke_tests_manager_cli(self):
        self.assertIn('"$manager" --help', self.workflow)
        self.assertIn('"$manager" --version', self.workflow)

    def test_rejects_unresolved_sdk_dependency(self):
        self.assertIn("ldd \"$manager\"", self.workflow)
        self.assertIn("libipa.so =>", self.workflow)
        self.assertIn("not found", self.workflow)


if __name__ == "__main__":
    unittest.main()
