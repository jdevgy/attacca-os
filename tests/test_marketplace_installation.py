"""Public GitHub catalogs and documented native installation contract."""

import io
import json
from pathlib import Path
import unittest
import zipfile

import attacca


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/jdevgy/attacca-os"


class MarketplaceInstallationTests(unittest.TestCase):
    def test_codex_catalog_preserves_existing_identifier_and_root_source(self):
        catalog = json.loads((ROOT / ".agents/plugins/marketplace.json").read_text())
        self.assertEqual(catalog["name"], "attacca-local")
        self.assertEqual(catalog["interface"]["displayName"], "Attacca")
        entries = [item for item in catalog["plugins"] if item["name"] == "attacca"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["source"], {"source": "local", "path": "./"})
        self.assertEqual(entries[0]["policy"]["installation"], "AVAILABLE")
        self.assertEqual(entries[0]["policy"]["authentication"], "ON_INSTALL")
        self.assertTrue(entries[0]["category"])

    def test_claude_catalog_preserves_existing_identifier_and_root_source(self):
        catalog = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text())
        self.assertEqual(catalog["name"], "agentg")
        self.assertEqual(catalog["owner"]["name"], "Attacca")
        self.assertEqual([(item["name"], item["source"])
                          for item in catalog["plugins"]], [("attacca", "./")])

    def test_both_native_manifests_link_to_public_repository(self):
        for name in (".codex-plugin/plugin.json", ".claude-plugin/plugin.json"):
            with self.subTest(manifest=name):
                manifest = json.loads((ROOT / name).read_text())
                self.assertEqual(manifest["name"], "attacca")
                self.assertEqual(manifest["author"]["name"], "Attacca")
                self.assertEqual(manifest["homepage"], REPOSITORY)
                self.assertEqual(manifest["repository"], REPOSITORY)

    def test_public_docs_use_actual_repository_and_explicit_bootstrap(self):
        readme = (ROOT / "README.md").read_text()
        self.assertNotIn("jdevgy/attacca-ai", readme)
        self.assertNotIn("jdevgy/attacca-ai", (ROOT / "SECURITY.md").read_text())
        native = readme.split("## Install directly from GitHub marketplaces", 1)[1].split(
            "## Advanced reference", 1)[0]
        prepare = "python3 install.py --runtime-only --url http://127.0.0.1:4173"
        commands = (
            "codex plugin marketplace add jdevgy/attacca-os",
            "codex plugin add attacca@attacca-local",
            "claude plugin marketplace add jdevgy/attacca-os",
            "claude plugin install attacca@agentg",
        )
        for command in commands:
            self.assertIn(command, native)
            self.assertLess(native.index(prepare), native.index(command))
        self.assertIn("does not start or restart the server", native)
        self.assertIn("native marketplace installation alone", native)
        self.assertIn("$attacca:setup", native)
        self.assertIn("/attacca:setup", native)

    def test_distributed_archive_keeps_catalogs_and_runtime_preparation(self):
        archive = zipfile.ZipFile(io.BytesIO(attacca.build_plugin_zip(
            "http://127.0.0.1:9")))
        with archive:
            self.assertEqual(archive.read("install.py"), (ROOT / "install.py").read_bytes())
            for name in (".agents/plugins/marketplace.json", ".claude-plugin/marketplace.json"):
                self.assertEqual(archive.read(name), (ROOT / name).read_bytes())
            self.assertIn("--runtime-only", archive.read("README.md").decode())
            for excluded in ("AGENTS.md", "CLAUDE.md", "attacca.db", ".attacca/project.json"):
                self.assertNotIn(excluded, archive.namelist())


if __name__ == "__main__":
    unittest.main()
