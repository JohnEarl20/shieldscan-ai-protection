from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
EXTENSION = ROOT / "browser_extension"


class BrowserExtensionTests(unittest.TestCase):
    def test_manifest_references_existing_files(self) -> None:
        manifest = json.loads((EXTENSION / "manifest.json").read_text(encoding="utf-8"))

        self.assertEqual(manifest["manifest_version"], 3)
        self.assertTrue((EXTENSION / manifest["action"]["default_popup"]).exists())
        self.assertTrue((EXTENSION / manifest["background"]["service_worker"]).exists())

        for script in manifest["content_scripts"][0]["js"]:
            self.assertTrue((EXTENSION / script).exists())

    def test_blocked_page_assets_exist(self) -> None:
        for file_name in ["blocked.html", "blocked.css", "blocked.js"]:
            self.assertTrue((EXTENSION / file_name).exists())

    def test_popup_hidden_rule_exists(self) -> None:
        css = (EXTENSION / "popup.css").read_text(encoding="utf-8")

        self.assertIn("[hidden]", css)
        self.assertIn("display: none", css)


if __name__ == "__main__":
    unittest.main()
