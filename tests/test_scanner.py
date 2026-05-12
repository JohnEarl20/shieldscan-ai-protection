from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from ai_scam_protection.config import ProtectionConfig, ensure_state
from ai_scam_protection.quarantine import QuarantineManager
from ai_scam_protection.scanner import parse_zone_identifier, scan_file, sha256_file


class ScannerTests(unittest.TestCase):
    def test_detects_double_extension(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = ProtectionConfig.default(root)
            ensure_state(config)
            sample = root / "invoice.pdf.exe"
            sample.write_bytes(b"MZfake")

            result = scan_file(sample, config, bad_hashes=set())

            self.assertGreaterEqual(result.score, config.medium_threshold)
            self.assertTrue(any(finding.rule == "double_extension" for finding in result.findings))

    def test_detects_known_bad_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = ProtectionConfig.default(root)
            ensure_state(config)
            sample = root / "payload.bin"
            sample.write_bytes(b"known bad content")
            digest = sha256_file(sample)

            result = scan_file(sample, config, bad_hashes={digest})

            self.assertEqual(result.level, "high")
            self.assertTrue(result.should_block)

    def test_detects_suspicious_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = ProtectionConfig.default(root)
            ensure_state(config)
            sample = root / "update.ps1"
            sample.write_text(
                "powershell -WindowStyle Hidden -EncodedCommand "
                + "A" * 160
                + "\nInvoke-Expression $x\n",
                encoding="utf-8",
            )

            result = scan_file(sample, config, bad_hashes=set())

            self.assertEqual(result.level, "high")
            self.assertTrue(result.should_block)

    def test_quarantine_and_restore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = ProtectionConfig.default(root)
            ensure_state(config)
            sample = root / "invoice.pdf.exe"
            sample.write_bytes(b"MZfake")
            result = scan_file(sample, config, bad_hashes=set())

            manager = QuarantineManager(config)
            item = manager.quarantine(result)

            self.assertFalse(sample.exists())
            self.assertTrue(item.stored_path.exists())
            restored = manager.restore(item.item_id)
            self.assertEqual(restored, sample.resolve())
            self.assertTrue(sample.exists())

    def test_parse_zone_identifier_source_urls(self) -> None:
        source = parse_zone_identifier(
            "[ZoneTransfer]\n"
            "ZoneId=3\n"
            "ReferrerUrl=https://example.test/download\n"
            "HostUrl=https://cdn.example.test/payload.exe\n"
        )

        self.assertIsNotNone(source)
        assert source is not None
        self.assertTrue(source.is_internet_zone)
        self.assertEqual(source.host_url, "https://cdn.example.test/payload.exe")
        self.assertEqual(source.referrer_url, "https://example.test/download")


if __name__ == "__main__":
    unittest.main()
