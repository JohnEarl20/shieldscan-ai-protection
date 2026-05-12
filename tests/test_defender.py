from __future__ import annotations

import unittest

from ai_scam_protection.defender import powershell_single_quoted


class DefenderTests(unittest.TestCase):
    def test_powershell_single_quote_handles_spaces(self) -> None:
        value = r"C:\Users\John Earl Mirabete\Downloads\Claude Setup.exe"

        self.assertEqual(
            powershell_single_quoted(value),
            r"'C:\Users\John Earl Mirabete\Downloads\Claude Setup.exe'",
        )

    def test_powershell_single_quote_escapes_single_quotes(self) -> None:
        value = r"C:\Downloads\John's App.exe"

        self.assertEqual(powershell_single_quoted(value), r"'C:\Downloads\John''s App.exe'")


if __name__ == "__main__":
    unittest.main()
