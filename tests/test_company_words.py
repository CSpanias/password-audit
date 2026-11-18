import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from analysis.parsers import load_company_words
from auditing.company_words import (
    prepare_company_word_sources,
    save_company_word_snapshot,
)
from ntds.exports import export_results


class CompanyWordListTests(unittest.TestCase):
    def test_loads_and_deduplicates_multiple_wordlists(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            generated = root / "generated.txt"
            curated = root / "curated.txt"
            generated.write_text("Acme\nDomain\n", encoding="utf-8")
            curated.write_text("ACME\nProduct\n", encoding="utf-8")

            self.assertEqual(
                load_company_words([generated, curated]),
                ["acme", "domain", "product"],
            )

    def test_warns_when_curated_list_appears_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            generated = root / "generated.txt"
            curated = root / "company-words.txt"
            state = root / ".company-words-state.json"
            generated.write_text("domain\n", encoding="utf-8")
            curated.write_text("Acme\nProduct\n", encoding="utf-8")

            with patch("auditing.company_words.info"), patch(
                "auditing.company_words.warn"
            ) as warn:
                sources, snapshot = prepare_company_word_sources(
                    generated,
                    custom_path=curated,
                    state_path=state,
                )
                save_company_word_snapshot(state, snapshot)
                prepare_company_word_sources(
                    generated,
                    custom_path=curated,
                    state_path=state,
                )

            self.assertEqual(sources, [generated, curated])
            self.assertTrue(
                any(
                    "appears unchanged" in call.args[0]
                    for call in warn.call_args_list
                )
            )

    def test_uses_conventional_curated_list_when_present(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            generated = root / "generated.txt"
            curated = root / "company-words.txt"
            generated.write_text("domain\n", encoding="utf-8")
            curated.write_text("Acme\n", encoding="utf-8")

            with patch("auditing.company_words.info"):
                sources, snapshot = prepare_company_word_sources(
                    generated,
                    state_path=root / "state.json",
                    default_custom_path=curated,
                )

            self.assertEqual(sources, [generated, curated])
            self.assertIsNotNone(snapshot)

    def test_export_replaces_stale_generated_wordlist_with_empty_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory)
            generated = output_directory / "company-words.txt"
            generated.write_text("stale-term\n", encoding="utf-8")
            results = {
                "enabled_users": [],
                "enabled": [],
                "disabled": [],
                "machines": [],
                "ntlm_hashes": [],
                "lm_users": [],
                "lm_hashes": [],
                "filtered_users": [],
                "domain_admins": [],
                "mapped_ntlm_passwords": [],
                "mapped_lm_passwords": [],
                "mapped_lm_da_passwords": [],
                "lm_da_users": [],
                "lm_da_candidates": [],
                "company_words": [],
                "policy": {},
            }

            export_results(results, output_directory)

            self.assertEqual(generated.read_text(encoding="utf-8"), "")


if __name__ == "__main__":
    unittest.main()
