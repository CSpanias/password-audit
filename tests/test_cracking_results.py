import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cracking import scheduler
from cracking.results import write_results


class CampaignResultTests(unittest.TestCase):
    def test_write_results_keeps_previous_file_if_serialization_fails(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            hash_file = Path(temporary_directory) / "hashes.txt"
            output_file = Path(temporary_directory) / "campaign-results.json"
            original = {
                "campaign": "campaign",
                "hashDataset": str(hash_file),
                "state": "running",
            }
            write_results(original)

            changed = dict(original, state="interrupted")
            with (
                patch(
                    "cracking.results.json.dump",
                    side_effect=TypeError("not serializable"),
                ),
                self.assertRaises(TypeError),
            ):
                write_results(changed)

            self.assertEqual(
                json.loads(output_file.read_text(encoding="utf-8")),
                original,
            )
            self.assertEqual(
                {path.name for path in Path(temporary_directory).iterdir()},
                {output_file.name},
            )

    def test_interrupted_campaign_requires_a_new_name(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            hash_file = Path(temporary_directory) / "hashes.txt"
            existing_results = {
                "state": "interrupted",
                "currentPhase": "first",
                "currentSession": "campaign-first",
            }
            config = {
                "parameters": {"hashMode": 1000},
                "phases": [{
                    "id": "first",
                    "type": "wordlist",
                    "wordlist": "words.txt",
                }],
            }

            with (
                patch.object(
                    scheduler,
                    "load_results",
                    return_value=existing_results,
                ),
                patch.object(scheduler, "warn") as warn,
                self.assertRaises(SystemExit),
            ):
                scheduler.run_campaign(
                    config=config,
                    hash_file=hash_file,
                    campaign_name="campaign",
                )

            warn.assert_any_call(
                "Campaign resume is not supported. Use a new campaign name "
                "to start again from the first phase."
            )
