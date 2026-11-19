import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from rich.console import Console

from cli.main import main
from cracking import estimate, results, scheduler, statistics
from cracking.parsers import parse_recovery_details
from cracking.validation import validate_campaign


def campaign():
    return {
        "parameters": {
            "hashMode": 1000,
            "hashcatDir": "client-secret-path",
            "flags": ["-O", "-w", "3", "-d", "1"],
        },
        "phases": [
            {
                "id": "client-sensitive-phase",
                "type": "wordlist",
                "wordlist": "client-private-file.txt",
                "rule": "private-rule.rule",
                "statistics": {
                    "wordlist": {"name": "public-words", "version": "2026"},
                    "rule": {"name": "public-rule", "version": "1"},
                },
            },
            {
                "id": "private-phase",
                "type": "wordlist",
                "wordlist": "client-private-file.txt",
            },
            {
                "id": "loopback",
                "type": "loopback",
                "wordlist": "client-private-loopback.txt",
                "rule": "private-rule.rule",
            },
        ],
    }


def fake_phase(**kwargs):
    count = kwargs["phase_id"]
    recovery = parse_recovery_details(
        f"Recovered........: {count * 10}/100 (0.00%) Digests (total), "
        "10/100 (0.00%) Digests (new)\n"
    )
    return {
        "duration": 60,
        "newRecovered": 10,
        "totalRecovered": count * 10,
        "returncode": 1,
        "recoveryDetails": recovery,
    }


class CampaignStatisticsTests(unittest.TestCase):
    def test_hashcat_recovery_uses_unique_counts_and_rejects_missing_or_inconsistent(self):
        parsed = parse_recovery_details(
            "Recovered........: 1,200/2,000 (60%), 200/2,000 (10%)\n"
        )
        self.assertEqual(parsed["remainingBefore"], 1000)
        self.assertEqual(parsed["newRecovered"], 200)
        self.assertIsNone(parse_recovery_details("All hashes found in potfile"))
        self.assertIsNone(parse_recovery_details("Recovered........: 1/2, 2/2"))

    def test_export_import_and_estimates_use_labels_not_phase_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local = root / "local" / "history"
            remote = root / "remote" / "history"
            export = root / "share.json"
            config = campaign()
            with (
                patch.object(results, "HISTORY_DIR", local),
                patch.object(statistics, "HISTORY_DIR", local),
                patch.object(scheduler, "validate_file"),
                patch.object(scheduler, "run_phase", side_effect=fake_phase),
                patch.object(scheduler, "generate_loopback_wordlist", return_value="secret.txt"),
            ):
                run = scheduler.run_campaign(config, root / "hashes.txt", "secret-client")
                self.assertNotIn("hardwareProfile", run)
                self.assertEqual(statistics.export_statistics(export), (3, 0))
                with self.assertRaises(FileExistsError):
                    statistics.export_statistics(export)
                second_export = root / "cli-export.json"
                with (
                    patch.object(sys, "argv", ["password-audit", "crack", "stats",
                                               "--export", str(second_export)]),
                    redirect_stdout(io.StringIO()) as output,
                ):
                    main()
                self.assertIn("Review before sharing", output.getvalue())
                self.assertEqual(json.loads(second_export.read_text()), json.loads(export.read_text()))

                raw = export.read_text(encoding="utf-8")
                for private in (
                    "client", "secret", "localFingerprint",
                    "hashDataset", "hashcatDir", "session", "started",
                ):
                    self.assertNotIn(private, raw)
                shared = json.loads(raw)["records"]
                self.assertEqual(shared[0]["remainingBefore"], 100)
                self.assertEqual(shared[1]["remainingBefore"], 90)
                self.assertIsNone(shared[1]["wordlist"])
                self.assertIsNone(shared[2]["wordlist"])
                self.assertIsNone(shared[2]["rule"])
                self.assertIsNone(statistics.attack_identity(shared[1]))
                self.assertIsNone(statistics.attack_identity(shared[2]))
                display = io.StringIO()
                with patch.object(statistics, "console", Console(file=display, width=180)):
                    statistics.print_phase_statistics()
                self.assertIn("public-words", display.getvalue())
                self.assertIn("10.00%", display.getvalue())
                self.assertIn("Broad Categories", display.getvalue())

                renamed = copy.deepcopy(config)
                renamed["phases"][0]["id"] = "renamed"
                with patch.object(estimate, "load_campaign", return_value={"ntlm": renamed}):
                    result = estimate.estimate_campaign("unused")["ntlm"]
                self.assertEqual(result["estimates"][0]["duration"], 60)
                self.assertEqual(result["estimates"][0]["runs"], 1)
                self.assertIsNone(result["estimates"][1]["duration"])
                archive = next(local.glob("*.json"))
                older = json.loads(archive.read_text(encoding="utf-8"))
                older["hardwareProfile"] = "previous-profile"
                archive.write_text(json.dumps(older), encoding="utf-8")
                with patch.object(estimate, "load_campaign", return_value={"ntlm": renamed}):
                    self.assertEqual(
                        estimate.estimate_campaign("unused")["ntlm"]["estimates"][0]["duration"],
                        60,
                    )
                for change in ("version", "settings", "hash_mode"):
                    modified = copy.deepcopy(renamed)
                    if change == "version":
                        modified["phases"][0]["statistics"]["wordlist"]["version"] = "2027"
                    elif change == "settings":
                        modified["parameters"]["flags"] = ["-O", "-w", "2"]
                    else:
                        modified["parameters"]["hashMode"] = 3000
                    with patch.object(estimate, "load_campaign", return_value={"ntlm": modified}):
                        self.assertIsNone(
                            estimate.estimate_campaign("unused")["ntlm"]["estimates"][0]["duration"]
                        )

            with patch.object(statistics, "HISTORY_DIR", remote):
                self.assertEqual(statistics.import_statistics(export), (3, 0))
                self.assertEqual(statistics.import_statistics(export), (0, 3))
                with (
                    patch.object(sys, "argv", ["password-audit", "crack", "stats",
                                               "--import", str(export)]),
                    redirect_stdout(io.StringIO()) as output,
                ):
                    main()
                self.assertIn("Imported 0 phase records; 3 already present.", output.getvalue())
                with patch.object(estimate, "load_campaign", return_value={"ntlm": config}):
                    self.assertIsNone(
                        estimate.estimate_campaign("unused")["ntlm"]["estimates"][0]["duration"]
                    )

                tampered = json.loads(raw)
                tampered["records"][0]["customer_path"] = "sensitive"
                bad = root / "bad.json"
                bad.write_text(json.dumps(tampered), encoding="utf-8")
                before = statistics._shared_file().read_text(encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "fields"):
                    statistics.import_statistics(bad)
                self.assertEqual(statistics._shared_file().read_text(encoding="utf-8"), before)

                tampered = json.loads(raw)
                tampered["records"][0]["newRecovered"] = 11
                bad.write_text(json.dumps(tampered), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "Conflicting"):
                    statistics.import_statistics(bad)
                self.assertEqual(statistics._shared_file().read_text(encoding="utf-8"), before)

    def test_missing_measurements_are_not_exported_as_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            history = root / "history"
            with (
                patch.object(results, "HISTORY_DIR", history),
                patch.object(statistics, "HISTORY_DIR", history),
                patch.object(scheduler, "validate_file"),
                patch.object(scheduler, "run_phase", return_value={
                    "duration": 10, "newRecovered": 0, "totalRecovered": 0, "returncode": 0,
                }),
            ):
                config = campaign()
                config["phases"] = config["phases"][:1]
                scheduler.run_campaign(config, root / "hashes.txt", "run")
                self.assertEqual(statistics.local_statistics()[1], 1)
                with self.assertRaisesRegex(ValueError, "No measured"):
                    statistics.export_statistics(root / "share.json")
                self.assertFalse((root / "share.json").exists())

    def test_private_or_unknown_settings_cannot_be_compared(self):
        config = campaign()
        validate_campaign(config)
        settings = statistics.describe_settings(["-O", "--runtime", "20"])
        self.assertTrue(settings["otherFlags"])
        self.assertIsNone(statistics.phase_identity(1000, config["phases"][0], settings))
        config["phases"][0]["statistics"]["wordlist"]["name"] = "client/path"
        with self.assertRaises(ValueError):
            validate_campaign(config)

    def test_incompatible_history_is_excluded_without_counting_as_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            history = Path(directory) / "history"
            history.mkdir()
            (history / "legacy.json").write_text(json.dumps({
                "state": "completed", "hashMode": "1000",
                "phases": [{"id": "old-phase", "duration": 30, "newRecovered": 5}],
            }), encoding="utf-8")
            output = io.StringIO()
            with (
                patch.object(statistics, "HISTORY_DIR", history),
                patch.object(statistics, "console", Console(file=output, width=180)),
                redirect_stdout(io.StringIO()) as message,
            ):
                statistics.print_phase_statistics()
                with self.assertRaisesRegex(ValueError, "No measured"):
                    statistics.export_statistics(Path(directory) / "share.json")
            self.assertIn("Excluded 1 phases without usable statistics.", message.getvalue())
            self.assertNotIn("old-phase", output.getvalue())


if __name__ == "__main__":
    unittest.main()
