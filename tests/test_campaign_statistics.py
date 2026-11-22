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

import cli.audit as cli_audit
import cli.crack as cli_crack
import cli.main as cli_main
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
                "wordlist": "client-directory/public-words.txt",
                "rule": "client-directory\\public-rule.rule",
            },
            {
                "id": "private-phase",
                "type": "wordlist",
                "wordlist": "public-words.txt",
            },
            {
                "id": "loopback",
                "type": "loopback",
                "wordlist": "client-private-loopback.txt",
                "rule": "public-rule.rule",
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
    def test_test_campaign_keeps_results_but_does_not_change_statistics_or_estimates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            history = root / "history"
            config = campaign()
            config["phases"] = config["phases"][:1]
            with (
                patch.object(results, "HISTORY_DIR", history),
                patch.object(statistics, "HISTORY_DIR", history),
                patch.object(scheduler, "validate_file"),
                patch.object(scheduler, "run_phase", side_effect=fake_phase),
                patch.object(estimate, "load_campaign", return_value={"ntlm": config}),
            ):
                scheduler.run_campaign(config, root / "hashes.txt", "real")
                existing_history = list(history.glob("*.json"))
                before_stats = statistics.local_statistics()
                before_estimate = estimate.estimate_campaign("unused")

                test_result = scheduler.run_campaign(
                    config, root / "hashes.txt", "test", test_run=True,
                )

                self.assertEqual(test_result["state"], "completed")
                self.assertEqual(
                    json.loads((root / "test-results.json").read_text(encoding="utf-8")),
                    test_result,
                )
                self.assertEqual(list(history.glob("*.json")), existing_history)
                self.assertEqual(statistics.local_statistics(), before_stats)
                self.assertEqual(estimate.estimate_campaign("unused"), before_estimate)
                self.assertEqual(len(existing_history), 1)

    def test_test_flag_is_forwarded_by_audit_and_crack_cli(self):
        cases = (
            (["audit", "-N", "ntds", "-B", "zip", "-C", "config", "-G", "run"],
             "run_audit_workflow"),
            (["crack", "run", "-H", "hashes", "-C", "config", "-G", "run"],
             "run_cracking_campaign"),
        )
        for arguments, handler in cases:
            for enabled in (False, True):
                with (
                    self.subTest(command=arguments[0], enabled=enabled),
                    patch.object(sys, "argv", ["password-audit", *arguments] +
                                 (["--test"] if enabled else [])),
                    patch.object(cli_main, handler) as command,
                ):
                    main()
                    parsed = command.call_args.args[0]
                    self.assertEqual(parsed.test_run, enabled)
                    if handler == "run_audit_workflow":
                        with patch.object(cli_audit, "run_audit") as run:
                            cli_audit.run_audit_workflow(parsed)
                    else:
                        with (
                            patch.object(cli_crack, "load_campaign",
                                         return_value={"ntlm": campaign()}),
                            patch.object(cli_crack, "run_campaign") as run,
                            patch.object(cli_crack, "print_summary"),
                        ):
                            cli_crack.run_cracking_campaign(parsed)
                    self.assertEqual(run.call_args.kwargs["test_run"], enabled)

    def test_hashcat_recovery_uses_unique_counts_and_rejects_missing_or_inconsistent(self):
        parsed = parse_recovery_details(
            "Recovered........: 1,200/2,000 (60%), 200/2,000 (10%)\n"
        )
        self.assertEqual(parsed["remainingBefore"], 1000)
        self.assertEqual(parsed["newRecovered"], 200)
        self.assertIsNone(parse_recovery_details("All hashes found in potfile"))
        self.assertIsNone(parse_recovery_details("Recovered........: 1/2, 2/2"))

    def test_export_import_and_estimates_use_filenames_not_phase_ids(self):
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
                self.assertIn("Review filenames and counts", output.getvalue())
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
                self.assertEqual(shared[0]["wordlist"], "public-words.txt")
                self.assertEqual(shared[0]["rule"], "public-rule.rule")
                self.assertEqual(shared[1]["wordlist"], "public-words.txt")
                self.assertIsNone(shared[1]["rule"])
                self.assertIsNone(shared[2]["wordlist"])
                self.assertEqual(shared[2]["rule"], "public-rule.rule")
                self.assertIsNotNone(statistics.attack_identity(shared[1]))
                self.assertIsNone(statistics.attack_identity(shared[2]))
                display = io.StringIO()
                with patch.object(statistics, "console", Console(file=display, width=180)):
                    statistics.print_phase_statistics()
                self.assertIn("public-words", display.getvalue())
                self.assertIn("10.00%", display.getvalue())
                self.assertIn("Other Attacks", display.getvalue())
                self.assertIn("Phase order", display.getvalue())
                self.assertIn("\n\nYield:", display.getvalue())
                self.assertIn("\n\n", display.getvalue())
                self.assertNotIn("(n=1)", display.getvalue())

                renamed = copy.deepcopy(config)
                renamed["phases"][0]["id"] = "renamed"
                renamed["phases"][0]["wordlist"] = "another-dir/public-words.txt"
                renamed["phases"][0]["rule"] = "another-dir/public-rule.rule"
                with patch.object(estimate, "load_campaign", return_value={"ntlm": renamed}):
                    result = estimate.estimate_campaign("unused")["ntlm"]
                self.assertEqual(result["estimates"][0]["duration"], 60)
                self.assertEqual(result["estimates"][0]["runs"], 1)
                self.assertEqual(result["estimates"][1]["duration"], 60)
                self.assertIsNone(result["estimates"][2]["duration"])
                archive = next(local.glob("*.json"))
                older = json.loads(archive.read_text(encoding="utf-8"))
                older["hardwareProfile"] = "previous-profile"
                archive.write_text(json.dumps(older), encoding="utf-8")
                with patch.object(estimate, "load_campaign", return_value={"ntlm": renamed}):
                    self.assertEqual(
                        estimate.estimate_campaign("unused")["ntlm"]["estimates"][0]["duration"],
                        60,
                    )
                for change in ("wordlist", "rule", "settings", "hash_mode"):
                    modified = copy.deepcopy(renamed)
                    if change == "wordlist":
                        modified["phases"][0]["wordlist"] = "other-words.txt"
                    elif change == "rule":
                        modified["phases"][0]["rule"] = "other-rule.rule"
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
                tampered["records"][0]["wordlist"] = "private/path.txt"
                bad.write_text(json.dumps(tampered), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "filename"):
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
                display = io.StringIO()
                with patch.object(statistics, "console", Console(file=display, width=180)):
                    statistics.print_phase_statistics()
                self.assertIn("Excluded 1 phases with missing or invalid recovery counts.",
                              display.getvalue())
                with self.assertRaisesRegex(ValueError, "No measured"):
                    statistics.export_statistics(root / "share.json")
                self.assertFalse((root / "share.json").exists())

    def test_unknown_settings_cannot_be_compared(self):
        config = campaign()
        validate_campaign(config)
        settings = statistics.describe_settings(["-O", "--runtime", "20"])
        self.assertTrue(settings["otherFlags"])
        self.assertIsNone(statistics.phase_identity(1000, config["phases"][0], settings))
        settings = statistics.describe_settings(["-O"])
        self.assertIsNotNone(statistics.phase_identity(1000, config["phases"][0], settings))

    def test_asset_filenames_exclude_windows_and_posix_directories(self):
        for path in ("C:\\client\\words.txt", "C:words.txt", "/client/words.txt"):
            with self.subTest(path=path):
                self.assertEqual(statistics.asset_filename(path), "words.txt")

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
            self.assertIn("No usable campaign statistics available.", message.getvalue())
            self.assertNotIn("old-phase", output.getvalue())


if __name__ == "__main__":
    unittest.main()
