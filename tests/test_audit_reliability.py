import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import DEFAULT, patch
from types import SimpleNamespace

import auditing.validation as validation
import auditing.workflow as audit
import cli.main as cli_main
from lm.workflow import generate_lm_results, map_lm_passwords
from ntds.constants import LM_EMPTY
from ntds.workflow import organise_dataset


class AuditReliabilityTests(unittest.TestCase):
    def test_hashcat_show_failure_does_not_replace_results(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "lm-results.txt"
            output.write_text("previous\n", encoding="utf-8")
            for code, stderr in ((1, "invalid hashes"), (-1, "")):
                with self.subTest(code=code), patch(
                    "lm.workflow.subprocess.run",
                    return_value=SimpleNamespace(
                        returncode=code, stderr=stderr, stdout="partial"
                    ),
                ):
                    with self.assertRaisesRegex(RuntimeError, "LM --show failed"):
                        generate_lm_results("hashcat.exe", "hashes", "potfile", output)
                    self.assertEqual(output.read_text(encoding="utf-8"), "previous\n")
            with patch("lm.workflow.subprocess.run", return_value=SimpleNamespace(
                returncode=0, stderr="", stdout=""
            )):
                generate_lm_results("hashcat.exe", "hashes", "potfile", output)
            self.assertEqual(output.read_text(encoding="utf-8"), "")

    def test_missing_bloodhound_account_data_is_not_treated_as_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ntds = root / "ntds.txt"
            ntds.write_text("", encoding="utf-8")
            archive_path = root / "bloodhound.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("domains.json", json.dumps({
                    "data": [{"Properties": {"domain": "example.test"}}],
                }))
            result = organise_dataset(ntds, root, bloodhound_file=archive_path)
            self.assertFalse(result["domain_admins_available"])
            self.assertFalse((root / "domain-admins.txt").exists())

    def test_audits_isolate_real_exports_and_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_root = root / "password-audit"
            output_root.mkdir()
            (output_root / "lm-users.txt").write_text("STALE\n", encoding="utf-8")
            (output_root / "mapped-ntlm-passwords.txt").write_text("STALE\n", encoding="utf-8")
            (root / "company-words.txt").write_text("example\n", encoding="utf-8")
            ntlm_dir = root / "ntlm"
            lm_dir = root / "lm"
            ntlm_dir.mkdir()
            lm_dir.mkdir()
            (ntlm_dir / "hashcat.potfile").write_text(
                "cccccccccccccccccccccccccccccccc:Password123!\n"
                "dddddddddddddddddddddddddddddddd:Otherpass123!\n",
                encoding="utf-16",
            )
            (root / "first.ntds").write_text(
                "alice:1000:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:"
                "cccccccccccccccccccccccccccccccc::: (status=Enabled)\n",
                encoding="utf-8",
            )
            (root / "second.ntds").write_text(
                f"bob:1001:{LM_EMPTY}:dddddddddddddddddddddddddddddddd::: (status=Enabled)\n",
                encoding="utf-8",
            )
            with zipfile.ZipFile(root / "bloodhound.zip", "w") as archive:
                archive.writestr("users.json", json.dumps({"data": []}))
                archive.writestr("groups.json", json.dumps({"data": []}))
                archive.writestr("domains.json", json.dumps({
                    "data": [{"Properties": {
                        "domain": "example.test", "minpwdlength": 12,
                        "pwdhistorylength": 5, "lockoutthreshold": 5,
                        "minpwdage": 1, "maxpwdage": 90,
                    }}],
                }))
            (root / "campaign.json").write_text(json.dumps({
                "ntlm": {
                    "parameters": {"hashMode": 1000, "hashcatDir": str(ntlm_dir)},
                    "phases": [{"id": "first", "type": "wordlist", "wordlist": "words.txt"}],
                },
                "lm": {
                    "parameters": {"hashMode": 3000, "hashcatDir": str(lm_dir)},
                    "phases": [{"id": "first", "type": "wordlist", "wordlist": "words.txt"}],
                },
            }), encoding="utf-8")
            sessions = []

            def fake_phase(**kwargs):
                sessions.append(kwargs["session_name"])
                return {"duration": 1, "newRecovered": 1, "totalRecovered": 1, "returncode": 0}

            def fake_lm_show(**kwargs):
                self.assertEqual(kwargs["potfile"], str(lm_dir / "hashcat.potfile"))
                self.assertEqual(kwargs["hashcat_binary"], str(lm_dir / "hashcat.exe"))
                Path(kwargs["output_file"]).write_text(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:ALICE\n", encoding="utf-8"
                )

            original_cwd = os.getcwd()
            try:
                os.chdir(root)
                with (
                    patch("cracking.scheduler.validate_file"),
                    patch("cracking.scheduler.run_phase", side_effect=fake_phase),
                    patch("cracking.scheduler.archive_results"),
                    patch.object(audit, "generate_lm_results", side_effect=fake_lm_show),
                    patch("auditing.company_words.warn") as reminder,
                ):
                    for ntds, extra in (("first.ntds", []), ("second.ntds", ["--csacyber"])):
                        args = ["password-audit", "audit", "-N", ntds, "-B", "bloodhound.zip",
                                "-C", "campaign.json", "-G", "test", *extra]
                        with patch.object(sys, "argv", args):
                            cli_main.main()
                self.assertTrue(any("appears unchanged" in call.args[0]
                                    for call in reminder.call_args_list))
            finally:
                os.chdir(original_cwd)

            run_dirs = [path for path in output_root.iterdir() if path.is_dir()]
            self.assertEqual(len(run_dirs), 2)
            first = next(path for path in run_dirs if (path / "lm-users.txt").exists())
            second = next(path for path in run_dirs if path != first)
            self.assertTrue((first / "password-audit-report.html").exists())
            self.assertTrue((first / "password-audit-findings.json").exists())
            self.assertTrue((first / "mapped-lm-passwords.txt").exists())
            self.assertIn("alice:Password123!", (first / "mapped-ntlm-passwords.txt").read_text())
            self.assertTrue((second / "password-audit-report.html").exists())
            self.assertTrue((second / "password-audit-findings.xml").exists())
            self.assertFalse((second / "lm-users.txt").exists())
            self.assertEqual((second / "enabled-users.txt").read_text().strip(), "bob")
            self.assertIn("bob:Otherpass123!", (second / "mapped-ntlm-passwords.txt").read_text())
            self.assertEqual((second / "domain-admins.txt").read_text(), "")
            self.assertEqual((output_root / "lm-users.txt").read_text(), "STALE\n")
            for run in run_dirs:
                campaign = json.loads((run / "test-results.json").read_text())
                self.assertEqual(campaign["hashDataset"], str(run / "ntlm-hashes.txt"))
                self.assertIn(run.name, campaign["phases"][0]["session"])
            self.assertEqual(len(set(sessions)), 3)

    def test_campaign_requires_at_least_one_enabled_phase(self):
        cases = [
            ({"ntlm": {"phases": [{"enabled": False}]}}, False),
            ({"ntlm": {"phases": [{}]}}, True),
            ({"ntlm": {"phases": []}, "lm": {"phases": [{}]}}, True),
            ({"ntlm": {"phases": []}, "lm": {"phases": []}}, False),
        ]
        with patch.object(validation.Path, "exists", return_value=True):
            for campaign, valid in cases:
                with self.subTest(campaign=campaign), patch.object(
                    validation, "load_campaign", return_value=campaign
                ):
                    if valid:
                        validation.validate_audit_inputs("ntds", "zip", "config")
                    else:
                        with self.assertRaisesRegex(ValueError, "no|any enabled phases"):
                            validation.validate_audit_inputs("ntds", "zip", "config")

    def test_lm_mapping_preserves_filter_in_exported_datasets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ntds = root / "ntds.txt"
            potfile = root / "potfile"
            lm_results = root / "lm.txt"
            ntds.write_text(
                "example\\alice:1000:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:"
                "cccccccccccccccccccccccccccccccc::: (status=Enabled)\n"
                "example\\testuser:1001:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:"
                "dddddddddddddddddddddddddddddddd::: (status=Enabled)\n",
                encoding="utf-8",
            )
            potfile.write_text(
                "cccccccccccccccccccccccccccccccc:ALICEPASS\n"
                "dddddddddddddddddddddddddddddddd:TESTPASS\n",
                encoding="utf-8",
            )
            lm_results.write_text(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:ALICE\n"
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:TEST\n",
                encoding="utf-8",
            )
            output = root / "output"
            map_lm_passwords(ntds, potfile, lm_results, output, username_filter="test")
            for name in (
                "enabled-users.txt", "ntds-users-clean.txt", "ntlm-hashes.txt",
                "lm-users.txt", "lm-hashes.txt", "mapped-ntlm-passwords.txt",
                "mapped-lm-passwords.txt",
            ):
                text = (output / name).read_text(encoding="utf-8").lower()
                self.assertNotIn("testuser", text, name)
                self.assertNotIn("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", text, name)
                self.assertNotIn("dddddddddddddddddddddddddddddddd", text, name)
                self.assertNotIn("testpass", text, name)
            self.assertIn("alice", (output / "mapped-lm-passwords.txt").read_text())

    def test_audit_forwards_username_filter_to_lm_mapping(self):
        with tempfile.TemporaryDirectory() as directory, patch.multiple(
            audit,
            validate_audit_inputs=DEFAULT, organise_dataset=DEFAULT,
            load_campaign=DEFAULT, has_enabled_phases=DEFAULT,
            analyse_passwords=DEFAULT, run_campaign=DEFAULT, print_summary=DEFAULT,
            generate_lm_results=DEFAULT, map_lm_passwords=DEFAULT,
        ) as mocks, patch.object(audit, "Path", side_effect=lambda p: Path(directory) / p):
            mocks["organise_dataset"].side_effect = [
                {"filtered_users": [], "enabled_users": [], "ntlm_hashes": [],
                 "lm_hashes": ["hash"], "domain_admins": []},
                {"mapped_ntlm_passwords": []},
            ]
            mocks["load_campaign"].return_value = {"ntlm": {"parameters": {}, "phases": []}}
            mocks["has_enabled_phases"].return_value = True
            mocks["run_campaign"].return_value = {"phases": []}
            mocks["map_lm_passwords"].return_value = {"mapped_lm_passwords": []}
            audit.run_audit("ntds", "zip", "config", "run", username_filter="test")
            self.assertEqual(mocks["map_lm_passwords"].call_args.kwargs["username_filter"], "test")
            self.assertEqual(
                mocks["generate_lm_results"].call_args.kwargs["potfile"],
                os.path.join(audit.DEFAULT_HASHCAT_DIR, "hashcat.potfile"),
            )

    def test_lm_show_uses_lm_campaign_but_ntlm_mapping_keeps_ntlm_potfile(self):
        with tempfile.TemporaryDirectory() as directory, patch.multiple(
            audit,
            validate_audit_inputs=DEFAULT, organise_dataset=DEFAULT,
            load_campaign=DEFAULT, has_enabled_phases=DEFAULT,
            analyse_passwords=DEFAULT, run_campaign=DEFAULT, print_summary=DEFAULT,
            generate_lm_results=DEFAULT, map_lm_passwords=DEFAULT,
        ) as mocks, patch.object(audit, "Path", side_effect=lambda p: Path(directory) / p):
            mocks["organise_dataset"].side_effect = [
                {"filtered_users": [], "enabled_users": [], "ntlm_hashes": [],
                 "lm_hashes": ["hash"], "domain_admins": []},
                {"mapped_ntlm_passwords": []},
            ]
            mocks["load_campaign"].return_value = {
                "ntlm": {"parameters": {"hashcatDir": "ntlm-dir"}, "phases": [{}]},
                "lm": {"parameters": {
                    "hashcatDir": "lm-dir", "hashcatBinary": "custom-lm.exe",
                }, "phases": [{}]},
            }
            mocks["has_enabled_phases"].return_value = True
            mocks["run_campaign"].return_value = {"phases": []}
            mocks["map_lm_passwords"].return_value = {"mapped_lm_passwords": []}
            audit.run_audit("ntds", "zip", "config", "run")
            show_args = mocks["generate_lm_results"].call_args.kwargs
            self.assertEqual(show_args["hashcat_binary"], "custom-lm.exe")
            self.assertEqual(show_args["potfile"], os.path.join("lm-dir", "hashcat.potfile"))
            self.assertEqual(
                mocks["map_lm_passwords"].call_args.kwargs["potfile"],
                os.path.join("ntlm-dir", "hashcat.potfile"),
            )

    def test_audit_stops_when_lm_show_fails(self):
        with tempfile.TemporaryDirectory() as directory, patch.multiple(
            audit,
            validate_audit_inputs=DEFAULT, organise_dataset=DEFAULT,
            load_campaign=DEFAULT, has_enabled_phases=DEFAULT,
            analyse_passwords=DEFAULT, run_campaign=DEFAULT, print_summary=DEFAULT,
            generate_lm_results=DEFAULT, map_lm_passwords=DEFAULT,
        ) as mocks, patch.object(audit, "Path", side_effect=lambda p: Path(directory) / p):
            mocks["organise_dataset"].side_effect = [
                {"filtered_users": [], "enabled_users": [], "ntlm_hashes": [],
                 "lm_hashes": ["hash"], "domain_admins": []},
                {"mapped_ntlm_passwords": []},
            ]
            mocks["load_campaign"].return_value = {"ntlm": {"parameters": {}, "phases": [{}]}}
            mocks["has_enabled_phases"].return_value = True
            mocks["run_campaign"].return_value = {"phases": []}
            mocks["generate_lm_results"].side_effect = RuntimeError("LM --show failed")
            with self.assertRaisesRegex(RuntimeError, "LM --show failed"):
                audit.run_audit("ntds", "zip", "config", "run")
            mocks["map_lm_passwords"].assert_not_called()
            mocks["analyse_passwords"].assert_not_called()


if __name__ == "__main__":
    unittest.main()
