import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cli import audit as cli_audit
from cli import main as cli_main
from cracking import scheduler
from cracking.results import write_results
from cracking.resume import build_resume_fingerprint


class CampaignResumeTests(unittest.TestCase):
    def test_audit_cli_owns_resume_option(self):
        def capture_help(arguments):
            output = io.StringIO()
            with (
                patch.object(
                    sys,
                    "argv",
                    ["password-audit", *arguments],
                ),
                redirect_stdout(output),
                self.assertRaises(SystemExit) as raised,
            ):
                cli_main.main()

            self.assertEqual(raised.exception.code, 0)
            return output.getvalue()

        audit_help = capture_help(["audit", "--help"])
        crack_help = capture_help(["crack", "run", "--help"])

        self.assertIn("--resume", audit_help)
        self.assertNotIn("--resume", crack_help)

    def test_audit_cli_forwards_resume(self):
        args = SimpleNamespace(
            ntds="ntds.txt",
            bloodhound="bloodhound.zip",
            campaign="campaign.json",
            campaign_name="audit",
            mapped_ntlm_passwords=None,
            mapped_lm_passwords=None,
            lm_users=None,
            domain_admins=None,
            company_words=None,
            enabled_users=None,
            pass_policy=None,
            filter=None,
            resume=True,
        )
        with patch.object(cli_audit, "run_audit") as run_audit:
            cli_audit.run_audit_workflow(args)

        self.assertTrue(run_audit.call_args.kwargs["resume"])

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
            with patch(
                "cracking.results.json.dump",
                side_effect=TypeError("not serializable"),
            ), self.assertRaises(TypeError):
                write_results(changed)

            self.assertEqual(
                json.loads(output_file.read_text(encoding="utf-8")),
                original,
            )
            self.assertEqual(
                {path.name for path in Path(temporary_directory).iterdir()},
                {output_file.name},
            )

    def test_fingerprint_changes_when_hashes_or_attack_inputs_change(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            hash_file = root / "hashes.txt"
            hash_file.write_text("hash-one\n", encoding="utf-8")

            hashcat_binary = root / "hashcat"
            hashcat_binary.write_text("binary", encoding="utf-8")

            wordlist_dir = root / "wordlists"
            wordlist_dir.mkdir()
            wordlist = wordlist_dir / "common.txt"
            wordlist.write_text("password-one\n", encoding="utf-8")

            rules_dir = root / "rules"
            rules_dir.mkdir()
            rule = rules_dir / "basic.rule"
            rule.write_text("rule-one\n", encoding="utf-8")

            config = {
                "parameters": {"hashMode": 1000, "flags": []},
                "phases": [{
                    "id": "common",
                    "type": "wordlist",
                    "wordlist": "common.txt",
                    "rule": "basic.rule",
                }],
            }

            def fingerprint():
                return build_resume_fingerprint(
                    config=config,
                    hash_file=hash_file,
                    campaign_name="campaign",
                    hashcat_binary=hashcat_binary,
                    hashcat_potfile=root / "hashcat.potfile",
                    wordlist_dir=wordlist_dir,
                    rules_dir=rules_dir,
                )

            initial = fingerprint()
            self.assertEqual(fingerprint(), initial)

            hash_file.write_text("hash-two\n", encoding="utf-8")
            self.assertNotEqual(fingerprint(), initial)

            hash_file.write_text("hash-one\n", encoding="utf-8")
            wordlist.write_text("password-two\n", encoding="utf-8")
            changed_wordlist = fingerprint()
            self.assertNotEqual(changed_wordlist, initial)

            wordlist.write_text("password-one\n", encoding="utf-8")
            rule.write_text("rule-two\n", encoding="utf-8")
            self.assertNotEqual(fingerprint(), initial)

            rule.write_text("rule-one\n", encoding="utf-8")
            hashcat_binary.write_text("different binary", encoding="utf-8")
            self.assertNotEqual(fingerprint(), initial)

    def test_resume_rejects_mismatched_fingerprint_before_running_phase(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            hash_file = Path(temporary_directory) / "hashes.txt"
            hash_file.write_text("hash\n", encoding="utf-8")
            config = {
                "parameters": {
                    "hashMode": 1000,
                    "hashcatDir": temporary_directory,
                },
                "phases": [{
                    "id": "first",
                    "type": "wordlist",
                    "wordlist": "words.txt",
                }],
            }
            existing_results = {
                "campaign": "campaign",
                "state": "interrupted",
                "currentPhase": "first",
                "phases": [],
                "resumeFingerprint": {"version": 1, "sha256": "old"},
            }

            with (
                patch.object(
                    scheduler,
                    "load_results",
                    return_value=existing_results,
                ),
                patch.object(scheduler, "validate_file"),
                patch.object(
                    scheduler,
                    "build_resume_fingerprint",
                    return_value={"version": 1, "sha256": "new"},
                ),
                patch.object(scheduler, "warn"),
                patch.object(scheduler, "run_phase") as run_phase,
                self.assertRaises(SystemExit),
            ):
                scheduler.run_campaign(
                    config=config,
                    hash_file=hash_file,
                    campaign_name="campaign",
                    resume=True,
                )

            run_phase.assert_not_called()

    def test_resume_reuses_a_completed_campaign_without_running_phases(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            hash_file = Path(temporary_directory) / "hashes.txt"
            hash_file.write_text("hash\n", encoding="utf-8")
            fingerprint = {"version": 1, "sha256": "same"}
            existing_results = {
                "campaign": "campaign",
                "state": "completed",
                "phases": [{"id": "first"}],
                "resumeFingerprint": fingerprint,
            }
            config = {
                "parameters": {
                    "hashMode": 1000,
                    "hashcatDir": temporary_directory,
                },
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
                patch.object(scheduler, "validate_file"),
                patch.object(
                    scheduler,
                    "build_resume_fingerprint",
                    return_value=fingerprint,
                ),
                patch.object(scheduler, "run_phase") as run_phase,
            ):
                results = scheduler.run_campaign(
                    config=config,
                    hash_file=hash_file,
                    campaign_name="campaign",
                    resume=True,
                )

            self.assertIs(results, existing_results)
            run_phase.assert_not_called()

    def test_resume_starts_a_campaign_when_no_results_exist(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            hash_file = Path(temporary_directory) / "hashes.txt"
            hash_file.write_text("hash\n", encoding="utf-8")
            config = {
                "parameters": {
                    "hashMode": 1000,
                    "hashcatDir": temporary_directory,
                },
                "phases": [{
                    "id": "first",
                    "type": "wordlist",
                    "wordlist": "words.txt",
                }],
            }

            with (
                patch.object(scheduler, "load_results", return_value=None),
                patch.object(scheduler, "validate_file"),
                patch.object(
                    scheduler,
                    "build_resume_fingerprint",
                    return_value={"version": 1, "sha256": "same"},
                ),
                patch.object(scheduler, "write_results"),
                patch.object(scheduler, "archive_results"),
                patch.object(
                    scheduler,
                    "run_phase",
                    return_value={
                        "duration": 1,
                        "newRecovered": 0,
                        "totalRecovered": 0,
                        "returncode": 0,
                    },
                ) as run_phase,
                patch.object(scheduler, "warn"),
            ):
                result = scheduler.run_campaign(
                    config=config,
                    hash_file=hash_file,
                    campaign_name="campaign",
                    resume=True,
                )

            self.assertEqual(result["state"], "completed")
            run_phase.assert_called_once()

    def test_resume_warns_and_uses_a_new_session_for_interrupted_phase(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            hash_file = Path(temporary_directory) / "hashes.txt"
            hash_file.write_text("hash\n", encoding="utf-8")
            config = {
                "parameters": {
                    "hashMode": 1000,
                    "hashcatDir": temporary_directory,
                },
                "phases": [{
                    "id": "first",
                    "type": "wordlist",
                    "wordlist": "words.txt",
                }],
            }
            fingerprint = {"version": 1, "sha256": "same"}
            existing_results = {
                "campaign": "campaign",
                "hashDataset": str(hash_file),
                "state": "interrupted",
                "currentPhase": "first",
                "currentSession": "campaign-first",
                "phases": [],
                "resumeFingerprint": fingerprint,
            }

            with (
                patch.object(
                    scheduler,
                    "load_results",
                    return_value=existing_results,
                ),
                patch.object(scheduler, "validate_file"),
                patch.object(
                    scheduler,
                    "build_resume_fingerprint",
                    return_value=fingerprint,
                ),
                patch.object(scheduler, "write_results"),
                patch.object(scheduler, "archive_results"),
                patch.object(
                    scheduler,
                    "run_phase",
                    return_value={
                        "duration": 1,
                        "newRecovered": 0,
                        "totalRecovered": 0,
                        "returncode": 0,
                    },
                ) as run_phase,
                patch.object(scheduler, "warn") as warn,
            ):
                result = scheduler.run_campaign(
                    config=config,
                    hash_file=hash_file,
                    campaign_name="campaign",
                    resume=True,
                )

            self.assertEqual(result["state"], "completed")
            self.assertNotEqual(
                run_phase.call_args.kwargs["session_name"],
                "campaign-first",
            )
            self.assertTrue(
                any(
                    "restart from the beginning" in call.args[0]
                    for call in warn.call_args_list
                )
            )

    def test_keyboard_interrupt_records_interrupted_phase(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            hash_file = Path(temporary_directory) / "hashes.txt"
            hash_file.write_text("hash\n", encoding="utf-8")
            config = {
                "parameters": {
                    "hashMode": 1000,
                    "hashcatDir": temporary_directory,
                },
                "phases": [{
                    "id": "first",
                    "type": "wordlist",
                    "wordlist": "words.txt",
                }],
            }

            with (
                patch.object(scheduler, "load_results", return_value=None),
                patch.object(scheduler, "validate_file"),
                patch.object(
                    scheduler,
                    "build_resume_fingerprint",
                    return_value={"version": 1, "sha256": "same"},
                ),
                patch.object(scheduler, "write_results") as write_results,
                patch.object(
                    scheduler,
                    "run_phase",
                    side_effect=KeyboardInterrupt,
                ),
                patch.object(scheduler, "warn"),
                self.assertRaises(SystemExit),
            ):
                scheduler.run_campaign(
                    config=config,
                    hash_file=hash_file,
                    campaign_name="campaign",
                )

            interrupted_results = write_results.call_args_list[-1].args[0]
            self.assertEqual(interrupted_results["state"], "interrupted")
            self.assertEqual(
                interrupted_results["interruption"]["phase"],
                "first",
            )


if __name__ == "__main__":
    unittest.main()
