import json
import io
import os
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime
from pathlib import Path
from unittest.mock import DEFAULT, patch
from types import SimpleNamespace
from rich.console import Console

import auditing.validation as validation
import auditing.workflow as audit
import cli.main as cli_main
from lm.workflow import generate_lm_results, map_lm_passwords
from ntds.constants import LM_EMPTY
from ntds.analysis import extract_domain_admins, extract_privileged_users
from ntds.results import build_results as build_ntds_results
from ntds.workflow import organise_dataset
from analysis.parsers import load_privileged_users
from common.console import confirm_ntds_domain


class AuditReliabilityTests(unittest.TestCase):
    def test_run_directory_uses_timestamp_and_numbers_only_for_collisions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "password-audit"
            with patch.object(audit, "datetime") as clock:
                clock.now.return_value = datetime(2026, 11, 19, 21, 18, 11)
                first = audit.create_audit_directory(root)
                (first / "previous.txt").write_text("keep", encoding="utf-8")
                (root / "20261119-211811-1").write_text("existing", encoding="utf-8")
                second = audit.create_audit_directory(root)
            self.assertEqual(first.name, "20261119-211811")
            self.assertEqual(second.name, "20261119-211811-2")
            self.assertEqual((first / "previous.txt").read_text(encoding="utf-8"), "keep")
            self.assertEqual((root / "20261119-211811-1").read_text(), "existing")

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
            self.assertEqual(
                json.loads((root / "privileged-users.json").read_text())["status"],
                "unavailable",
            )

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
                "external.test\\alice:1000:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:"
                "cccccccccccccccccccccccccccccccc::: (status=Enabled)\n"
                f"example.test\\dave:1002:{LM_EMPTY}:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee::: (status=Enabled)\n"
                f"example.test\\eve:1003:{LM_EMPTY}:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE::: (status=Enabled)\n"
                f"example.test\\disabled:1004:{LM_EMPTY}:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee::: (status=Disabled)\n"
                f"example.test\\excluded:1005:{LM_EMPTY}:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee::: (status=Enabled)\n"
                f"example.test\\computer$:1006:{LM_EMPTY}:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee::: (status=Enabled)\n",
                encoding="utf-8",
            )
            (root / "second.ntds").write_text(
                f"bob:1001:{LM_EMPTY}:dddddddddddddddddddddddddddddddd::: (status=Enabled)\n",
                encoding="utf-8",
            )
            with zipfile.ZipFile(root / "bloodhound.zip", "w") as archive:
                archive.writestr("users.json", json.dumps({"data": [
                    {"ObjectIdentifier": f"S-1-5-21-1-2-3-{rid}",
                     "Properties": {"samaccountname": name, "domain": "example.test"}}
                    for name, rid in (("alice", 1000), ("dave", 1002), ("eve", 1003))
                ]}))
                archive.writestr("groups.json", json.dumps({"data": [
                    {"ObjectIdentifier": "S-1-5-21-1-2-3-512", "Members": []},
                    {"ObjectIdentifier": "S-1-5-32-544", "Members": []},
                    {"ObjectIdentifier": "S-1-5-32-551", "Members": [
                        {"ObjectIdentifier": "S-1-5-21-1-2-3-1000", "ObjectType": "User"},
                        {"ObjectIdentifier": "S-1-5-21-1-2-3-1002", "ObjectType": "User"},
                    ]},
                ]}))
                archive.writestr("domains.json", json.dumps({
                    "data": [{"ObjectIdentifier": "S-1-5-21-1-2-3", "Properties": {
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
                    patch.object(audit, "confirm_ntds_domain", return_value=True) as confirm,
                    patch("auditing.company_words.warn") as reminder,
                ):
                    for ntds, extra in (("first.ntds", ["-F", "excluded"]),
                                        ("second.ntds", ["--csacyber"])):
                        args = ["password-audit", "audit", "-N", ntds, "-B", "bloodhound.zip",
                                "-C", "campaign.json", "-G", "test", *extra]
                        with patch.object(sys, "argv", args):
                            cli_main.main()
                confirm.assert_called_once_with({
                    "name": "example.test", "sid": "S-1-5-21-1-2-3",
                })
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
            privileged = json.loads((first / "privileged-users.json").read_text())
            self.assertEqual(privileged["status"], "available")
            self.assertEqual(privileged["accounts"], [
                {"username": "example.test\\dave", "groups": ["Backup Operators"]},
                {"username": "external.test\\alice", "groups": ["Backup Operators"]},
            ])
            self.assertEqual(privileged["confirmed_domain"], {
                "name": "example.test", "sid": "S-1-5-21-1-2-3",
            })
            report = (first / "password-audit-report.html").read_text(encoding="utf-8")
            self.assertIn("Backup Operators", report)
            self.assertIn("user-confirmed source domain", report)
            self.assertIn("S-1-5-21-1-2-3", report)
            self.assertIn("Pa********3!", report)
            findings = json.loads((first / "password-audit-findings.json").read_text())
            self.assertIn("PRIV-ACCOUNT-001", [
                finding["id"] for finding in findings["findings"]
            ])
            reuse = next(f for f in findings["findings"] if f["id"] == "PWD-REUSE-003")
            self.assertEqual(reuse["affected_assets"], ["example.test\\dave", "example.test\\eve"])
            self.assertIn("Backup Operators", reuse["evidence"][0])
            self.assertNotIn("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", report.lower())
            self.assertNotIn("example.test\\excluded", reuse["evidence"][0])
            self.assertIn("dave, eve", report)
            self.assertNotIn("one of these hashes is shared with accounts", report)
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

    def test_privileged_membership_nested_primary_overlap_and_ambiguous_names(self):
        domain_sid = "S-1-5-21-1-2-3"
        other_sid = "S-1-5-21-4-5-6"
        def user(sid, name, domain, primary=None):
            return {"ObjectIdentifier": sid, "PrimaryGroupSID": primary,
                    "Properties": {"samaccountname": name, "domain": domain}}
        def group(sid, members, **properties):
            return {"ObjectIdentifier": sid, "Properties": properties,
                    "Members": [{"ObjectIdentifier": member, "ObjectType": kind}
                                for member, kind in members]}
        users = {"data": [
            user(f"{domain_sid}-1000", "alice", "example.test"),
            user(f"{domain_sid}-1001", "bob", "example.test", f"{domain_sid}-2000"),
            user(f"{domain_sid}-1002", "same", "example.test"),
            user(f"{other_sid}-1002", "same", "other.test"),
        ]}
        groups = {"data": [
            group(f"{domain_sid}-512", []),
            group("S-1-5-32-544", []),
            group("S-1-5-32-551", [(f"{domain_sid}-2000", "Group"),
                                   (f"{domain_sid}-9999", "User")]),
            group(f"{domain_sid}-2000", [(f"{domain_sid}-1000", "User"),
                                         ("S-1-5-32-551", "Group")]),
            group(f"{domain_sid}-3000", [(f"{domain_sid}-1000", "User"),
                                         (f"{domain_sid}-1002", "User")],
                  samaccountname="DNSAdmins", domain="example.test"),
        ]}
        entries = [
            {"username": "example.test\\alice", "rid": "1000"},
            {"username": "example.test\\bob", "rid": "1001"},
            {"username": "same", "rid": "1002"},
        ]
        result = extract_privileged_users(users, groups, entries)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["accounts"], [
            {"username": "example.test\\alice",
             "groups": ["Backup Operators", "DNSAdmins (example.test)"]},
            {"username": "example.test\\bob", "groups": ["Backup Operators"]},
        ])
        self.assertTrue(any("could not be resolved" in w for w in result["warnings"]))
        self.assertTrue(any("ambiguous" in w for w in result["warnings"]))
        entries[-1]["username"] = "example.test\\same"
        resolved = extract_privileged_users(users, groups, entries)
        self.assertIn(
            {"username": "example.test\\same", "groups": ["DNSAdmins (example.test)"]},
            resolved["accounts"],
        )
        entries[0]["username"] = "WRONG\\alice"
        mismatch = extract_privileged_users(users, groups, entries)
        self.assertNotIn("WRONG\\alice", [item["username"] for item in mismatch["accounts"]])
        self.assertTrue(any("could not be confirmed" in w for w in mismatch["warnings"]))
        del groups["data"][2]["Members"]
        missing_members = extract_privileged_users(users, groups, entries)
        self.assertTrue(any("lacked membership data" in w for w in missing_members["warnings"]))

    def test_prefixed_builtin_groups_merge_duplicate_memberships(self):
        domain_sid = "S-1-5-21-1-2-3"
        builtin = "EXAMPLE.TEST-S-1-5-32-544"
        users = {"data": [
            {"ObjectIdentifier": f"{domain_sid}-{rid}", "Properties": {
                "samaccountname": name, "domain": "example.test",
            }}
            for name, rid in (("alice", 1000), ("bob", 1001))
        ]}
        groups = {"data": [
            {"ObjectIdentifier": f"{domain_sid}-512", "Members": []},
            {"ObjectIdentifier": builtin, "Properties": {"name": "Administrators"},
             "Members": [{"ObjectIdentifier": f"{domain_sid}-1000", "ObjectType": "User"}]},
            {"ObjectIdentifier": builtin, "Properties": {"name": "ADMINISTRATORS@EXAMPLE.TEST",
                                                          "domain": "EXAMPLE.TEST"},
             "Members": [{"ObjectIdentifier": f"{domain_sid}-1001", "ObjectType": "User"}]},
        ]}
        entries = [
            {"username": f"example.test\\{name}", "rid": str(rid)}
            for name, rid in (("alice", 1000), ("bob", 1001))
        ]
        result = extract_privileged_users(users, groups, entries)
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["accounts"], [
            {"username": "example.test\\alice", "groups": ["Administrators (example.test)"]},
            {"username": "example.test\\bob", "groups": ["Administrators (example.test)"]},
        ])

    def test_upn_suffix_matches_only_when_confirmed_for_the_account(self):
        domain_sid = "S-1-5-21-1-2-3"
        users = {"data": [
            {"ObjectIdentifier": f"{domain_sid}-1000", "Properties": {
                "samaccountname": "alice", "domain": "local.example.test",
                "userprincipalname": "alice@external.example",
            }},
            {"ObjectIdentifier": f"{domain_sid}-1001", "Properties": {
                "samaccountname": "bob", "domain": "local.example.test",
            }},
        ]}
        members = [
            {"ObjectIdentifier": f"{domain_sid}-{rid}", "ObjectType": "User"}
            for rid in (1000, 1001)
        ]
        groups = {"data": [
            {"ObjectIdentifier": f"{domain_sid}-512", "Members": members},
            {"ObjectIdentifier": "S-1-5-32-544", "Members": []},
        ]}
        entries = [
            {"username": "external.example\\alice", "rid": "1000"},
            {"username": "external.example\\bob", "rid": "1001"},
        ]
        result = extract_privileged_users(users, groups, entries)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["accounts"], [
            {"username": "external.example\\alice", "groups": ["Domain Admins"]},
        ])
        self.assertIn("1 NTDS account(s)", result["warnings"][0])

        entries[0]["username"] = "local\\alice"
        result = extract_privileged_users(users, groups, entries)
        self.assertEqual(result["accounts"], [])
        self.assertIn("2 NTDS account(s)", result["warnings"][0])

    def test_domain_confirmation_respects_filtering_and_decline(self):
        sid = "S-1-5-21-1-2-3"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ntds = root / "ntds.txt"
            ntds.write_text(
                "".join(
                    f"external.test\\{name}:{rid}:{LM_EMPTY}:"
                    "cccccccccccccccccccccccccccccccc::: (status=Enabled)\n"
                    for name, rid in (("alice", 1000), ("filtered", 1001))
                ) + (
                    f"external.test\\disabled:1002:{LM_EMPTY}:"
                    "cccccccccccccccccccccccccccccccc::: (status=Disabled)\n"
                ), encoding="utf-8",
            )
            archive_path = root / "bloodhound.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("users.json", json.dumps({"data": [
                    {"ObjectIdentifier": f"{sid}-{rid}", "Properties": {
                        "samaccountname": name, "domain": "example.test",
                    }} for name, rid in (("alice", 1000), ("filtered", 1001),
                                         ("disabled", 1002))
                ]}))
                archive.writestr("groups.json", json.dumps({"data": [
                    {"ObjectIdentifier": f"{sid}-512", "Members": [
                        {"ObjectIdentifier": f"{sid}-{rid}", "ObjectType": "User"}
                        for rid in (1000, 1001, 1002)
                    ]},
                    {"ObjectIdentifier": "S-1-5-32-544", "Members": []},
                ]}))
                archive.writestr("domains.json", json.dumps({"data": [
                    {"ObjectIdentifier": sid, "Properties": {"domain": "example.test"}}
                ]}))
            for accepted in (False, True):
                with self.subTest(accepted=accepted):
                    result = organise_dataset(
                        ntds, root, bloodhound_file=archive_path,
                        username_filter="filtered",
                        confirm_domain=lambda domain: accepted,
                    )
                    privileged = load_privileged_users(root / "privileged-users.json")
                    self.assertEqual(result["privileged_users"], privileged)
                    if accepted:
                        self.assertEqual(privileged["status"], "available")
                        self.assertEqual(privileged["accounts"], [
                            {"username": "external.test\\alice", "groups": ["Domain Admins"]},
                        ])
                        self.assertEqual(privileged["confirmed_domain"]["sid"], sid)
                    else:
                        self.assertEqual(privileged["status"], "incomplete")
                        self.assertEqual(privileged["accounts"], [])
                        self.assertNotIn("confirmed_domain", privileged)

            ntds.write_text(
                f"example.test\\alice:1000:{LM_EMPTY}:"
                "cccccccccccccccccccccccccccccccc::: (status=Enabled)\n",
                encoding="utf-8",
            )
            with patch("common.console.confirm_ntds_domain") as confirm:
                result = organise_dataset(ntds, root, bloodhound_file=archive_path,
                                          confirm_domain=confirm)
            confirm.assert_not_called()
            self.assertEqual(result["privileged_users"]["status"], "available")

            with self.assertRaisesRegex(ValueError, "no longer matches"):
                organise_dataset(ntds, root, bloodhound_file=archive_path,
                                 confirmed_domain_sid="S-1-5-21-9-9-9")

            ntds.write_text(
                f"external.test\\alice:1000:{LM_EMPTY}:"
                "cccccccccccccccccccccccccccccccc::: (status=Enabled)\n",
                encoding="utf-8",
            )
            multi_archive = root / "multi.zip"
            with zipfile.ZipFile(archive_path) as source, zipfile.ZipFile(multi_archive, "w") as target:
                for item in source.infolist():
                    if item.filename != "domains.json":
                        target.writestr(item.filename, source.read(item))
                target.writestr("domains.json", json.dumps({"data": [
                    {"ObjectIdentifier": sid, "Properties": {"domain": "example.test"}},
                    {"ObjectIdentifier": "S-1-5-21-4-5-6", "Properties": {"domain": "other.test"}},
                ]}))
            with patch("common.console.confirm_ntds_domain") as confirm:
                result = organise_dataset(ntds, root, bloodhound_file=multi_archive,
                                          confirm_domain=confirm)
            confirm.assert_not_called()
            self.assertEqual(result["privileged_users"]["status"], "incomplete")
            self.assertEqual(result["privileged_users"]["accounts"], [])

    def test_domain_confirmation_requires_unambiguous_single_domain(self):
        from ntds.analysis import single_bloodhound_domain
        sid = "S-1-5-21-1-2-3"
        domain = {"ObjectIdentifier": sid, "Properties": {"domain": "example.test"}}
        users = {"data": [{"ObjectIdentifier": f"{sid}-1000", "Properties": {
            "samaccountname": "alice", "domain": "example.test",
        }}]}
        groups = {"data": []}
        self.assertEqual(single_bloodhound_domain({"data": [domain]}, users, groups),
                         {"name": "example.test", "sid": sid})
        for domains, account_data in (
            ({"data": [domain, domain]}, users),
            ({"data": [{"ObjectIdentifier": "invalid", "Properties": {
                "domain": "example.test"}}]}, users),
            ({"data": [domain]}, {"data": users["data"] + [{
                "ObjectIdentifier": "S-1-5-21-4-5-6-1000",
                "Properties": {"samaccountname": "alice", "domain": "other.test"},
            }]}),
        ):
            with self.subTest(domains=domains, account_data=account_data):
                self.assertIsNone(single_bloodhound_domain(domains, account_data, groups))

    def test_confirmed_domain_preserves_ambiguous_matches(self):
        sid = "S-1-5-21-1-2-3"
        users = {"data": [{"ObjectIdentifier": f"{sid}-1000", "Properties": {
            "samaccountname": "alice", "domain": "example.test",
        }}]}
        groups = {"data": [
            {"ObjectIdentifier": f"{sid}-512", "Members": [
                {"ObjectIdentifier": f"{sid}-1000", "ObjectType": "User"}
            ]},
            {"ObjectIdentifier": "S-1-5-32-544", "Members": []},
        ]}
        result = extract_privileged_users(users, groups, [
            {"username": "external.test\\alice", "rid": "1000"},
            {"username": "example.test\\alice", "rid": "1000"},
        ], sid)
        self.assertEqual(result["accounts"], [])
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(any("ambiguous" in warning for warning in result["warnings"]))

        users["data"].append({
            "ObjectIdentifier": "S-1-5-21-4-5-6-1000",
            "Properties": {"samaccountname": "alice", "domain": "other.test"},
        })
        result = extract_privileged_users(users, groups, [
            {"username": "external.test\\alice", "rid": "1000"},
        ], sid)
        self.assertEqual(result["accounts"], [
            {"username": "external.test\\alice", "groups": ["Domain Admins"]},
        ])

    def test_noninteractive_domain_confirmation_is_declined(self):
        with patch("common.console.sys.stdin") as stdin, patch("builtins.input") as prompt:
            stdin.isatty.return_value = False
            self.assertFalse(confirm_ntds_domain({
                "name": "example.test", "sid": "S-1-5-21-1-2-3",
            }))
            prompt.assert_not_called()
        with patch("common.console.sys.stdin") as stdin, patch(
            "builtins.input", return_value="yes"
        ):
            stdin.isatty.return_value = True
            self.assertTrue(confirm_ntds_domain({
                "name": "example.test", "sid": "S-1-5-21-1-2-3",
            }))

    def test_prefixed_builtin_groups_remain_separate_between_domains(self):
        users = {"data": [
            {"ObjectIdentifier": f"S-1-5-21-{domain}-2-3-1000", "Properties": {
                "samaccountname": "alice", "domain": f"domain{domain}.test",
            }}
            for domain in (1, 4)
        ]}
        groups = {"data": [
            {"ObjectIdentifier": "S-1-5-21-1-2-3-512", "Members": []},
            *[
                {"ObjectIdentifier": f"DOMAIN{domain}.TEST-S-1-5-32-544",
                 "Properties": {"domain": f"domain{domain}.test"},
                 "Members": [{"ObjectIdentifier": f"S-1-5-21-{domain}-2-3-1000",
                              "ObjectType": "User"}]}
                for domain in (1, 4)
            ],
        ]}
        entries = [
            {"username": f"domain{domain}.test\\alice", "rid": "1000"}
            for domain in (1, 4)
        ]
        result = extract_privileged_users(users, groups, entries)
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["accounts"], [
            {"username": "domain1.test\\alice", "groups": ["Administrators (domain1.test)"]},
            {"username": "domain4.test\\alice", "groups": ["Administrators (domain4.test)"]},
        ])

    def test_domain_admins_preserve_members_from_duplicate_groups(self):
        domain_sid = "S-1-5-21-1-2-3"
        users = {"data": [
            {"ObjectIdentifier": f"{domain_sid}-{rid}",
             "Properties": {"samaccountname": name}}
            for name, rid in (("alice", 1000), ("bob", 1001))
        ]}
        groups = {"data": [
            {"ObjectIdentifier": f"{domain_sid}-512",
             "Members": [{"ObjectIdentifier": f"{domain_sid}-{rid}", "ObjectType": "User"}]}
            for rid in (1000, 1001)
        ]}
        self.assertEqual(extract_domain_admins(users, groups), ["alice", "bob"])

    def test_matching_upn_suffix_remains_ambiguous_across_domains(self):
        users = {"data": [
            {"ObjectIdentifier": f"S-1-5-21-{domain}-2-3-1000", "Properties": {
                "samaccountname": "alice", "domain": f"domain{domain}.test",
                "userprincipalname": "alice@shared.test",
            }}
            for domain in (1, 4)
        ]}
        groups = {"data": [
            {"ObjectIdentifier": "S-1-5-21-1-2-3-512", "Members": [
                {"ObjectIdentifier": "S-1-5-21-1-2-3-1000", "ObjectType": "User"},
            ]},
            {"ObjectIdentifier": "S-1-5-32-544", "Members": []},
        ]}
        result = extract_privileged_users(
            users, groups, [{"username": "shared.test\\alice", "rid": "1000"}],
        )
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["accounts"], [])
        self.assertTrue(any("ambiguous" in warning for warning in result["warnings"]))

    def test_domain_mismatch_warnings_only_count_privileged_candidates(self):
        sid = "S-1-5-21-1-2-3"
        users = {"data": [
            {"ObjectIdentifier": f"{sid}-{rid}", "Properties": {
                "samaccountname": name, "domain": "example.test",
            }}
            for name, rid in (("admin", 1000), ("ordinary", 1001))
        ]}
        groups = {"data": [
            {"ObjectIdentifier": f"{sid}-512", "Members": [
                {"ObjectIdentifier": f"{sid}-1000", "ObjectType": "User"},
            ]},
            {"ObjectIdentifier": "S-1-5-32-544", "Members": []},
        ]}
        entries = [
            {"username": "example.test\\admin", "rid": "1000"},
            {"username": "external.test\\ordinary", "rid": "1001"},
        ]
        result = extract_privileged_users(users, groups, entries)
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["warnings"], [])
        self.assertEqual(result["accounts"], [
            {"username": "example.test\\admin", "groups": ["Domain Admins"]},
        ])

        entries[0]["username"] = "external.test\\admin"
        result = extract_privileged_users(users, groups, entries)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["accounts"], [])
        self.assertEqual(len(result["warnings"]), 1)
        self.assertIn("1 NTDS account(s)", result["warnings"][0])
        self.assertIn("selected privileged users", result["warnings"][0])
        confirmed = extract_privileged_users(users, groups, entries, sid)
        self.assertEqual(confirmed["status"], "available")
        self.assertEqual(confirmed["accounts"], [
            {"username": "external.test\\admin", "groups": ["Domain Admins"]},
        ])

    def test_audit_summary_shows_privileged_coverage(self):
        for status, accounts, expected in (
            ("available", [{"username": "alice", "groups": ["Domain Admins"]}], "1"),
            ("incomplete", [{"username": "alice", "groups": ["Domain Admins"]}], "1 (incomplete)"),
            ("unavailable", [], "Unavailable"),
        ):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                output = io.StringIO()
                organised = {
                    "filtered_users": [], "enabled_users": [], "ntlm_hashes": [],
                    "lm_hashes": [], "domain_admins": [],
                    "privileged_users": {"status": status, "accounts": accounts},
                }
                with (
                    patch.object(audit, "validate_audit_inputs"),
                    patch.object(audit, "create_audit_directory", return_value=Path(directory)),
                    patch.object(audit, "organise_dataset", return_value=organised),
                    patch.object(audit, "load_campaign", return_value={
                        "ntlm": {"parameters": {}, "phases": []},
                    }),
                    patch.object(audit, "has_enabled_phases", side_effect=RuntimeError("stop")),
                    patch.object(audit, "console", Console(file=output, width=100)),
                ):
                    with self.assertRaisesRegex(RuntimeError, "stop"):
                        audit.run_audit("company.ntds", "bloodhound.zip", "campaign.json", "test")
                summary = output.getvalue()
                row = next(line for line in summary.splitlines() if "Privileged Accounts" in line)
                self.assertIn(expected, row)

    def test_missing_and_invalid_privileged_data_are_not_clean_results(self):
        self.assertEqual(extract_privileged_users(None, None, [])["status"], "unavailable")
        self.assertEqual(
            extract_privileged_users({"data": []}, {"data": []}, [])["status"],
            "incomplete",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "privileged-users.json"
            path.write_text('{"status":"available","accounts":"bad","warnings":[]}')
            with self.assertRaisesRegex(ValueError, "Invalid privileged"):
                load_privileged_users(path)
            path.write_text(json.dumps({
                "status": "available", "accounts": [], "warnings": [],
                "confirmed_domain": {"name": "example.test", "sid": "invalid"},
            }))
            with self.assertRaisesRegex(ValueError, "Invalid privileged"):
                load_privileged_users(path)

    def test_extracts_each_selected_privileged_group(self):
        domain_sid = "S-1-5-21-1-2-3"
        user_sid = f"{domain_sid}-1000"
        users = {"data": [{
            "ObjectIdentifier": user_sid, "Properties": {"samaccountname": "alice"},
        }]}
        members = [{"ObjectIdentifier": user_sid, "ObjectType": "User"}]
        groups = {"data": [
            {"ObjectIdentifier": f"{domain_sid}-{rid}", "Members": members}
            for rid in (512, 518, 519, 517)
        ] + [
            {"ObjectIdentifier": f"S-1-5-32-{rid}", "Members": members}
            for rid in (544, 548, 549, 551)
        ] + [
            {"ObjectIdentifier": f"{domain_sid}-{rid}", "Members": members,
             "Properties": {"name": name}}
            for rid, name in ((2000, "DNSAdmins"), (2001, "Exchange Windows Permissions"))
        ]}
        result = extract_privileged_users(users, groups, [{"username": "alice", "rid": "1000"}])
        self.assertEqual(result["status"], "available")
        self.assertEqual(set(result["accounts"][0]["groups"]), {
            "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
            "DNSAdmins", "Account Operators", "Backup Operators", "Server Operators",
            "Cert Publishers", "Exchange Windows Permissions",
        })

    def test_privileged_export_excludes_disabled_and_filtered_accounts(self):
        domain_sid = "S-1-5-21-1-2-3"
        names = [("alice", "1000", True), ("test-user", "1001", True),
                 ("disabled", "1002", False)]
        entries = [
            {"username": name, "rid": rid, "enabled": enabled, "machine": False,
             "ntlm": "a" * 32, "lm": LM_EMPTY, "raw": name}
            for name, rid, enabled in names
        ]
        users = {"data": [
            {"ObjectIdentifier": f"{domain_sid}-{rid}",
             "Properties": {"samaccountname": name, "domain": "example.test"}}
            for name, rid, _ in names
        ]}
        groups = {"data": [
            {"ObjectIdentifier": f"{domain_sid}-512", "Members": []},
            {"ObjectIdentifier": "S-1-5-32-544", "Members": []},
            {"ObjectIdentifier": "S-1-5-32-551", "Members": [
                {"ObjectIdentifier": f"{domain_sid}-{rid}", "ObjectType": "User"}
                for _, rid, _ in names
            ]},
        ]}
        result = build_ntds_results(
            entries, username_filter="test-user", users_json=users, groups_json=groups,
        )
        self.assertEqual(result["privileged_users"]["accounts"], [
            {"username": "alice", "groups": ["Backup Operators"]},
        ])

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
                 "lm_hashes": ["hash"], "domain_admins": [],
                 "privileged_users": {"status": "available", "accounts": []}},
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
                 "lm_hashes": ["hash"], "domain_admins": [],
                 "privileged_users": {"status": "available", "accounts": []}},
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
                 "lm_hashes": ["hash"], "domain_admins": [],
                 "privileged_users": {"status": "available", "accounts": []}},
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
