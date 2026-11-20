import io
import json
import os
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import DEFAULT, patch

from rich.console import Console

import analysis.workflow as analysis_workflow
import auditing.workflow as audit_workflow
import cli.audit as cli_audit
import cli.analyse as cli_analyse
import cli.main as cli_main
from reports.html import render_html
from reports.json import write_findings
from reports.sureformat import write_sureformat
from analysis.parsers import load_ntds_users
from analysis.analysis import ntlm_hash_reuse
from analysis.executive_summary import executive_summary
from analysis.findings import build_findings_dict
from analysis.results import build_results
from analysis.technical_commentary import (
    commentary_admins,
    commentary_company_words,
    commentary_common_passwords,
    commentary_date_passwords,
    commentary_keyboard_walks,
    commentary_ntlm_hash_reuse,
    commentary_password_lengths,
    commentary_privileged_users,
    commentary_similar_account_reuse,
    commentary_username_passwords,
    technical_commentary,
)

REPORT = {
    "summary": {
        "total_passwords": 12,
        "enabled_users": 20,
        "unique_passwords": 10,
        "crack_rate": 60.0,
        "lm_hashes": 2,
        "lm_passwords_recovered": 1,
        "lm_recovery_rate": 50.0,
    },
    "executive_summary": "Executive summary text.",
    "technical_commentary": "Technical commentary text.",
    "remediation_guidance": "Remediation guidance text.",
    "references": (
        "- [https://example.test/passwords](https://example.test/passwords)\n"
        "- [https://example.test/policy(v=1)]"
        "(https://example.test/policy(v=1))"
    ),
    "findings": [{
        "id": "PWD-REUSE-001",
        "title": "</script><img src=x onerror=alert(1)>",
        "description": "A password was reused.",
        "severity": "high",
        "category": "password_reuse",
        "remediation": "Require unique passwords.",
        "evidence": [],
        "affected_assets": [],
        "references": [],
    }],
}


class HtmlReportTests(unittest.TestCase):
    def _patch_analysis_workflow(self):
        mocks = patch.multiple(
            analysis_workflow,
            load_list=DEFAULT,
            load_domain_policy=DEFAULT,
            load_company_words=DEFAULT,
            build_results=DEFAULT,
            executive_summary=DEFAULT,
            technical_commentary=DEFAULT,
            remediation_guidance=DEFAULT,
            remediation_references=DEFAULT,
            build_findings_dict=DEFAULT,
            write_findings=DEFAULT,
            _print_console_summary=DEFAULT,
        )
        values = mocks.start()
        self.addCleanup(mocks.stop)

        values["load_list"].return_value = []
        values["load_domain_policy"].return_value = {
            "Domain": "example.test",
            "Minimum Password Length": "12",
        }
        values["load_company_words"].return_value = []
        values["build_results"].return_value = {
            "total_passwords": 12,
            "enabled_users": 20,
            "unique_passwords": 10,
            "crack_rate": 60.0,
            "lm_hashes": {"count": 2},
            "lm_passwords": {"count": 1, "recoveryRate": 50.0},
            "domain_name": "example.test",
        }
        values["executive_summary"].return_value = "Executive summary."
        values["technical_commentary"].return_value = "Technical commentary."
        values["remediation_guidance"].return_value = "Remediation guidance."
        values["remediation_references"].return_value = "References."
        values["build_findings_dict"].return_value = REPORT["findings"]
        return values

    def test_html_dashboard_is_interactive_and_escapes_embedded_report_data(self):
        html = render_html(REPORT)

        self.assertIn('id="severity-filter"', html)
        self.assertIn('id="category-filter"', html)
        self.assertIn('id="search"', html)
        self.assertIn('id="lm-recovery-rate"', html)
        self.assertIn("title.textContent =", html)
        self.assertIn('createCopyControls("Copy Markdown", sectionMarkdown)', html)
        self.assertIn('createCopyControls("Copy All Markdown", allMarkdown.join("\\n\\n"))', html)
        self.assertIn("await navigator.clipboard.writeText(text)", html)
        self.assertIn('referenceHeading.textContent = "References"', html)
        self.assertIn("function renderReferenceList(references)", html)
        self.assertIn("link.href = match[2]", html)
        self.assertIn('link.rel = "noopener noreferrer"', html)
        self.assertIn('markdown.push(`### References\\n\\n${references}`)', html)
        self.assertNotIn('["references", "References"]', html)
        self.assertIn("\\u003c/script\\u003e\\u003cimg", html)
        self.assertNotIn("</script><img", html)
        self.assertNotIn("<script src=", html.lower())

    def test_findings_sidecar_keeps_its_json_envelope(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.json"
            write_findings(path, REPORT["findings"])

            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                {"findings": REPORT["findings"]},
            )

    def test_analysis_workflow_writes_html_and_findings_sidecar(self):
        with tempfile.TemporaryDirectory() as directory:
            mocks = self._patch_analysis_workflow()
            output = Path(directory) / "audit.txt"

            analysis_workflow.analyse_passwords(
                mapped_ntlm_passwords=None,
                domain_admins=None,
                company_words=None,
                pass_policy="policy.txt",
                enabled_users=None,
                output_file=str(output),
            )

            self.assertTrue((Path(directory) / "audit.html").exists())
            for suffix in (".md", ".json", ".yaml", ".sarif"):
                self.assertFalse((Path(directory) / f"audit{suffix}").exists())
            mocks["write_findings"].assert_called_once_with(
                "password-audit-findings.json",
                REPORT["findings"],
            )

    def test_sureformat_export_matches_adapter_and_warns_for_unmapped(self):
        mappings = [
            ("PWD-AUDIT-001", "SC-1930"),
            ("DOMAIN-ADMIN-001", "SC-2113"),
            ("PWD-REUSE-001", "SC-1708"),
            ("PWD-PATTERN-003", "SC-2201"),
            ("PWD-PATTERN-005", "SC-2203"),
            ("PWD-PATTERN-002", "SC-2204"),
            ("PWD-PATTERN-001", "SC-2200"),
            ("PWD-PATTERN-004", "SC-2205"),
            ("PWD-STATS-001", "SC-2206"),
            ("PWD-POLICY-001", "SC-3307"),
            ("LM-AUTH-001", "SC-1801"),
        ]
        findings = [
            {"id": finding_id, "description": f"{finding_id} < B & C"}
            for finding_id, _ in mappings
        ]
        findings.append({"id": "PWD-REUSE-002", "description": "No mapping."})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.xml"
            with patch("reports.sureformat.warn") as warning:
                write_sureformat(path, "example.test", findings)
            warning.assert_called_once_with(
                "No SureFormat mapping found for finding: PWD-REUSE-002"
            )
            root = ET.parse(path).getroot()
            self.assertEqual(root.tag, "items")
            self.assertEqual(root.attrib, {"source": "SureFormat", "version": "1.0.0"})
            item = root.find("item")
            self.assertEqual(item.attrib, {"ipaddress": "", "hostname": "example.test"})
            service = item.find("services/service")
            self.assertEqual(service.attrib, {"name": "", "port": "", "protocol": "tcp"})
            vulnerabilities = service.findall("vulnerabilities/vulnerability")
            self.assertEqual(
                [(v.attrib["id"], v.findtext("information")) for v in vulnerabilities],
                [(vuln_id, f"{finding_id} < B & C") for finding_id, vuln_id in mappings],
            )

    def test_sureformat_combines_reuse_findings_with_the_same_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.xml"
            write_sureformat(path, "example.test", [
                {"id": "PWD-REUSE-001", "description": "Recovered reuse."},
                {"id": "PWD-REUSE-003", "description": "Hash reuse."},
            ])
            entries = ET.parse(path).findall(".//vulnerability")
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].attrib["id"], "SC-1708")
            self.assertEqual(entries[0].findtext("information"), "Recovered reuse.\nHash reuse.")

    def test_ntds_user_loading_deduplicates_and_rejects_bad_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "users.txt"
            path.write_text(
                "EXAMPLE\\alice:1000:unused:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:::\n"
                "example\\ALICE:1000:unused:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:::\n",
                encoding="utf-8",
            )
            self.assertEqual(len(load_ntds_users(path)), 1)
            for record in (
                "alice:1000:unused:not-a-hash:::\n",
                "alice:not-a-rid:unused:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:::\n",
                "machine$:1000:unused:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:::\n",
                "alice:1000:unused:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa::: (status=Disabled)\n",
                "not-an-ntds-record\n",
                "EXAMPLE\\alice:1001:unused:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:::\n",
            ):
                with self.subTest(record=record):
                    path.write_text(
                        "EXAMPLE\\alice:1000:unused:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:::\n"
                        + record, encoding="utf-8"
                    )
                    with self.assertRaises(ValueError):
                        load_ntds_users(path)

    def test_hash_reuse_commentary_masks_samples_and_formats_counts(self):
        privileged = {
            "status": "incomplete", "warnings": ["Some members could not be resolved."],
            "accounts": [{"username": "EXAMPLE\\admin", "groups": ["Backup Operators"]}],
        }
        accounts = [
            {"username": "EXAMPLE\\admin", "ntlm": "a" * 32},
            {"username": "OTHER\\user|one", "ntlm": "a" * 32},
        ]
        reuse = ntlm_hash_reuse(accounts, privileged)
        text = commentary_ntlm_hash_reuse({"ntlm_hash_reuse": reuse})
        self.assertIn("A total of one shared NTLM hash was", text)
        self.assertIn("across two enabled user accounts", text)
        self.assertIn("Of these, one involves", text)
        self.assertNotIn("not identified in selected privileged groups", text)
        self.assertNotIn("\n\nOf these", text)
        self.assertIn("| aa" + "*" * 28 + "aa | admin, user\\|one |", text)
        self.assertNotIn("a" * 32, text)
        self.assertNotIn("a" * 32, json.dumps(reuse))
        self.assertNotIn("(s)", text)

        privileged["accounts"].append({"username": "OTHER\\user|one", "groups": ["Domain Admins"]})
        text = commentary_ntlm_hash_reuse({
            "ntlm_hash_reuse": ntlm_hash_reuse(accounts, privileged),
        })
        self.assertIn("Of these, one involves", text)
        self.assertNotIn("not identified in selected privileged groups", text)

        accounts = [
            {"username": f"user-{number}-{member}", "ntlm": f"{number:032x}"}
            for number in range(10) for member in range(2)
        ]
        nine = ntlm_hash_reuse(accounts[:18], privileged)
        self.assertIn("A total of nine shared NTLM hashes were",
                      commentary_ntlm_hash_reuse({"ntlm_hash_reuse": nine}))
        reuse = ntlm_hash_reuse(accounts, privileged)
        text = commentary_ntlm_hash_reuse({"ntlm_hash_reuse": reuse})
        self.assertIn("A total of 10 shared NTLM hashes were", text)
        self.assertIn("across 20 enabled user accounts", text)
        self.assertEqual(len([line for line in text.splitlines() if line.startswith("| 00")]), 5)
        self.assertEqual(len(reuse["groups"]), 10)

    def test_privileged_coverage_warning_is_concise(self):
        text = commentary_privileged_users({"privileged_users": {
            "status": "incomplete", "count": 1,
            "accounts": [{"username": "admin", "groups": ["Backup Operators"],
                          "password": "Password123!"}],
            "warnings": [
                "2 group member object(s) could not be resolved.",
                "386 NTDS account(s) could not be matched to a BloodHound domain; "
                "NetBIOS names or UPN suffixes may differ from DNS names.",
                "1 ambiguous NTDS/BloodHound account match(es) were omitted.",
            ],
        }})
        self.assertIn("Privileged group coverage is incomplete", text)
        self.assertIn("group memberships or account matches could not be verified", text)
        self.assertIn("see the privileged group membership dataset for details", text)
        self.assertNotIn("386", text)
        self.assertIn("Passwords were recovered for one account", text)
        self.assertNotIn("(s)", text)
        unavailable = commentary_privileged_users({"privileged_users": {
            "status": "unavailable", "count": 0, "accounts": [],
            "warnings": ["No privileged group membership dataset was supplied."],
        }})
        self.assertIn("Privileged group analysis is unavailable.", unavailable)
        self.assertNotIn("incomplete", unavailable)

    def test_password_length_commentary_uses_plural_characters_for_tied_lengths(self):
        text = commentary_password_lengths({
            "password_length": {"minimum_length": 14, "count": 6, "percentage": 22.9,
                                "failures": [{"length": length} for length in (10, 10, 10, 11, 11, 11)]},
            "password_lengths": {"lengths": [(15, 5), (10, 3), (11, 3)]},
        })
        self.assertIn("lengths were 10 and 11 characters", text)
        text = commentary_password_lengths({
            "password_length": {"minimum_length": 14, "count": 1, "percentage": 10,
                                "failures": [{"length": 10}]},
            "password_lengths": {"lengths": [(15, 5), (10, 1)]},
        })
        self.assertIn("identified one password (10% of", text)
        self.assertIn("password length was 10 characters", text)

    def test_hash_reuse_summary_and_finding(self):
        results = build_results(
            ntlm_mapped_passwords=[{"username": "user", "password": "weak"}],
            domain_admins=[], company_words=[], minimum_length=14,
            enabled_users=["admin", "user"], domain_name="example.test",
            lm_users=[], lm_mapped_passwords=[],
            privileged_users={
                "status": "available", "warnings": [],
                "accounts": [{"username": "admin", "groups": ["Backup Operators"]}],
            },
            ntds_users=[
                {"username": "admin", "ntlm": "a" * 32},
                {"username": "user", "ntlm": "a" * 32},
            ],
        )
        summary = executive_summary(results)
        self.assertIn("password reuse", summary)
        self.assertNotIn("shared credentials involving selected privileged", summary)
        self.assertNotIn("NTLM hash comparison", summary)
        finding = next(f for f in build_findings_dict(results) if f["id"] == "PWD-REUSE-003")
        self.assertIn("A total of one shared NTLM credential group was", finding["description"])
        self.assertNotIn("not identified in those groups", finding["description"])
        self.assertIn("Backup Operators", finding["evidence"][0])
        self.assertNotIn("(s)", finding["description"])
        self.assertNotIn("a" * 32, json.dumps(finding))
        audit_finding = next(f for f in build_findings_dict(results) if f["id"] == "PWD-AUDIT-001")
        self.assertIn("one plaintext password was recovered from two enabled accounts",
                      audit_finding["description"])
        hash_only = build_results(
            ntlm_mapped_passwords=[], domain_admins=[], company_words=[],
            minimum_length=14, enabled_users=["admin", "user"],
            domain_name="example.test", lm_users=[], lm_mapped_passwords=[],
            privileged_users={
                "status": "available", "warnings": [],
                "accounts": [{"username": "admin", "groups": ["Backup Operators"]}],
            },
            ntds_users=[
                {"username": "admin", "ntlm": "a" * 32},
                {"username": "user", "ntlm": "a" * 32},
            ],
        )
        self.assertIn("a broader password-management weakness: password reuse",
                      executive_summary(hash_only))

    def test_account_tables_omit_prefixes_without_changing_results(self):
        account = {"username": "EXAMPLE\\Ali|ce", "password": "Password123!",
                   "groups": ["Backup Operators"], "shared_with": "OTHER\\Bob"}
        sections = [
            (commentary_admins, {"admins": {"accounts": [account], "count": 1}}),
            (commentary_privileged_users, {"privileged_users": {
                "status": "available", "warnings": [], "accounts": [account], "count": 1,
            }}),
            (commentary_similar_account_reuse, {"similar_account_reuse": {
                "accounts": [account], "count": 1, "similarPairs": 1,
            }}),
        ]
        for function, key in (
            (commentary_username_passwords, "username_passwords"),
            (commentary_company_words, "company_words"),
            (commentary_common_passwords, "common_passwords"),
            (commentary_date_passwords, "date_passwords"),
            (commentary_keyboard_walks, "keyboard_walks"),
        ):
            sections.append((function, {key: {"accounts": [account], "count": 1, "stats": []}}))
        for function, results in sections:
            with self.subTest(section=function.__name__):
                text = function(results)
                self.assertIn("| Ali\\|ce |", text)
                self.assertNotIn("EXAMPLE\\", text)
                if function is commentary_similar_account_reuse:
                    self.assertIn("| Bob |", text)
                    self.assertNotIn("OTHER\\", text)
        self.assertEqual(account["username"], "EXAMPLE\\Ali|ce")
        self.assertEqual(account["shared_with"], "OTHER\\Bob")

    def test_commentary_headings_are_conditional_and_reuse_sections_are_ordered(self):
        results = build_results(
            ntlm_mapped_passwords=[
                {"username": "EXAMPLE\\alice", "password": "Password123!"},
                {"username": "EXAMPLE\\bob", "password": "Password123!"},
            ],
            domain_admins=[], company_words=[], minimum_length=14,
            enabled_users=["EXAMPLE\\alice", "EXAMPLE\\bob"], domain_name="example.test",
            lm_users=[], lm_mapped_passwords=[],
            privileged_users={"status": "available", "warnings": [], "accounts": []},
            ntds_users=[
                {"username": "EXAMPLE\\alice", "ntlm": "a" * 32},
                {"username": "EXAMPLE\\bob", "ntlm": "a" * 32},
            ],
        )
        text = technical_commentary(results)
        self.assertIn("### Password Compliance\n\n", text)
        self.assertIn("### Password Reuse\n\n", text)
        self.assertIn("### Common Patterns\n\n", text)
        self.assertIn("### Password Complexity\n\n", text)
        self.assertNotIn("### Privileged Accounts", text)
        self.assertNotIn("### LM Hashes", text)
        self.assertLess(text.index("Password reuse was identified"),
                        text.index("A total of one shared NTLM hash"))
        results["privileged_users"]["status"] = "incomplete"
        results["lm_hashes"].update({"count": 1, "uniqueHashes": 1, "duplicateHashes": 0})
        text = technical_commentary(results)
        self.assertIn("### Privileged Accounts\n\n", text)
        self.assertIn("### LM Hashes\n\n", text)

    def test_analysis_csacyber_writes_xml_instead_of_json(self):
        with tempfile.TemporaryDirectory() as directory:
            mocks = self._patch_analysis_workflow()
            output = Path(directory) / "audit.html"
            xml_path = Path(directory) / "findings.xml"
            with patch.object(
                analysis_workflow, "write_sureformat",
                side_effect=lambda path, domain, findings: write_sureformat(
                    xml_path, domain, findings
                ),
            ) as write_xml:
                analysis_workflow.analyse_passwords(
                    mapped_ntlm_passwords=None,
                    domain_admins=None,
                    company_words=None,
                    pass_policy="policy.txt",
                    enabled_users=None,
                    output_file=str(output),
                    csacyber=True,
                )
            write_xml.assert_called_once_with(
                "password-audit-findings.xml", "example.test", REPORT["findings"]
            )
            mocks["write_findings"].assert_not_called()
            self.assertTrue(output.exists())
            root = ET.parse(xml_path).getroot()
            self.assertEqual(root.find("item").attrib["hostname"], "example.test")
            mocks["_print_console_summary"].assert_called_once_with(
                mocks["build_results"].return_value, REPORT["findings"], output,
                "password-audit-findings.xml",
            )

    def test_csacyber_requires_domain_before_writing_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            mocks = self._patch_analysis_workflow()
            mocks["build_results"].return_value["domain_name"] = None
            output = Path(directory) / "audit.html"
            with self.assertRaisesRegex(ValueError, "requires a domain name"):
                analysis_workflow.analyse_passwords(
                    mapped_ntlm_passwords=None,
                    domain_admins=None,
                    company_words=None,
                    pass_policy="policy.txt",
                    enabled_users=None,
                    output_file=str(output),
                    csacyber=True,
                )
            self.assertFalse(output.exists())
            mocks["write_findings"].assert_not_called()

    def test_csacyber_flag_is_forwarded_by_both_commands(self):
        for command, args, handler, forward in (
            ("audit", ["-N", "input.ntds", "-B", "input.zip", "-C", "config.json",
                       "-G", "test"], "run_audit_workflow", "audit"),
            ("analyse", ["-M", "passwords.txt"], "run_password_analysis", "analyse"),
        ):
            with self.subTest(command=command):
                with (
                    patch.object(sys, "argv", ["password-audit", command, *args, "--csacyber"]),
                    patch.object(cli_main, handler) as run_command,
                ):
                    cli_main.main()
                parsed = run_command.call_args.args[0]
                self.assertTrue(parsed.csacyber)
                if forward == "audit":
                    with patch.object(cli_audit, "run_audit") as run:
                        cli_audit.run_audit_workflow(parsed)
                else:
                    with patch.object(cli_analyse, "analyse_passwords") as run:
                        cli_analyse.run_password_analysis(parsed)
                self.assertTrue(run.call_args.kwargs["csacyber"])

    def test_analyse_cli_generates_selected_findings_format(self):
        with tempfile.TemporaryDirectory() as directory:
            original_cwd = os.getcwd()
            try:
                for csacyber in (False, True):
                    run_dir = Path(directory) / ("xml" if csacyber else "json")
                    run_dir.mkdir()
                    (run_dir / "mapped.txt").write_text(
                        "alice:Password123!\n", encoding="utf-8"
                    )
                    (run_dir / "policy.txt").write_text(
                        "Domain: example.test\nMinimum Password Length: 12\n",
                        encoding="utf-8",
                    )
                    (run_dir / "admins.txt").write_text("", encoding="utf-8")
                    (run_dir / "users.txt").write_text("alice\n", encoding="utf-8")
                    os.chdir(run_dir)
                    args = [
                        "password-audit", "analyse", "-M", "mapped.txt",
                        "-P", "policy.txt", "-D", "admins.txt", "-E", "users.txt",
                    ]
                    if csacyber:
                        args.append("--csacyber")
                    with patch.object(sys, "argv", args):
                        cli_main.main()
                    self.assertTrue((run_dir / "password-audit-report.html").exists())
                    json_path = run_dir / "password-audit-findings.json"
                    xml_path = run_dir / "password-audit-findings.xml"
                    self.assertEqual(json_path.exists(), not csacyber)
                    self.assertEqual(xml_path.exists(), csacyber)
                    if csacyber:
                        root = ET.parse(xml_path).getroot()
                        self.assertEqual(root.find("item").attrib["hostname"], "example.test")
                        ids = {
                            node.attrib["id"]
                            for node in root.findall(".//vulnerability")
                        }
                        self.assertIn("SC-1930", ids)
                    else:
                        self.assertTrue(json.loads(json_path.read_text(encoding="utf-8"))["findings"])
            finally:
                os.chdir(original_cwd)

    def test_analyse_cli_accepts_privileged_membership_from_organise(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "mapped.txt").write_text(
                "EXAMPLE\\alice:Password123!\nEXAMPLE\\alice:Password123!\n"
                "OTHER\\alice:Different123!\n",
                encoding="utf-8",
            )
            (root / "policy.txt").write_text(
                "Domain: example.test\nMinimum Password Length: 12\n", encoding="utf-8"
            )
            (root / "admins.txt").write_text("", encoding="utf-8")
            (root / "users.txt").write_text(
                "EXAMPLE\\alice\nOTHER\\alice\n", encoding="utf-8"
            )
            (root / "privileged.json").write_text(json.dumps({
                "status": "available",
                "accounts": [{"username": "EXAMPLE\\alice", "groups": ["Backup Operators"]}],
                "warnings": [],
            }), encoding="utf-8")
            original_cwd = os.getcwd()
            try:
                os.chdir(root)
                args = [
                    "password-audit", "analyse", "-M", "mapped.txt",
                    "-P", "policy.txt", "-D", "admins.txt", "-E", "users.txt",
                    "--privileged-users", "privileged.json",
                ]
                with patch.object(sys, "argv", args):
                    cli_main.main()
                findings = json.loads((root / "password-audit-findings.json").read_text())
                finding = next(f for f in findings["findings"]
                               if f["id"] == "PRIV-ACCOUNT-001")
                self.assertIn("one account", finding["description"])
                report = (root / "password-audit-report.html").read_text(encoding="utf-8")
                self.assertIn("Backup Operators", report)
                self.assertIn("Pa********3!", report)
                self.assertNotIn("Di**********3!", report)
                (root / "privileged.json").write_text(json.dumps({
                    "status": "incomplete",
                    "accounts": [{"username": "EXAMPLE\\alice", "groups": ["Backup Operators"]}],
                    "warnings": ["Some group members were not resolved."],
                }), encoding="utf-8")
                with patch.object(sys, "argv", args):
                    cli_main.main()
                report = (root / "password-audit-report.html").read_text(encoding="utf-8")
                self.assertIn("Privileged group coverage is incomplete", report)
                self.assertIn("Backup Operators", report)
                (root / "mapped.txt").write_text(
                    "EXAMPLE\\alice:Password123!\nEXAMPLE\\alice:OtherPass123!\n",
                    encoding="utf-8",
                )
                with patch.object(sys, "argv", args):
                    with self.assertRaisesRegex(ValueError, "Conflicting recovered passwords"):
                        cli_main.main()
            finally:
                os.chdir(original_cwd)

    def test_analyse_cli_reports_unrecovered_hash_reuse_and_incomplete_privilege_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "mapped.txt").write_text("", encoding="utf-8")
            (root / "policy.txt").write_text(
                "Domain: example.test\nMinimum Password Length: 12\n", encoding="utf-8"
            )
            (root / "admins.txt").write_text("", encoding="utf-8")
            (root / "users.txt").write_text("admin\nuser\n", encoding="utf-8")
            (root / "ntds.txt").write_text(
                "admin:1000:unused:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:::\n"
                "user:1001:unused:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:::\n",
                encoding="utf-8",
            )
            (root / "privileged.json").write_text(json.dumps({
                "status": "incomplete",
                "accounts": [{"username": "admin", "groups": ["Backup Operators"]}],
                "warnings": ["Some group members were not resolved."],
            }), encoding="utf-8")
            original_cwd = os.getcwd()
            try:
                os.chdir(root)
                args = [
                    "password-audit", "analyse", "-M", "mapped.txt",
                    "-P", "policy.txt", "-D", "admins.txt", "-E", "users.txt",
                    "--privileged-users", "privileged.json", "--ntds-users", "ntds.txt",
                ]
                with patch.object(sys, "argv", args):
                    cli_main.main()
                findings = json.loads((root / "password-audit-findings.json").read_text())
                reuse = next(item for item in findings["findings"] if item["id"] == "PWD-REUSE-003")
                self.assertEqual(reuse["affected_assets"], ["admin", "user"])
                self.assertNotIn("not necessarily unprivileged", reuse["description"])
                self.assertIn("Backup Operators", reuse["evidence"][0])
                self.assertNotIn("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", json.dumps(reuse).lower())
                report = (root / "password-audit-report.html").read_text(encoding="utf-8")
                self.assertIn("Privileged group coverage is incomplete", report)
                self.assertIn("regardless of whether their passwords were recovered", report)
                self.assertNotIn("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", report.lower())
                self.assertIn("No plaintext passwords were recovered", report)
                self.assertNotIn("did not identify any significant", report)
                self.assertNotIn("full compliance with the configured", report)

                (root / "ntds.txt").write_text(
                    "admin:1000:unused:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:::\n"
                    "user:1001:unused:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:::\n",
                    encoding="utf-8",
                )
                with patch.object(sys, "argv", args):
                    cli_main.main()
                findings = json.loads((root / "password-audit-findings.json").read_text())
                self.assertNotIn("PWD-REUSE-003", [item["id"] for item in findings["findings"]])
                with patch.object(sys, "argv", args[:-2]):
                    cli_main.main()
                report = (root / "password-audit-report.html").read_text(encoding="utf-8")
                self.assertIn("NTLM hash reuse analysis was unavailable", report)

                with patch.object(sys, "argv", args[:-2] + ["--ntds-users", "missing.txt"]):
                    with self.assertRaises(FileNotFoundError):
                        cli_main.main()
            finally:
                os.chdir(original_cwd)

    def test_analyse_auto_loads_hashes_only_for_the_default_dataset(self):
        with tempfile.TemporaryDirectory() as directory:
            original_cwd = os.getcwd()
            try:
                os.chdir(directory)
                Path("password-audit").mkdir()
                Path("password-audit/ntds-users-clean.txt").write_text("", encoding="utf-8")
                for mapped, expected in (
                    ("password-audit/mapped-ntlm-passwords.txt", Path("password-audit/ntds-users-clean.txt")),
                    ("other/mapped.txt", None),
                ):
                    with self.subTest(mapped=mapped), patch.object(
                        sys, "argv", ["password-audit", "analyse", "-M", mapped]
                    ), patch.object(cli_analyse, "analyse_passwords") as run:
                        cli_main.main()
                        self.assertEqual(run.call_args.kwargs["ntds_users"], expected)
            finally:
                os.chdir(original_cwd)

    def test_audit_cli_forwards_without_report_format_option(self):
        arguments = [
            "password-audit",
            "audit",
            "-N", "company.ntds",
            "-B", "bloodhound.zip",
            "-C", "config.json",
            "-G", "internal-password-audit",
        ]
        with (
            patch.object(sys, "argv", arguments),
            patch.object(cli_main, "run_audit_workflow") as run_audit_workflow,
        ):
            cli_main.main()

        parsed = run_audit_workflow.call_args.args[0]
        self.assertIsNone(parsed.company_words)
        for field in (
            "mapped_ntlm_passwords", "mapped_lm_passwords", "lm_users",
            "domain_admins", "pass_policy", "enabled_users",
        ):
            self.assertIsNone(getattr(parsed, field))
        self.assertFalse(hasattr(parsed, "resume"))
        self.assertFalse(hasattr(parsed, "report_formats"))

        args = parsed
        with patch.object(cli_audit, "run_audit") as run_audit:
            cli_audit.run_audit_workflow(args)

        self.assertNotIn("report_formats", run_audit.call_args.kwargs)
        self.assertNotIn("resume", run_audit.call_args.kwargs)

    def test_audit_workflow_uses_html_report_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path_factory = lambda path: Path(directory) / path
            mocks = patch.multiple(
                audit_workflow,
                validate_audit_inputs=DEFAULT,
                organise_dataset=DEFAULT,
                load_campaign=DEFAULT,
                has_enabled_phases=DEFAULT,
                analyse_passwords=DEFAULT,
                run_campaign=DEFAULT,
                print_summary=DEFAULT,
            )
            values = mocks.start()
            self.addCleanup(mocks.stop)
            path_patch = patch.object(
                audit_workflow,
                "Path",
                side_effect=path_factory,
            )
            path_patch.start()
            self.addCleanup(path_patch.stop)

            values["organise_dataset"].side_effect = [
                {
                    "filtered_users": [],
                    "enabled_users": [],
                    "ntlm_hashes": [],
                    "lm_hashes": [],
                    "domain_admins": [],
                    "privileged_users": {"status": "available", "accounts": []},
                },
                {"mapped_ntlm_passwords": []},
            ]
            values["load_campaign"].return_value = {
                "ntlm": {"parameters": {}, "phases": []},
            }
            values["has_enabled_phases"].return_value = True
            values["run_campaign"].return_value = {"phases": []}

            result = audit_workflow.run_audit(
                ntds_file="company.ntds",
                bloodhound_file="bloodhound.zip",
                campaign_file="config.json",
                campaign_name="internal-password-audit",
                csacyber=True,
                mapped_ntlm_passwords="custom-ntlm.txt",
                mapped_lm_passwords="custom-lm.txt",
                lm_users="custom-lm-users.txt",
                domain_admins="custom-admins.txt",
                pass_policy="custom-policy.txt",
                enabled_users="custom-users.txt",
            )

            analysis_args = values["analyse_passwords"].call_args.kwargs
            self.assertTrue(analysis_args["csacyber"])
            for field, path in (
                ("mapped_ntlm_passwords", "custom-ntlm.txt"),
                ("mapped_lm_passwords", "custom-lm.txt"),
                ("lm_users", "custom-lm-users.txt"),
                ("domain_admins", "custom-admins.txt"),
                ("pass_policy", "custom-policy.txt"),
                ("enabled_users", "custom-users.txt"),
            ):
                self.assertEqual(analysis_args[field], path)
            self.assertNotIn(
                "resume",
                values["run_campaign"].call_args.kwargs,
            )
            self.assertNotIn(
                "report_formats",
                values["analyse_passwords"].call_args.kwargs,
            )
            self.assertEqual(
                values["analyse_passwords"].call_args.kwargs["company_words"],
                [result["outputDir"] / "company-words.txt"],
            )
            self.assertEqual(
                result["report"],
                result["outputDir"] / "password-audit-report.html",
            )
            self.assertEqual(
                values["analyse_passwords"].call_args.kwargs["findings_file"],
                result["outputDir"] / "password-audit-findings.xml",
            )

    def test_cli_help_uses_rich_formatter_and_keeps_examples(self):
        output = io.StringIO()
        arguments = ["password-audit", "analyse", "--help"]
        with (
            patch.object(sys, "argv", arguments),
            redirect_stdout(output),
            self.assertRaises(SystemExit) as exit_info,
        ):
            cli_main.main()

        self.assertEqual(exit_info.exception.code, 0)
        help_text = output.getvalue()
        self.assertIn("Options:", help_text)
        self.assertIn("Example:", help_text)
        self.assertIn("password-audit analyse", help_text)
        self.assertNotIn("--format", help_text)
        self.assertNotIn("--resume", help_text)

    def test_audit_help_has_no_report_format_option(self):
        output = io.StringIO()
        arguments = ["password-audit", "audit", "--help"]
        with (
            patch.object(sys, "argv", arguments),
            redirect_stdout(output),
            self.assertRaises(SystemExit) as exit_info,
        ):
            cli_main.main()

        self.assertEqual(exit_info.exception.code, 0)
        help_text = output.getvalue()
        self.assertNotIn("--format", help_text)
        self.assertNotIn("--resume", help_text)

    def test_rich_summary_displays_findings_and_output_paths(self):
        output = io.StringIO()
        original_console = analysis_workflow.console
        analysis_workflow.console = Console(file=output, width=120)
        results = {
            "total_passwords": 12,
            "enabled_users": 20,
            "unique_passwords": 10,
            "crack_rate": 60.0,
            "lm_hashes": {"count": 2},
            "lm_passwords": {"count": 1},
        }
        try:
            analysis_workflow._print_console_summary(
                results,
                REPORT["findings"],
                Path("audit.html"),
                "password-audit-findings.json",
            )
        finally:
            analysis_workflow.console = original_console

        rendered = output.getvalue()
        self.assertIn("PWD-REUSE-001", rendered)
        self.assertIn("password_reuse", rendered)
        self.assertIn("audit.html", rendered)
        self.assertNotIn("Critical / High Findings", rendered)


if __name__ == "__main__":
    unittest.main()
