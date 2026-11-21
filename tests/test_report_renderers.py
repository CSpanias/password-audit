import io
import json
import os
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout
from copy import deepcopy
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
from analysis.findings import build_finding_summary, build_findings_dict
from analysis.remediation_guidance import remediation_references
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
            build_finding_summary=DEFAULT,
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
        values["build_finding_summary"].return_value = []
        return values

    def test_html_dashboard_is_interactive_and_escapes_embedded_report_data(self):
        html = render_html(REPORT)

        self.assertIn('id="severity-filter"', html)
        self.assertIn('id="category-filter"', html)
        self.assertIn('id="search"', html)
        self.assertIn('id="lm-recovery-rate"', html)
        self.assertIn('id="finding-summary-cards"', html)
        self.assertIn("title.textContent =", html)
        self.assertIn('createCopyControls("Copy Markdown", sectionMarkdown)', html)
        self.assertIn('createCopyControls("Copy All Markdown", allMarkdown.join("\\n\\n"))', html)
        self.assertIn("await navigator.clipboard.writeText(text)", html)
        self.assertIn('referenceHeading.textContent = "References"', html)
        self.assertIn("function renderReferenceList(references)", html)
        self.assertIn("link.href = match[2]", html)
        self.assertIn('link.rel = "noopener noreferrer"', html)
        self.assertIn('markdown.push(`### References\\n\\n${references}`)', html)
        self.assertIn("const references = finding.references || []", html)
        self.assertIn("detail.append(heading, renderReferenceList(markdown))", html)
        self.assertNotIn('["references", "References"]', html)
        self.assertIn("\\u003c/script\\u003e\\u003cimg", html)
        self.assertNotIn("</script><img", html)
        self.assertNotIn("<script src=", html.lower())

    def test_finding_summary_includes_only_findings_with_accurate_units(self):
        results = build_results(
            ntlm_mapped_passwords=[
                {"username": "alice", "password": "Password1"},
                {"username": "alice_adm", "password": "Password1"},
            ],
            domain_admins=[], company_words=[], minimum_length=14,
            enabled_users=["alice", "alice_adm"], domain_name="example.test",
            lm_users=[], lm_mapped_passwords=[],
            privileged_users={"status": "available", "warnings": [], "accounts": []},
            ntds_users=[
                {"username": "alice", "ntlm": "a" * 32},
                {"username": "alice_adm", "ntlm": "a" * 32},
            ],
        )
        results["hibp"] = {"checked": 2, "count": 2, "accounts": ["alice", "alice_adm"]}
        findings = build_findings_dict(results)
        cards = {card["id"]: card for card in build_finding_summary(results, findings)}
        self.assertEqual((cards["PWD-BREACH-001"]["count"], cards["PWD-BREACH-001"]["unit"]),
                         (2, "accounts"))
        self.assertEqual((cards["PWD-REUSE-001"]["count"], cards["PWD-REUSE-001"]["unit"]),
                         (1, "unique passwords"))
        self.assertEqual((cards["PWD-REUSE-002"]["count"], cards["PWD-REUSE-002"]["unit"]),
                         (1, "account pairs"))
        self.assertEqual((cards["PWD-REUSE-003"]["count"], cards["PWD-REUSE-003"]["unit"]),
                         (1, "shared credential groups"))
        self.assertEqual(set(cards), {
            finding["id"] for finding in findings
            if finding["id"] not in {"PWD-AUDIT-001", "PWD-STATS-001"}
        })

        results["hibp"]["count"] = 0
        findings = build_findings_dict(results)
        self.assertNotIn("PWD-BREACH-001", {
            card["id"] for card in build_finding_summary(results, findings)
        })
        del results["hibp"]
        findings = build_findings_dict(results)
        self.assertNotIn("PWD-BREACH-001", {
            card["id"] for card in build_finding_summary(results, findings)
        })

    def test_finding_summary_covers_each_check_and_excludes_generic_findings(self):
        results = build_results(
            ntlm_mapped_passwords=[], domain_admins=[], company_words=[],
            minimum_length=14, enabled_users=["alice"], domain_name="example.test",
            lm_users=[], lm_mapped_passwords=[],
            privileged_users={"status": "available", "warnings": [], "accounts": []},
            ntds_users=[],
        )
        self.assertEqual(build_finding_summary(results, build_findings_dict(results)), [])
        results["total_passwords"] = 1
        results["admins"]["count"] = 1
        results["privileged_users"]["accounts"] = [{"username": "operator", "groups": []}]
        results["lm_hashes"]["count"] = 1
        results["lm_admins"]["count"] = 1
        results["password_reuse_general"]["sharedPasswords"] = 1
        results["similar_account_reuse"]["count"] = 1
        results["ntlm_hash_reuse"].update({
            "groups": [{"accounts": [{"username": "alice", "groups": []}]}],
            "account_count": 1,
        })
        results["hibp"] = {"count": 1, "accounts": ["alice"]}
        for key in ("password_length", "username_passwords", "company_words",
                    "common_passwords", "date_passwords", "keyboard_walks"):
            results[key]["count"] = 1
        findings = build_findings_dict(results)
        cards = build_finding_summary(results, findings)
        self.assertEqual(len(cards), 14)
        self.assertEqual(
            {card["id"] for card in cards},
            {finding["id"] for finding in findings}
            - {"PWD-AUDIT-001", "PWD-STATS-001"},
        )
        self.assertTrue(all(card["count"] == 1 and card["unit"] for card in cards))

    def test_password_findings_and_report_include_relevant_nist_references(self):
        results = build_results(
            ntlm_mapped_passwords=[{"username": "alice", "password": "short"}],
            domain_admins=[], company_words=[], minimum_length=14,
            enabled_users=["alice"], domain_name="example.test",
            lm_users=[], lm_mapped_passwords=[],
            privileged_users={"status": "available", "warnings": [], "accounts": []},
            ntds_users=[],
        )
        base = "https://pages.nist.gov/800-63-4/sp800-63b.html"
        findings = {finding["id"]: finding for finding in build_findings_dict(results)}
        self.assertIn(base + "#appA", findings["PWD-AUDIT-001"]["references"])
        self.assertIn(base + "#length", findings["PWD-POLICY-001"]["references"])
        self.assertIn(base + "#complexity", findings["PWD-STATS-001"]["references"])
        references = remediation_references(results)
        for anchor in ("appA", "length", "complexity"):
            self.assertEqual(references.count(f"({base}#{anchor})"), 1)
        self.assertIn(
            "Strict composition rules can encourage predictable choices and make passwords harder to remember.",
            technical_commentary(results),
        )

        results["password_length"]["count"] = 0
        results["character_classes"] = {}
        references = remediation_references(results)
        self.assertIn(base + "#appA", references)
        self.assertNotIn(base + "#length", references)
        self.assertNotIn(base + "#complexity", references)
        self.assertNotIn("PWD-POLICY-001", {
            finding["id"] for finding in build_findings_dict(results)
        })

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
            cards = [{
                "id": "PWD-BREACH-001", "title": "Passwords Found in Known Breach Data",
                "count": 2, "unit": "accounts",
            }]
            mocks["build_finding_summary"].return_value = cards

            analysis_workflow.analyse_passwords(
                mapped_ntlm_passwords=None,
                domain_admins=None,
                company_words=None,
                pass_policy="policy.txt",
                enabled_users=None,
                output_file=str(output),
            )

            self.assertTrue((Path(directory) / "audit.html").exists())
            html = (Path(directory) / "audit.html").read_text(encoding="utf-8")
            data = html.split('<script id="report-data" type="application/json">', 1)[1]
            report = json.loads(data.split("</script>", 1)[0])
            self.assertEqual(report["finding_summary"], cards)
            mocks["build_finding_summary"].assert_called_once_with(
                mocks["build_results"].return_value, REPORT["findings"]
            )
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
            ("DOMAIN-ADMIN-002", "SC-10673"),
            ("PRIV-ACCOUNT-001", "SC-10672"),
            ("PWD-REUSE-001", "SC-10671"),
            ("PWD-REUSE-002", "SC-2202"),
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
        findings.append({"id": "UNMAPPED-TEST", "description": "No mapping."})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.xml"
            with patch("reports.sureformat.warn") as warning:
                write_sureformat(path, "example.test", findings)
            warning.assert_called_once_with(
                "No SureFormat mapping found for finding: UNMAPPED-TEST"
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
                {"id": "PWD-REUSE-002", "description": "Similar accounts."},
                {"id": "DOMAIN-ADMIN-002", "description": "Domain admin LM."},
            ])
            entries = ET.parse(path).findall(".//vulnerability")
            self.assertEqual(len(entries), 3)
            self.assertEqual(entries[0].attrib["id"], "SC-10671")
            self.assertEqual(entries[0].findtext("information"), "Recovered reuse.\nHash reuse.")
            self.assertEqual(entries[1].attrib["id"], "SC-2202")
            self.assertEqual(entries[1].findtext("information"), "Similar accounts.")
            self.assertEqual(entries[2].attrib["id"], "SC-10673")
            self.assertEqual(entries[2].findtext("information"), "Domain admin LM.")

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
            "accounts": [{"username": "EXAMPLE\\admin", "groups": [
                "Backup Operators (example.test)", "Domain Admins (example.test)",
            ]}],
        }
        accounts = [
            {"username": "EXAMPLE\\admin", "ntlm": "a" * 32},
            {"username": "OTHER\\user|one", "ntlm": "a" * 32},
        ]
        reuse = ntlm_hash_reuse(accounts, privileged)
        text = commentary_ntlm_hash_reuse({"ntlm_hash_reuse": reuse})
        self.assertIn("A total of one shared NTLM hash was", text)
        self.assertIn("across two enabled user accounts", text)
        self.assertIn("Of these, one includes an account in a selected privileged group.", text)
        self.assertNotIn("not identified in selected privileged groups", text)
        self.assertNotIn("\n\nOf these", text)
        self.assertIn("| aa" + "*" * 28 + "aa | admin (Backup Operators, Domain Admins) | user\\|one |", text)
        self.assertIn("| NTLM Hash | Privileged Accounts (Groups) | Other Accounts |", text)
        self.assertNotIn("example.test", text)
        self.assertNotIn("The hash reuse finding lists", text)
        self.assertNotIn("a" * 32, text)
        self.assertNotIn("a" * 32, json.dumps(reuse))
        self.assertNotIn("(s)", text)

        privileged["accounts"].append({"username": "OTHER\\user|one", "groups": ["Domain Admins"]})
        text = commentary_ntlm_hash_reuse({
            "ntlm_hash_reuse": ntlm_hash_reuse(accounts, privileged),
        })
        self.assertIn("Of these, one includes", text)
        self.assertIn("admin (Backup Operators, Domain Admins); user\\|one (Domain Admins) | - |", text)
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
        self.assertNotIn("Of these", text)
        self.assertEqual(len([line for line in text.splitlines() if line.startswith("| 00")]), 5)
        self.assertEqual(len(reuse["groups"]), 10)

    def test_hash_reuse_commentary_separates_privileged_and_other_samples(self):
        accounts = [
            {"username": "admin", "ntlm": "a" * 32},
            {"username": "user", "ntlm": "a" * 32},
            {"username": "operator", "ntlm": "b" * 32},
            {"username": "other", "ntlm": "b" * 32},
            {"username": "member1", "ntlm": "c" * 32},
            {"username": "member2", "ntlm": "c" * 32},
        ]
        privileged = {"accounts": [
            {"username": "admin", "groups": ["Domain Admins (example.test)"]},
            {"username": "operator", "groups": ["Backup Operators"]},
        ]}
        text = commentary_ntlm_hash_reuse({
            "ntlm_hash_reuse": ntlm_hash_reuse(accounts, privileged),
        })
        self.assertIn(
            "Of these, two include accounts in selected privileged groups.",
            text,
        )
        self.assertIn("admin (Domain Admins) | user |", text)
        self.assertIn("operator (Backup Operators) | other |", text)
        self.assertIn("| cc" + "*" * 28 + "cc | member1, member2 |", text)
        self.assertIn("| NTLM Hash | Accounts |", text)
        self.assertNotIn("example.test", text)

    def test_privileged_coverage_warning_is_concise(self):
        text = commentary_privileged_users({"admins": {"accounts": []}, "privileged_users": {
            "status": "incomplete", "count": 1,
            "accounts": [{"username": "admin", "groups": ["Backup Operators"],
                          "password": "Password123!"}],
            "confirmed_domain": {"name": "example.test", "sid": "S-1-5-21-1-2-3"},
            "warnings": [
                "1 group member object could not be resolved because its record was not found "
                "in the BloodHound users or groups data.",
                "1 ambiguous NTDS/BloodHound account match was omitted.",
            ],
        }})
        self.assertIn(
            "Privileged group coverage for the confirmed domain example.test is incomplete: "
            "one group member object could not be resolved because its record was not found "
            "in the BloodHound users or groups data. "
            "One ambiguous NTDS/BloodHound account match was omitted. "
            "Some affected accounts may be missing. Group memberships include nested "
            "membership and are limited to the collected BloodHound data; they are not "
            "a complete assessment of all privileged access or attack paths.\n\n",
            text,
        )
        self.assertEqual(text.count("Group memberships include nested membership"), 1)
        self.assertNotIn("S-1-5-21-1-2-3", text)
        self.assertIn("Passwords were recovered for one account", text)
        self.assertNotIn("(s)", text)
        unavailable = commentary_privileged_users({"admins": {"accounts": []}, "privileged_users": {
            "status": "unavailable", "count": 0, "accounts": [],
            "warnings": ["No privileged group membership dataset was supplied."],
        }})
        self.assertIn("Privileged group analysis is unavailable.", unavailable)
        self.assertNotIn("incomplete", unavailable)

    def test_privileged_coverage_expands_single_digit_counts_only(self):
        for count, expected in enumerate(
            ("one", "two", "three", "four", "five", "six", "seven", "eight", "nine"), 1
        ):
            with self.subTest(count=count):
                results = {"admins": {"accounts": []}, "privileged_users": {
                    "status": "incomplete", "accounts": [],
                    "warnings": [f"{count} group member objects could not be resolved."],
                }}
                self.assertIn(f"is incomplete: {expected} group member", commentary_privileged_users(results))
        warnings = [
            "9 groups lacked membership data.",
            "10 groups had conflicting names or domains.",
            "1 ambiguous NTDS/BloodHound account match was omitted.",
        ]
        results = {"admins": {"accounts": []}, "privileged_users": {
            "status": "incomplete", "accounts": [], "warnings": warnings,
        }}
        text = commentary_privileged_users(results)
        self.assertIn(
            "is incomplete: nine groups lacked membership data. "
            "10 groups had conflicting names or domains. "
            "One ambiguous NTDS/BloodHound account match was omitted.",
            text,
        )
        self.assertEqual(warnings[0], "9 groups lacked membership data.")
        results["privileged_users"]["status"] = "unavailable"
        results["privileged_users"]["warnings"] = ["1 group record is unavailable."]
        self.assertIn("unavailable. One group record", commentary_privileged_users(results))

    def test_password_length_commentary_uses_plural_characters_for_tied_lengths(self):
        text = commentary_password_lengths({
            "password_length": {"minimum_length": 14, "count": 6, "percentage": 22.9,
                                "failures": [{"length": length} for length in (10, 10, 10, 11, 11, 11)]},
            "password_lengths": {"lengths": [(15, 5), (10, 3), (11, 3)]},
        })
        self.assertIn("lengths were 10 and 11 characters", text)
        self.assertIn("15 characters.\n\nThe following non-compliant", text)
        text = commentary_password_lengths({
            "password_length": {"minimum_length": 14, "count": 1, "percentage": 10,
                                "failures": [{"length": 10}]},
            "password_lengths": {"lengths": [(15, 5), (10, 1)]},
        })
        self.assertIn("found one password (10% of", text)
        self.assertIn("password length was 10 characters", text)

    def test_executive_summary_includes_generic_positive_sentence_only_when_applicable(self):
        results = build_results(
            ntlm_mapped_passwords=[
                {"username": "alice", "password": "weak"},
                {"username": "alice_adm", "password": "weak"},
            ],
            domain_admins=["alice"], company_words=[], minimum_length=14,
            enabled_users=["alice", "alice_adm"], domain_name="example.test",
            lm_users=[], lm_mapped_passwords=[],
            privileged_users={"status": "available", "warnings": [], "accounts": []},
        )
        results["admins"]["count"] = 1
        results["password_reuse_general"]["sharedPasswords"] = [("weak", 2)]
        results["ntlm_hash_reuse"]["groups"] = []
        results["password_length"]["count"] = 1
        results["similar_account_reuse"]["similarPairs"] = 1
        results["similar_account_reuse"]["count"] = 1
        positive = (
            "Some results suggest that existing password security controls and "
            "user practices may be reducing exposure to credential compromise."
        )

        summary = executive_summary(results)
        self.assertNotIn(positive, summary)
        self.assertIn("The audit demonstrated", summary.split("\n\n")[0])

        for finding in ("admins", "reuse", "length", "similar"):
            with self.subTest(finding=finding):
                positive_results = deepcopy(results)
                if finding == "admins":
                    positive_results["admins"]["count"] = 0
                elif finding == "reuse":
                    positive_results["password_reuse_general"]["sharedPasswords"] = []
                elif finding == "length":
                    positive_results["password_length"]["count"] = 0
                else:
                    positive_results["similar_account_reuse"]["count"] = 0
                summary = executive_summary(positive_results)
                self.assertIn(
                    positive + " However, the audit demonstrated",
                    summary.split("\n\n")[0],
                )
                self.assertNotIn("Several positive security outcomes", summary)

        incomplete = deepcopy(results)
        incomplete["admins"]["count"] = 0
        incomplete["privileged_users"]["status"] = "incomplete"
        self.assertNotIn(positive, executive_summary(incomplete))

        results["total_passwords"] = 0
        summary = executive_summary(results)
        self.assertNotIn(positive, summary)
        self.assertIn("No plaintext passwords were recovered", summary.split("\n\n")[0])

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
        self.assertIn("Password reuse could allow a compromised credential to affect multiple accounts", summary)
        self.assertNotIn("LanMan (LM)", summary)
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
        hash_only_summary = executive_summary(hash_only)
        self.assertIn("Password reuse could allow a compromised credential",
                      hash_only_summary)
        self.assertNotIn("Recovered passwords contained predictable patterns", hash_only_summary)

    def test_executive_summary_pairs_present_findings_with_impacts(self):
        results = build_results(
            ntlm_mapped_passwords=[], domain_admins=[], company_words=[],
            minimum_length=14, enabled_users=["alice"], domain_name="example.test",
            lm_users=[], lm_mapped_passwords=[],
            privileged_users={"status": "available", "warnings": [], "accounts": []},
            ntds_users=[],
        )
        cases = [
            ("admins", "count", "Privileged account credentials were recovered",
             "providing access to critical systems"),
            ("lm_hashes", "count", "Legacy LanMan (LM) password hashes were present",
             "susceptible to offline password cracking"),
            ("hibp", "count", "Some account password hashes matched known breach data",
             "their passwords may be easier to guess"),
            ("password_length", "count", "Some recovered passwords were shorter",
             "potentially making them easier to crack"),
            ("keyboard_walks", "count", "Recovered passwords contained predictable patterns",
             "reducing the effort required to compromise accounts"),
        ]
        results["hibp"] = {"count": 0}
        for key, field, finding, impact in cases:
            with self.subTest(finding=key):
                selected = deepcopy(results)
                selected[key][field] = 1
                paragraphs = executive_summary(selected).split("\n\n")
                self.assertEqual(len(paragraphs), 3)
                self.assertIn(finding, paragraphs[1])
                self.assertIn(impact, paragraphs[1])
                for other_key, _, other_finding, _ in cases:
                    if key != other_key:
                        self.assertNotIn(other_finding, paragraphs[1])

        selected = deepcopy(results)
        selected["lm_hashes"]["count"] = 1
        selected["lm_passwords"]["count"] = 1
        selected["lm_admins"]["count"] = 1
        selected["admins"]["count"] = 1
        selected["keyboard_walks"]["count"] = 1
        selected["ntlm_hash_reuse"]["groups"] = [{"accounts": []}]
        selected["similar_account_reuse"]["count"] = 1
        paragraph = executive_summary(selected).split("\n\n")[1]
        self.assertIn("Privileged account credentials were recovered", paragraph)
        self.assertIn("Passwords were recovered from accounts storing LM hashes.", paragraph)
        self.assertIn("LM passwords were recovered for Domain Administrator accounts", paragraph)
        self.assertIn("Reuse between related accounts", paragraph)
        self.assertIn("Recovered passwords contained predictable patterns", paragraph)

        selected["lm_hashes"]["count"] = 0
        paragraph = executive_summary(selected).split("\n\n")[1]
        self.assertIn("Legacy LanMan (LM) password hashes were present", paragraph)
        self.assertIn("LM passwords were recovered for Domain Administrator accounts", paragraph)

    def test_account_tables_omit_prefixes_without_changing_results(self):
        account = {"username": "EXAMPLE\\Ali|ce", "password": "Password123!",
                   "groups": ["Backup Operators (example.test)", "Custom Group (regional)"],
                   "shared_with": "OTHER\\Bob"}
        sections = [
            (commentary_admins, {"admins": {"accounts": [account], "count": 1},
                                 "privileged_users": {"accounts": [account]}}),
            (commentary_privileged_users, {"admins": {"accounts": []}, "privileged_users": {
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
                if function is commentary_privileged_users:
                    self.assertIn("Backup Operators, Custom Group (regional)", text)
                    self.assertNotIn("example.test", text)
                if function is commentary_similar_account_reuse:
                    self.assertIn("| Bob |", text)
                    self.assertNotIn("OTHER\\", text)
        self.assertEqual(account["username"], "EXAMPLE\\Ali|ce")
        self.assertEqual(account["shared_with"], "OTHER\\Bob")

    def test_pattern_commentary_uses_correct_singular_and_plural(self):
        account = {"username": "alice", "password": "Password1", "shared_with": "alice_adm"}
        for count, phrase in ((1, "one recovered password contained"),
                              (2, "two recovered passwords contained")):
            for function, key in (
                (commentary_username_passwords, "username_passwords"),
                (commentary_common_passwords, "common_passwords"),
                (commentary_date_passwords, "date_passwords"),
                (commentary_keyboard_walks, "keyboard_walks"),
            ):
                with self.subTest(count=count, section=key):
                    text = function({key: {"accounts": [account], "count": count, "stats": []}})
                    self.assertIn(phrase, text)
                    self.assertNotIn("identified", text)
            reuse = commentary_similar_account_reuse({"similar_account_reuse": {
                "accounts": [account], "count": count, "similarPairs": count,
            }})
            self.assertIn("one account pair shared" if count == 1
                          else "two account pairs shared", reuse)

    def test_domain_and_enterprise_admins_are_not_repeated_in_privileged_table(self):
        admins = [{"username": "EXAMPLE\\Cotton.Adm", "password": "Password123!"}]
        privileged = {
            "status": "incomplete", "warnings": ["Some group members were not resolved."],
            "count": 4,
            "accounts": [
                {"username": "example\\cotton.adm", "password": "Password123!",
                 "groups": ["Administrators (example.test)", "Domain Admins (example.test)",
                            "Schema Admins (example.test)"]},
                {"username": "EXAMPLE\\enterprise", "password": "Password456!",
                 "groups": ["Enterprise Admins (example.test)", "Backup Operators (example.test)"]},
                {"username": "EXAMPLE\\operator", "password": "Password789!",
                 "groups": ["Backup Operators (example.test)"]},
                {"username": "OTHER\\Cotton.Adm", "password": "OtherPassword!",
                 "groups": ["Server Operators (other.test)"]},
            ],
        }
        results = {"admins": {"accounts": admins, "count": 1}, "privileged_users": privileged}
        high = commentary_admins(results)
        other = commentary_privileged_users(results)
        self.assertIn("two Domain or Enterprise Administrator accounts", high)
        self.assertIn("| Cotton.Adm | Administrators, Domain Admins, Schema Admins |", high)
        self.assertIn("| enterprise | Enterprise Admins, Backup Operators |", high)
        self.assertNotIn("| operator |", high)
        self.assertIn("two other accounts", other)
        self.assertIn("| operator | Backup Operators |", other)
        self.assertIn("| Cotton.Adm | Server Operators |", other)
        self.assertNotIn("| enterprise |", other)
        self.assertNotIn("Domain Admins", other)
        self.assertNotIn("example.test", high)

    def test_da_without_verified_group_membership_is_labelled_as_name_match(self):
        results = {
            "admins": {"accounts": [{"username": "EXAMPLE\\admin", "password": "Password123!"}]},
            "privileged_users": {"accounts": []},
        }
        text = commentary_admins(results)
        self.assertIn("| admin | Domain Admins (name match only) |", text)

    def test_enterprise_admin_only_and_overlapping_groups(self):
        account = {"username": "EXAMPLE\\admin", "password": "Password123!",
                   "groups": ["Enterprise Admins (example.test)"]}
        results = {"admins": {"accounts": []}, "privileged_users": {
            "status": "incomplete", "warnings": ["Some members were not resolved."],
            "accounts": [account],
        }}
        self.assertIn("one Enterprise Administrator account had a password", commentary_admins(results))
        other = commentary_privileged_users(results)
        self.assertIn(
            "Privileged group coverage is incomplete: Some members were not resolved. "
            "Some affected accounts may be missing. "
            "Group memberships include nested membership",
            other,
        )
        self.assertNotIn("| Username |", other)
        account["groups"].append("Domain Admins (example.test)")
        text = commentary_admins(results)
        self.assertIn("one Domain or Enterprise Administrator account had a password", text)
        self.assertEqual(text.count("| admin |"), 1)

    def test_domain_admin_and_other_privileged_findings_do_not_overlap(self):
        da = {"username": "EXAMPLE\\admin", "groups": [
            "Domain Admins (example.test)", "Administrators (example.test)",
        ]}
        enterprise = {"username": "EXAMPLE\\enterprise", "groups": ["Enterprise Admins"]}
        operator = {"username": "EXAMPLE\\operator", "groups": ["Backup Operators"]}
        other_admin_name = {"username": "OTHER\\admin", "groups": ["Backup Operators"]}
        cases = [
            ([da], ["admin"], "one", None),
            ([da, enterprise, operator], ["admin"], "one", "two"),
            ([da, other_admin_name, enterprise], [], "one", "two"),
            ([enterprise], [], None, "one"),
        ]
        for accounts, legacy_admins, expected_da, expected_other in cases:
            with self.subTest(accounts=accounts, legacy_admins=legacy_admins):
                mapped = [{"username": a["username"], "password": "Password123!"}
                          for a in accounts]
                results = build_results(
                    ntlm_mapped_passwords=mapped + mapped[:1],
                    domain_admins=legacy_admins, company_words=[], minimum_length=14,
                    enabled_users=[a["username"] for a in accounts],
                    domain_name="example.test", lm_users=[], lm_mapped_passwords=[],
                    privileged_users={"status": "available", "warnings": [], "accounts": accounts},
                    ntds_users=[],
                )
                findings = {f["id"]: f for f in build_findings_dict(results)}
                for finding_id, expected in (
                    ("DOMAIN-ADMIN-001", expected_da),
                    ("PRIV-ACCOUNT-001", expected_other),
                ):
                    if expected is None:
                        self.assertNotIn(finding_id, findings)
                    else:
                        self.assertIn(f"A total of {expected} ", findings[finding_id]["description"])
                if expected_da:
                    self.assertNotIn("no recovered Domain Administrator passwords",
                                     executive_summary(results))
                self.assertEqual(len(results["privileged_users"]["accounts"]), len(accounts))

        legacy_only = build_results(
            ntlm_mapped_passwords=[{"username": "EXAMPLE\\admin", "password": "Password123!"}],
            domain_admins=["admin"], company_words=[], minimum_length=14,
            enabled_users=["EXAMPLE\\admin"], domain_name="example.test",
            lm_users=[], lm_mapped_passwords=[], ntds_users=[],
        )
        ids = {finding["id"] for finding in build_findings_dict(legacy_only)}
        self.assertIn("DOMAIN-ADMIN-001", ids)
        self.assertNotIn("PRIV-ACCOUNT-001", ids)

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
        self.assertLess(text.index("Passwords were reused"),
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
                    "status": "available",
                    "accounts": [{"username": "EXAMPLE\\alice",
                                  "groups": ["Domain Admins", "Backup Operators"]}],
                    "warnings": [],
                }), encoding="utf-8")
                with patch.object(sys, "argv", args):
                    cli_main.main()
                findings = json.loads((root / "password-audit-findings.json").read_text())
                ids = {finding["id"] for finding in findings["findings"]}
                self.assertIn("DOMAIN-ADMIN-001", ids)
                self.assertNotIn("PRIV-ACCOUNT-001", ids)
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
                hibp=directory,
            )

            analysis_args = values["analyse_passwords"].call_args.kwargs
            self.assertTrue(analysis_args["csacyber"])
            self.assertEqual(analysis_args["hibp"], directory)
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
