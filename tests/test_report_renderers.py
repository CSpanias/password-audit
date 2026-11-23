import io
import json
import os
import re
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout
from copy import deepcopy
from itertools import combinations
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
from analysis.parsers import load_ntds_users, load_passwords
from analysis.analysis import ntlm_hash_reuse, similar_account_reuse, similar_account_hash_reuse
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
    commentary_lm_hashes,
    commentary_ntlm_hash_reuse,
    commentary_password_lengths,
    commentary_password_reuse,
    commentary_privileged_users,
    commentary_similar_account_reuse,
    commentary_username_passwords,
    technical_commentary,
)
from common.utils import username_base

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
        self.assertIn('id="ntlm-recovery"', html)
        self.assertIn('id="lm-recovery"', html)
        self.assertLess(html.index('id="ntlm-recovery"'), html.index('id="lm-recovery"'))
        self.assertIn('id="audit-summary"', html)
        self.assertNotIn("Findings at a glance", html)
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
        categories = {finding["id"]: finding["category"] for finding in findings}
        self.assertEqual(categories["PWD-BREACH-001"], "breached_passwords")
        self.assertEqual(categories["PWD-REUSE-001"], "password_reuse")
        cards = {card["id"]: card for card in build_finding_summary(results, findings)}
        self.assertEqual((cards["PWD-BREACH-001"]["count"], cards["PWD-BREACH-001"]["unit"]),
                         (2, "accounts"))
        self.assertEqual(cards["PWD-BREACH-001"]["label"], "Breached")
        self.assertEqual((cards["PWD-REUSE-001"]["count"], cards["PWD-REUSE-001"]["unit"]),
                         (1, "unique passwords"))
        self.assertEqual((cards["PWD-REUSE-002"]["count"], cards["PWD-REUSE-002"]["unit"]),
                         (1, "account pairs"))
        self.assertEqual((cards["PWD-REUSE-003"]["count"], cards["PWD-REUSE-003"]["unit"]),
                         (1, "shared credential groups"))
        self.assertEqual(set(cards), {
            finding["id"] for finding in findings
            if finding["id"] not in {"PWD-AUDIT-001", "PWD-STATS-001", "LM-AUTH-001"}
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
        self.assertEqual(len(cards), 13)
        self.assertEqual(
            {card["id"] for card in cards},
            {finding["id"] for finding in findings}
            - {"PWD-AUDIT-001", "PWD-STATS-001", "LM-AUTH-001"},
        )
        self.assertTrue(all(card["count"] == 1 and card["unit"] for card in cards))
        self.assertTrue(all(card["label"] and "password" not in card["label"].lower()
                            for card in cards))

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
                "label": "Breached", "count": 2, "unit": "accounts",
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
            mocks["executive_summary"].assert_called_once_with(
                mocks["build_results"].return_value, REPORT["findings"]
            )
            mocks["technical_commentary"].assert_called_once_with(
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
                write_sureformat(path, "EXAMPLE.TEST", findings)
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

    def test_hash_reuse_caps_each_account_list_but_keeps_full_finding(self):
        admins = [f"EXAMPLE\\admin{i:03}" for i in range(6)]
        others = [f"EXAMPLE\\other{i:03}" for i in range(7)]
        users = [f"EXAMPLE\\user{i:03}" for i in range(110)]
        boundary = [f"EXAMPLE\\boundary{i:03}" for i in range(5)]
        ntds_users = [
            {"username": username, "ntlm": ntlm * 32}
            for names, ntlm in ((admins + others, "a"), (users, "b"), (boundary, "c"))
            for username in names
        ]
        results = build_results(
            ntlm_mapped_passwords=[], domain_admins=[], company_words=[],
            minimum_length=12, enabled_users=[item["username"] for item in ntds_users],
            domain_name="example.test", lm_users=[], lm_mapped_passwords=[],
            privileged_users={
                "status": "available", "warnings": [],
                "accounts": [{"username": username, "groups": ["Domain Admins (example.test)"]}
                             for username in admins],
            },
            ntds_users=ntds_users,
        )
        text = commentary_ntlm_hash_reuse(results)
        privileged_row = next(line for line in text.splitlines() if line.startswith("| aa"))
        user_row = next(line for line in text.splitlines() if line.startswith("| bb"))
        boundary_row = next(line for line in text.splitlines() if line.startswith("| cc"))
        self.assertIn(
            "; ".join(f"admin{i:03} (Domain Admins)" for i in range(5)) + "; +1 more",
            privileged_row,
        )
        self.assertIn(", ".join(f"other{i:03}" for i in range(5)) + ", +2 more",
                      privileged_row)
        self.assertNotIn("admin005", privileged_row)
        self.assertNotIn("other005", privileged_row)
        self.assertIn(", ".join(f"user{i:03}" for i in range(5)) + ", +105 more", user_row)
        self.assertNotIn("user005", user_row)
        self.assertIn(", ".join(f"boundary{i:03}" for i in range(5)), boundary_row)
        self.assertNotIn("more", boundary_row)
        self.assertIn("across 128 enabled user accounts", text)

        finding = next(
            item for item in build_findings_dict(results) if item["id"] == "PWD-REUSE-003"
        )
        self.assertEqual(len(finding["affected_assets"]), 128)
        self.assertIn("EXAMPLE\\admin005", finding["affected_assets"])
        self.assertIn("EXAMPLE\\user109", finding["affected_assets"])
        self.assertTrue(any("EXAMPLE\\user109" in entry for entry in finding["evidence"]))

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
                                "failures": [
                                    {"username": f"user{i}", "password": "Secret" + str(i), "length": length}
                                    for i, length in enumerate((10, 10, 10, 11, 11, 11))
                                ]},
            "password_lengths": {"lengths": [(15, 5), (10, 3), (11, 3)]},
        })
        self.assertIn("lengths were 10 and 11 characters", text)
        self.assertIn("Fine-grained policies or earlier policy changes", text)
        self.assertIn("| Username | Password |", text)
        self.assertNotIn("Secret0", text)
        self.assertIn("| user4 |", text)
        self.assertNotIn("| user5 |", text)
        text = commentary_password_lengths({
            "password_length": {"minimum_length": 14, "count": 1, "percentage": 10,
                                "failures": [{"username": "user", "password": "Secret1234", "length": 10}]},
            "password_lengths": {"lengths": [(15, 5), (10, 1)]},
        })
        self.assertIn("found one password (10% of", text)
        self.assertIn("password length was 10 characters", text)

    def test_unavailable_password_policy_is_not_reported_as_compliant(self):
        results = build_results(
            ntlm_mapped_passwords=[{"username": "alice", "password": "short"}],
            domain_admins=[], company_words=[], minimum_length=None,
            enabled_users=["alice"], domain_name=None,
            lm_users=[], lm_mapped_passwords=[], ntds_users=None,
        )
        self.assertEqual(results["password_length"]["status"], "unavailable")
        self.assertIsNone(results["password_length"]["count"])
        self.assertIsNone(results["password_length"]["percentage"])
        self.assertEqual(results["password_lengths"]["lengths"], [(5, 1)])
        self.assertNotIn("PWD-POLICY-001", {
            finding["id"] for finding in build_findings_dict(results)
        })
        summary = executive_summary(results)
        self.assertIn("against the assessed domain", summary)
        self.assertIn("Password length compliance could not be assessed", summary)
        self.assertNotIn("positive observation", summary)
        self.assertIn("Password length compliance could not be assessed",
                      technical_commentary(results))

    def test_executive_summary_combines_introduction_and_scales_positive_observations(self):
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
        results["password_reuse_general"]["sharedPasswords"] = 1
        results["ntlm_hash_reuse"]["status"] = "available"
        results["ntlm_hash_reuse"]["groups"] = []
        results["password_length"]["count"] = 1
        results["similar_account_reuse"]["similarPairs"] = 1
        results["similar_account_reuse"]["count"] = 1
        summary = executive_summary(results)
        introduction = summary.split("\n\n")[0]
        self.assertNotIn("positive observation", introduction)
        self.assertIn("The assessment demonstrated", introduction)
        self.assertNotIn("simulated the activities", introduction)

        for finding in ("admins", "reuse", "length", "similar"):
            with self.subTest(finding=finding):
                positive_results = deepcopy(results)
                if finding == "admins":
                    positive_results["admins"]["count"] = 0
                elif finding == "reuse":
                    positive_results["password_reuse_general"]["sharedPasswords"] = 0
                elif finding == "length":
                    positive_results["password_length"]["count"] = 0
                else:
                    positive_results["similar_account_reuse"]["count"] = 0
                introduction = executive_summary(positive_results).split("\n\n")[0]
                self.assertIn("While the assessment yielded some positive observations", introduction)
                self.assertIn("could be recovered through offline password cracking", introduction)

        incomplete = deepcopy(results)
        incomplete["admins"]["count"] = 0
        incomplete["privileged_users"]["status"] = "incomplete"
        self.assertNotIn("positive observation", executive_summary(incomplete))

        unavailable = deepcopy(results)
        unavailable["password_reuse_general"]["sharedPasswords"] = 0
        unavailable["ntlm_hash_reuse"]["status"] = "unavailable"
        self.assertNotIn("positive observation", executive_summary(unavailable))
        recovered_privileged = deepcopy(results)
        recovered_privileged["admins"]["count"] = 0
        recovered_privileged["privileged_users"]["count"] = 1
        self.assertNotIn("positive observation", executive_summary(recovered_privileged))
        recovered_privileged["privileged_users"]["count"] = 0
        recovered_privileged["privileged_users"]["lm_recovered_count"] = 1
        self.assertNotIn("positive observation", executive_summary(recovered_privileged))
        recovered_privileged["privileged_users"]["lm_recovered_count"] = 0
        recovered_privileged["lm_admins"]["count"] = 1
        self.assertNotIn("positive observation", executive_summary(recovered_privileged))

        positive_results = deepcopy(results)
        positive_results["admins"]["count"] = 0
        positive_results["password_length"]["count"] = 0
        self.assertIn("some positive observations", executive_summary(positive_results))
        positive_results["password_reuse_general"]["sharedPasswords"] = 0
        positive_results["similar_account_reuse"]["count"] = 0
        self.assertIn("many positive observations", executive_summary(positive_results))

        positive_results["enabled_users"] = 0
        introduction = executive_summary(positive_results).split("\n\n")[0]
        self.assertIn("passwords could be recovered", introduction)
        self.assertNotIn("subset of user credentials", introduction)

        results["total_passwords"] = 0
        summary = executive_summary(results)
        self.assertNotIn("positive observation", summary)
        self.assertIn("No plaintext passwords were recovered", summary.split("\n\n")[0])
        self.assertEqual(summary.count("No plaintext passwords were recovered"), 1)

    def test_recovery_rate_wording_matches_in_summary_and_commentary(self):
        results = build_results(
            ntlm_mapped_passwords=[{"username": "alice", "password": "weak"}],
            domain_admins=[], company_words=[], minimum_length=14,
            enabled_users=["alice"], domain_name="example.test",
            lm_users=[], lm_mapped_passwords=[],
        )
        cases = (
            (0.1, "a small subset", "a limited number of"),
            (4.9, "a small subset", "a limited number of"),
            (5.0, "a subset", "some"),
            (14.9, "a subset", "some"),
            (15.0, "a substantial subset", "a notable proportion of"),
            (29.9, "a substantial subset", "a notable proportion of"),
            (30.0, "a significant subset", "a significant proportion of"),
            (100.0, "a significant subset", "a significant proportion of"),
        )
        for rate, subset, impact in cases:
            with self.subTest(rate=rate):
                results["total_passwords"] = round(rate * 10)
                results["enabled_users"] = 1000
                results["crack_rate"] = rate
                summary = executive_summary(results, []).split("\n\n")[0]
                commentary = technical_commentary(results, []).split("\n\n")[1]
                self.assertIn(f"{subset} of user credentials", summary)
                self.assertIn(f"{impact} passwords remain susceptible", summary)
                self.assertIn(f"{impact} user credentials remain susceptible", commentary)

        results["total_passwords"] = 0
        results["crack_rate"] = 0
        summary = executive_summary(results, []).split("\n\n")[0]
        commentary = technical_commentary(results, []).split("\n\n")[1]
        self.assertIn("No plaintext passwords were recovered", summary)
        self.assertIn("Password composition could not be assessed", commentary)
        self.assertNotIn("remain susceptible", commentary)

        results["enabled_users"] = 0
        for total in (0, 1):
            with self.subTest(enabled_users=0, total_passwords=total):
                results["total_passwords"] = total
                summary = executive_summary(results, []).split("\n\n")[0]
                commentary = technical_commentary(results, []).split("\n\n")[1]
                self.assertNotIn("subset of user credentials", summary)
                self.assertIn("No enabled user accounts were available to calculate a recovery rate", commentary)
                self.assertNotIn("% of the assessed population", commentary)
                self.assertNotIn("user credentials remain susceptible", commentary)

    def test_commentary_groups_recovered_password_analysis_with_readability(self):
        results = build_results(
            ntlm_mapped_passwords=[{"username": "alice", "password": "weak"}],
            domain_admins=[], company_words=[], minimum_length=14,
            enabled_users=["alice"], domain_name="example.test",
            lm_users=[], lm_mapped_passwords=[],
        )
        results.update(total_passwords=49, enabled_users=320, crack_rate=15.3)
        paragraphs = technical_commentary(results, []).split("\n\n")
        self.assertEqual(
            paragraphs[1],
            "Through password-cracking techniques, it was possible to recover 49 plaintext "
            "passwords from 320 enabled user accounts, representing approximately 15.3% of the "
            "assessed population. This demonstrates that a notable proportion of user credentials "
            "remain susceptible to password-cracking attacks following credential exposure.",
        )
        self.assertEqual(
            paragraphs[2],
            "The recovered passwords were subsequently analysed for common password selection "
            "patterns, password length, and other indicators of weak password hygiene. To maintain "
            "report readability, example findings have been included throughout this section. "
            "Unless otherwise stated, tables are intended to provide representative samples and may "
            "not contain all affected accounts found during the assessment.",
        )
        results["total_passwords"] = 0
        commentary = technical_commentary(results, [])
        self.assertNotIn("The recovered passwords were subsequently analysed", commentary)
        self.assertIn("\n\nTo maintain report readability", commentary)

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
        self.assertIn(
            "Password reuse could allow a compromised "
            "credential to affect multiple accounts",
            summary,
        )
        self.assertIn("multiple accounts or systems.", summary)
        self.assertNotIn("undermine separation", summary)
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
        self.assertIn("Password reuse could allow a "
                      "compromised credential", hash_only_summary)
        self.assertNotIn("passwords followed predictable patterns",
                         hash_only_summary)

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
             "expose critical systems"),
            ("lm_hashes", "count", "Legacy LanMan (LM) password hashes were present",
             "susceptible to offline password cracking"),
            ("hibp", "count", "Some passwords matched known breach data",
             "affected accounts at greater risk of compromise"),
            ("password_length", "count", "Some recovered passwords fell below",
             "easier to guess or crack"),
            ("keyboard_walks", "count", "Some recovered passwords followed predictable patterns",
             "affected accounts at greater risk of compromise"),
        ]
        results["hibp"] = {"count": 0, "accounts": []}
        for key, field, finding, impact in cases:
            with self.subTest(finding=key):
                selected = deepcopy(results)
                selected[key][field] = 1
                paragraphs = executive_summary(selected).split("\n\n")
                self.assertEqual(len(paragraphs), 3)
                self.assertTrue(paragraphs[1].startswith(
                    "The assessment also highlighted weaknesses that could increase "
                    "the risk of credential compromise. "
                ))
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
        selected["hibp"]["count"] = 1
        selected["password_length"]["count"] = 1
        selected["ntlm_hash_reuse"]["groups"] = [{"accounts": []}]
        selected["similar_account_reuse"]["count"] = 1
        paragraph = executive_summary(selected).split("\n\n")[1]
        self.assertIn("Privileged account credentials were recovered", paragraph)
        self.assertIn(
            "passwords recovered from accounts storing them",
            paragraph,
        )
        self.assertIn("including for Domain Administrator accounts", paragraph)
        self.assertIn("multiple accounts or systems and may undermine "
                      "separation between accounts with different roles", paragraph)
        self.assertIn("passwords matching known breach data and passwords with "
                      "predictable patterns", paragraph.lower())
        self.assertIn("some recovered passwords fell below", paragraph.lower())
        self.assertIn("In addition, legacy LanMan", paragraph)
        self.assertIn("Finally, some recovered passwords", paragraph)
        self.assertEqual(paragraph.count("The assessment"), 1)
        self.assertNotIn("Moreover", paragraph)
        self.assertNotIn("Some passwords matched known breach data", paragraph)
        self.assertNotIn("Some recovered passwords followed predictable patterns", paragraph)

        selected["lm_hashes"]["count"] = 0
        paragraph = executive_summary(selected).split("\n\n")[1]
        self.assertIn("legacy lanman (lm) password hashes were present", paragraph.lower())
        self.assertIn("including for Domain Administrator accounts", paragraph)

    def test_executive_summary_transitions_follow_present_findings(self):
        results = build_results(
            ntlm_mapped_passwords=[], domain_admins=[], company_words=[],
            minimum_length=14, enabled_users=["alice"], domain_name="example.test",
            lm_users=[], lm_mapped_passwords=[], ntds_users=[],
        )
        results["hibp"] = {"count": 0, "accounts": []}
        cases = [
            ("lm_hashes", "count", "legacy lanman (lm) password hashes"),
            ("password_reuse_general", "sharedPasswords", "password reuse could"),
            ("hibp", "count", "passwords matched known breach data"),
            ("password_length", "count", "recovered passwords fell below"),
        ]
        findings_data = [
            {"id": finding_id, "severity": severity}
            for finding_id, severity in (
                ("LM-AUTH-001", "high"), ("PWD-REUSE-001", "high"),
                ("PWD-BREACH-001", "high"), ("PWD-POLICY-001", "medium"),
            )
        ]
        for size in range(1, len(cases) + 1):
            for chosen in combinations(cases, size):
                with self.subTest(findings=[case[0] for case in chosen]):
                    selected = deepcopy(results)
                    for key, field, _ in chosen:
                        selected[key][field] = 1
                    paragraph = executive_summary(selected, findings_data).split("\n\n")[1]
                    self.assertEqual(paragraph.count("The assessment"), 1)
                    self.assertLessEqual(paragraph.lower().count("potentially"), 1)
                    self.assertEqual(paragraph.count("In addition,"), int(size > 1))
                    self.assertEqual(paragraph.count("Finally,"), int(size > 2))
                    positions = [paragraph.lower().index(marker) for _, _, marker in chosen]
                    self.assertEqual(positions, sorted(positions))
                    for case in cases:
                        if case not in chosen:
                            self.assertNotIn(case[2], paragraph.lower())

    def test_executive_summary_flows_for_combined_findings(self):
        results = build_results(
            ntlm_mapped_passwords=[], domain_admins=[], company_words=[],
            minimum_length=14, enabled_users=["alice"], domain_name="example.test",
            lm_users=[], lm_mapped_passwords=[], ntds_users=[],
        )
        results["lm_hashes"]["count"] = 1
        results["lm_passwords"]["count"] = 1
        results["password_reuse_general"]["sharedPasswords"] = 1
        results["similar_account_reuse"]["count"] = 1
        results["hibp"] = {"count": 1, "accounts": []}
        results["keyboard_walks"]["count"] = 1
        results["password_length"]["count"] = 1
        paragraph = executive_summary(results).split("\n\n")[1]
        self.assertEqual(
            paragraph,
            "The assessment also highlighted weaknesses that could increase the risk of "
            "credential compromise. Legacy LanMan (LM) password hashes were present, "
            "making credentials more susceptible to offline password cracking, as "
            "demonstrated by passwords recovered from accounts storing them. In addition, "
            "password reuse could allow a compromised credential to affect multiple accounts "
            "or systems and may undermine separation between accounts with different "
            "roles. Passwords matching known breach data and passwords with predictable "
            "patterns were identified, placing affected accounts at greater risk of "
            "compromise. Finally, some recovered passwords fell below the domain's configured "
            "minimum length and may be easier to guess or crack.",
        )

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

    def test_password_reuse_examples_limit_displayed_accounts(self):
        accounts = [
            {"username": f"EXAMPLE\\user|{i}", "password": "P|ssword1"}
            for i in range(7)
        ]
        accounts.extend(
            {"username": f"EXAMPLE\\group{group}user{index}",
             "password": f"Shared{group}!"}
            for group in range(5) for index in range(2)
        )
        accounts.append({"username": "EXAMPLE\\different", "password": "p|ssword1"})
        results = build_results(
            ntlm_mapped_passwords=accounts, domain_admins=[], company_words=[],
            minimum_length=12, enabled_users=[a["username"] for a in accounts],
            domain_name="example.test", lm_users=[], lm_mapped_passwords=[], ntds_users=[],
        )
        text = commentary_password_reuse(results)
        expected_accounts = ", ".join(f"user\\|{i}" for i in range(5)) + ", +2 more"
        self.assertIn("| Password | Times Seen | Percentage | Accounts |", text)
        self.assertIn(f"| P\\|*****d1 | 7 | 38.9% | {expected_accounts} |", text)
        self.assertNotIn("user\\|5", text)
        self.assertEqual(len(results["password_reuse_general"]["example_accounts"]["P|ssword1"]), 7)
        self.assertNotIn("different", text)
        self.assertNotIn("group4user0", text)
        self.assertNotIn("EXAMPLE\\", text)
        self.assertEqual(len(results["password_reuse_general"]["example_accounts"]), 5)

        no_reuse = build_results(
            ntlm_mapped_passwords=accounts[-1:], domain_admins=[], company_words=[],
            minimum_length=12, enabled_users=["EXAMPLE\\different"],
            domain_name="example.test", lm_users=[], lm_mapped_passwords=[], ntds_users=[],
        )
        self.assertEqual(commentary_password_reuse(no_reuse), "")

    def test_password_reuse_reports_omitted_account_count(self):
        accounts = [
            {"username": f"EXAMPLE\\user{i:03}", "password": "shared"}
            for i in range(110)
        ]
        results = build_results(
            ntlm_mapped_passwords=accounts, domain_admins=[], company_words=[],
            minimum_length=12, enabled_users=[account["username"] for account in accounts],
            domain_name="example.test", lm_users=[], lm_mapped_passwords=[], ntds_users=[],
        )
        text = commentary_password_reuse(results)
        self.assertIn("| 110 | 100.0% | user000, user001, user002, user003, user004, +105 more |",
                      text)
        self.assertNotIn("user005", text)
        self.assertEqual(len(results["password_reuse_general"]["example_accounts"]["shared"]), 110)

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
            self.assertIn("one account pair with similar names" if count == 1
                          else "two account pairs with similar names", reuse)

    def test_similar_account_reuse_includes_unrecovered_hashes_without_duplicates(self):
        names = ["training05", "training1", "training2", "training3", "training4"]
        hash_value = "ABCDEF0123456789ABCDEF0123456789"
        ntds_users = [
            {"username": f"EXAMPLE\\{name}", "ntlm": hash_value}
            for name in names
        ] + [
            {"username": "EXAMPLE\\other", "ntlm": hash_value},
            {"username": "EXAMPLE\\training6", "ntlm": "0" * 32},
        ]
        kwargs = dict(
            domain_admins=[], company_words=[], minimum_length=12,
            enabled_users=[account["username"] for account in ntds_users],
            domain_name="example.test", lm_users=[], lm_mapped_passwords=[],
        )
        hash_only = build_results(ntlm_mapped_passwords=[], ntds_users=ntds_users, **kwargs)
        finding = hash_only["similar_account_reuse"]
        self.assertEqual(finding["count"], 10)
        self.assertTrue(all("masked_hash" in account for account in finding["accounts"]))
        text = commentary_similar_account_reuse(hash_only)
        self.assertIn("Matching NTLM hash examples:", text)
        self.assertIn("ab****************************89", text)
        self.assertIn("Similar names do not establish", text)
        self.assertNotIn(hash_value, text)
        self.assertNotIn("| other |", text)
        self.assertNotIn("training6", text)
        exported = next(f for f in build_findings_dict(hash_only) if f["id"] == "PWD-REUSE-002")
        self.assertIn("10 similarly named account pairs", exported["description"])
        self.assertIn("matching NTLM hashes", exported["description"])
        self.assertNotIn(hash_value, json.dumps(exported))
        cards = {card["id"]: card for card in build_finding_summary(
            hash_only, build_findings_dict(hash_only)
        )}
        self.assertEqual(cards["PWD-REUSE-002"]["count"], 10)

        recovered = [
            {"username": "example\\TRAINING1", "password": "Secret123"},
            {"username": "example\\training05", "password": "Secret123"},
        ]
        combined = build_results(ntlm_mapped_passwords=recovered, ntds_users=ntds_users, **kwargs)
        self.assertEqual(combined["similar_account_reuse"]["count"], 10)
        text = commentary_similar_account_reuse(combined)
        self.assertIn("Recovered password examples:", text)
        self.assertIn("Matching NTLM hash examples:", text)
        self.assertNotIn("Secret123", text)
        without_hashes = build_results(ntlm_mapped_passwords=recovered, ntds_users=None, **kwargs)
        self.assertEqual(without_hashes["similar_account_reuse"]["count"], 1)
        self.assertNotIn("Matching NTLM hash examples:",
                         commentary_similar_account_reuse(without_hashes))

    def test_large_similar_hash_group_counts_all_pairs_with_bounded_examples(self):
        users = [
            {"username": f"training{i}", "ntlm": "a" * 32}
            for i in range(2000)
        ]
        results = build_results(
            ntlm_mapped_passwords=[], domain_admins=[], company_words=[],
            minimum_length=12, enabled_users=[user["username"] for user in users],
            domain_name="example.test", lm_users=[], lm_mapped_passwords=[],
            ntds_users=users,
        )
        self.assertEqual(results["similar_account_reuse"]["count"], 1_999_000)
        self.assertEqual(len(results["similar_account_reuse"]["accounts"]), 5)

    def test_similar_account_grouping_matches_pairwise_counts(self):
        recovered = [
            {"username": "A\\sam1", "password": "one"},
            {"username": "A\\sam2", "password": "one"},
            {"username": "B\\sam3", "password": "two"},
            {"username": "A\\sam4", "password": "one"},
            {"username": "A\\sam5", "password": "two"},
            {"username": "A\\other", "password": "one"},
        ]
        pairs = [(a, b) for a, b in combinations(recovered, 2)
                 if username_base(a["username"]) == username_base(b["username"])]
        shared = [(a, b) for a, b in pairs if a["password"] == b["password"]]
        examples, comparable, count = similar_account_reuse(recovered)
        self.assertEqual(comparable, len(pairs))
        self.assertEqual(count, len(shared))
        self.assertEqual([(x["username"], x["shared_with"]) for x in examples],
                         [(a["username"], b["username"]) for a, b in shared[:5]])

        groups = [{"masked_hash": "masked", "accounts": [
            {"username": name} for name in
            ("a\\SAM1", "a\\sam2", "B\\sam3", "A\\sam6", "A\\other")
        ]}]
        recovered_pairs = {frozenset((a["username"].casefold(), b["username"].casefold()))
                           for a, b in shared}
        hash_pairs = [(a["username"], b["username"])
                      for a, b in combinations(groups[0]["accounts"], 2)
                      if username_base(a["username"]) == username_base(b["username"])
                      and frozenset((a["username"].casefold(), b["username"].casefold()))
                      not in recovered_pairs]
        hash_examples, hash_count = similar_account_hash_reuse(groups, recovered, 5)
        self.assertEqual(hash_count, len(hash_pairs))
        self.assertEqual([(x["username"], x["shared_with"]) for x in hash_examples], hash_pairs[:5])

    def test_large_recovered_group_counts_pairs_without_materialising_them(self):
        records = [{"username": f"user{i}", "password": "shared"} for i in range(5000)]
        examples, comparable, count = similar_account_reuse(records)
        self.assertEqual(comparable, 12_497_500)
        self.assertEqual(count, comparable)
        self.assertEqual(len(examples), 5)
        groups = [{"masked_hash": "masked", "accounts": records}]
        hash_examples, hash_count = similar_account_hash_reuse(groups, records, 5)
        self.assertEqual((hash_examples, hash_count), ([], 0))

    def test_recovered_account_validation_and_full_identity_deduplication(self):
        kwargs = dict(domain_admins=[], company_words=[], minimum_length=8,
                      enabled_users=["A\\sam", "B\\sam", "a\\SAM"],
                      domain_name="example.test", lm_users=[], lm_mapped_passwords=[])
        records = [{"username": "A\\sam", "password": "same"},
                   {"username": "a\\SAM", "password": "same"},
                   {"username": "B\\sam", "password": "other"}]
        results = build_results(ntlm_mapped_passwords=records, **kwargs)
        self.assertEqual((results["total_passwords"], results["enabled_users"], results["crack_rate"]),
                         (2, 2, 100.0))
        self.assertEqual(results["password_reuse_general"]["sharedPasswords"], 0)
        with self.assertRaisesRegex(ValueError, "Conflicting recovered passwords"):
            build_results(ntlm_mapped_passwords=records + [
                {"username": "a\\sam", "password": "different"}], **kwargs)
        with self.assertRaisesRegex(ValueError, "not in the enabled-user dataset"):
            build_results(ntlm_mapped_passwords=[{"username": "unknown", "password": "x"}], **kwargs)

        lm_account = {"username": "A\\sam", "rid": "1000", "lm_hash": "a" * 32, "nt_hash": "b" * 32}
        kwargs["lm_users"] = [lm_account, {**lm_account, "username": "a\\SAM", "lm_hash": "A" * 32}]
        kwargs["lm_mapped_passwords"] = [records[0], records[1]]
        results = build_results(ntlm_mapped_passwords=[], **kwargs)
        self.assertEqual((results["lm_hashes"]["count"], results["lm_passwords"]["count"],
                          results["lm_passwords"]["recoveryRate"]), (1, 1, 100.0))
        kwargs["privileged_users"] = {
            "status": "available", "warnings": [],
            "accounts": [{"username": "a\\SAM", "groups": ["Backup Operators"]}],
        }
        results = build_results(ntlm_mapped_passwords=[], **kwargs)
        self.assertEqual(results["privileged_users"]["lm_recovered_count"], 1)
        kwargs["lm_users"].append({**lm_account, "rid": "1001"})
        with self.assertRaisesRegex(ValueError, "Conflicting LM user records"):
            build_results(ntlm_mapped_passwords=[], **kwargs)
        kwargs["lm_users"] = []
        with self.assertRaisesRegex(ValueError, "not in the LM-user dataset"):
            build_results(ntlm_mapped_passwords=[], **kwargs)

    def test_recovered_file_validation_and_explicit_missing_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "mapped.txt"
            path.write_text("user: leading:trailing \t\n", encoding="utf-8")
            self.assertEqual(load_passwords(path)[0]["password"], " leading:trailing \t")
            for content in (b"no separator\n", b":password\n", b"user:\xff\n"):
                path.write_bytes(content)
                with self.assertRaises((ValueError, UnicodeDecodeError)):
                    load_passwords(path)
            (root / "enabled.txt").write_text("", encoding="utf-8")
            (root / "policy.txt").write_text("Domain: example.test\nMinimum Password Length: 8\n", encoding="utf-8")
            args = dict(mapped_ntlm_passwords=None, domain_admins=None, company_words=None,
                        pass_policy=root / "policy.txt", enabled_users=root / "enabled.txt",
                        lm_users=None, mapped_lm_passwords=None, privileged_users=None, ntds_users=None)
            self.assertEqual(analysis_workflow._build_analysis_results(**args)["total_passwords"], 0)
            for field in ("mapped_ntlm_passwords", "mapped_lm_passwords", "lm_users", "domain_admins"):
                with self.subTest(field=field), self.assertRaises(FileNotFoundError):
                    analysis_workflow._build_analysis_results(**{**args, field: root / "missing.txt"})

    def test_analysis_warnings_are_separated_from_following_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "enabled.txt").write_text("", encoding="utf-8")
            (root / "policy.txt").write_text(
                "Domain: example.test\nMinimum Password Length: 8\n", encoding="utf-8"
            )
            (root / "privileged.json").write_text(json.dumps({
                "status": "incomplete", "accounts": [],
                "warnings": ["Some group members were not resolved."],
            }), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                analysis_workflow._build_analysis_results(
                    mapped_ntlm_passwords=None, domain_admins=None, company_words=None,
                    pass_policy=root / "policy.txt", enabled_users=root / "enabled.txt",
                    lm_users=None, mapped_lm_passwords=None,
                    privileged_users=root / "privileged.json", ntds_users=None,
                )
                print("Loading and analyzing datasets")
            text = output.getvalue()
            self.assertIn("Some group members were not resolved.\n\n", text)
            self.assertIn(
                "no organised NTDS user records supplied.\n\nLoading and analyzing datasets",
                text,
            )

    def test_analysis_warning_is_separated_from_live_progress(self):
        self._patch_analysis_workflow()
        output = io.StringIO()
        with (
            tempfile.TemporaryDirectory() as directory,
            redirect_stdout(output),
            patch.object(analysis_workflow, "console", Console(
                file=output, force_terminal=True, color_system=None, width=120
            )),
            patch.object(analysis_workflow, "load_privileged_users", return_value={
                "status": "incomplete", "accounts": [],
                "warnings": ["Some group members were not resolved."],
            }),
            patch.object(analysis_workflow, "render_html", return_value="report"),
        ):
            analysis_workflow.analyse_passwords(
                mapped_ntlm_passwords=None, domain_admins=None, company_words=None,
                pass_policy="policy", enabled_users="enabled", ntds_users=None,
                output_file=Path(directory) / "report.html",
            )
        text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", output.getvalue()).replace("\r", "")
        self.assertIn("Some group members were not resolved.\n\n", text)
        self.assertIn("no organised NTDS user records supplied.\n\n", text)

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
        results["lm_hashes"].update({
            "count": 1, "uniqueHashes": 1, "duplicateHashes": 0,
            "accounts": [{"username": "EXAMPLE\\alice", "lm_hash": "A" * 32}],
        })
        text = technical_commentary(results)
        self.assertIn("### Privileged Accounts\n\n", text)
        self.assertIn("### LM Hashes\n\n", text)

    def test_summary_and_commentary_prioritise_present_finding_severities(self):
        mapped = [
            {"username": "EXAMPLE\\operator", "password": "PasswordSpring1"},
            {"username": "EXAMPLE\\user", "password": "PasswordSpring1"},
        ]
        results = build_results(
            ntlm_mapped_passwords=mapped, domain_admins=["admin"],
            company_words=[], minimum_length=20,
            enabled_users=[account["username"] for account in mapped],
            domain_name="example.test",
            lm_users=[{"username": "EXAMPLE\\admin", "lm_hash": "a" * 32}],
            lm_mapped_passwords=[{"username": "EXAMPLE\\admin", "password": "SPRING"}],
            privileged_users={
                "status": "available", "warnings": [],
                "accounts": [{"username": "EXAMPLE\\operator", "groups": ["Backup Operators"]}],
            },
            ntds_users=[],
        )
        results["hibp"] = {
            "count": 1, "checked": 2, "accounts": ["EXAMPLE\\operator"],
            "examples": [{"username": "EXAMPLE\\operator", "masked_hash": "ab" + "*" * 28 + "ef"}],
        }
        summary = executive_summary(results)
        paragraph = summary.split("\n\n")[1]
        paragraph_lower = paragraph.lower()
        self.assertLess(paragraph_lower.index("including for domain administrator accounts"),
                        paragraph_lower.index("privileged account credentials were recovered"))
        self.assertLess(paragraph_lower.index("privileged account credentials were recovered"),
                        paragraph_lower.index("some recovered passwords fell below"))
        self.assertLess(paragraph_lower.index("passwords matching known breach data"),
                        paragraph_lower.index("some recovered passwords fell below"))
        self.assertIn("Prioritising remediation according to severity and business context",
                      summary.split("\n\n")[-1])
        self.assertIn("Affected privileged passwords should be reset promptly",
                      summary.split("\n\n")[-1])

        text = technical_commentary(results)
        headings = [
            "### LM Hashes", "### Privileged Accounts", "### Password Reuse",
            "### Passwords in Breach Data", "### Password Compliance",
            "### Common Patterns", "### Password Complexity",
        ]
        self.assertEqual([text.index(heading) for heading in headings],
                         sorted(text.index(heading) for heading in headings))
        self.assertLess(text.index("LM recovery results included"),
                        text.index("LM password hashes were present"))

        hash_only = build_results(
            ntlm_mapped_passwords=[], domain_admins=[], company_words=[],
            minimum_length=12, enabled_users=["alice", "bob"], domain_name="example.test",
            lm_users=[], lm_mapped_passwords=[],
            ntds_users=[{"username": "alice", "ntlm": "a" * 32},
                        {"username": "bob", "ntlm": "a" * 32}],
        )
        conclusion = executive_summary(hash_only).split("\n\n")[-1]
        self.assertIn("Prioritising remediation according to severity", conclusion)
        self.assertIn("Tracking remediation and reassessing", conclusion)
        self.assertNotIn("privileged passwords", conclusion)

        low_only = build_results(
            ntlm_mapped_passwords=[{"username": "user", "password": "Spring#17"}],
            domain_admins=[], company_words=[], minimum_length=8,
            enabled_users=["user"], domain_name="example.test",
            lm_users=[], lm_mapped_passwords=[], ntds_users=[],
        )
        conclusion = executive_summary(low_only).split("\n\n")[-1]
        self.assertIn("Prioritising remediation according to severity", conclusion)
        self.assertNotIn("high-severity", conclusion)
        self.assertNotIn("low-severity", conclusion)

    def test_lm_recovery_and_impact_share_a_paragraph(self):
        results = {
            "lm_hashes": {
                "count": 1, "uniqueHashes": 1, "duplicateHashes": 0,
                "accounts": [{"username": "EXAMPLE\\alice", "lm_hash": "A" * 32}],
            },
            "lm_passwords": {
                "count": 1, "partialCount": 0, "recoveryRate": 100.0,
            },
            "lm_admins": {"count": 0},
        }
        text = commentary_lm_hashes(results)

        self.assertIn(
            "password recovery using commonly available password dictionaries and rule sets.\n\n"
            "Passwords were successfully recovered from one account that stored LM hashes, "
            "representing 100.0% of affected accounts, which demonstrates the practical "
            "weakness of LM password storage.",
            text,
        )
        self.assertNotIn("The extremely high recovery rate", text)
        results["lm_passwords"]["partialCount"] = 1
        self.assertIn("weakness of LM password storage. A further one account",
                      commentary_lm_hashes(results))
        for rate in (50.0, 10.0):
            with self.subTest(rate=rate):
                results["lm_passwords"]["recoveryRate"] = rate
                text = commentary_lm_hashes(results)
                recovery = text.split("\n\n")[2]
                self.assertIn("Passwords were successfully recovered", recovery)
                self.assertIn("LM password storage", recovery)
                self.assertIn("A further one account", recovery)

    def test_partial_lm_admin_recovery_does_not_claim_a_complete_password(self):
        results = build_results(
            ntlm_mapped_passwords=[], domain_admins=["admin"], company_words=[],
            minimum_length=12, enabled_users=["EXAMPLE\\admin"], domain_name="example.test",
            lm_users=[{"username": "EXAMPLE\\admin", "lm_hash": "a" * 32}],
            lm_mapped_passwords=[{"username": "EXAMPLE\\admin", "password": "SECRET[notfound]"}],
            ntds_users=[],
        )
        summary = executive_summary(results)
        commentary = commentary_lm_hashes(results)
        self.assertIn("including for Domain Administrator accounts", summary)
        self.assertNotIn("passwords recovered from accounts storing them", summary)
        self.assertIn("LM recovery results included one Domain Administrator account", commentary)
        self.assertIn("| Partially Recovered LM Passwords | 1 |", commentary)
        self.assertNotIn("Passwords were successfully recovered", commentary)

    def test_lm_commentary_shows_masked_account_examples_without_recovery(self):
        hashes = [f"ABCDEF{i:026X}" for i in range(6)]
        results = build_results(
            ntlm_mapped_passwords=[], domain_admins=[], company_words=[],
            minimum_length=12, enabled_users=[], domain_name="example.test",
            lm_users=[
                {"username": f"EXAMPLE\\user|{i}", "lm_hash": value}
                for i, value in enumerate(hashes)
            ],
            lm_mapped_passwords=[], ntds_users=[],
        )
        text = commentary_lm_hashes(results)
        self.assertLess(text.index("| Accounts with LM Hashes | 6 |"),
                        text.index("| Username | LM Hash |"))
        for i, value in enumerate(hashes[:5]):
            self.assertIn(f"| user\\|{i} | {value[:2].lower()}{'*' * 28}{value[-2:].lower()} |", text)
            self.assertNotIn(value, text)
        self.assertNotIn("user\\|5", text)

        results["lm_hashes"]["count"] = 0
        self.assertEqual(commentary_lm_hashes(results), "")

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

                names = ["training05", "training1", "training2", "training3", "training4"]
                (root / "users.txt").write_text("\n".join(names) + "\n", encoding="utf-8")
                (root / "ntds.txt").write_text("".join(
                    f"{name}:{1000 + index}:unused:{'a' * 32}:::\n"
                    for index, name in enumerate(names)
                ), encoding="utf-8")
                with patch.object(sys, "argv", args):
                    cli_main.main()
                findings = json.loads((root / "password-audit-findings.json").read_text())
                related = next(item for item in findings["findings"]
                               if item["id"] == "PWD-REUSE-002")
                self.assertIn("10 similarly named account pairs", related["description"])
                report = (root / "password-audit-report.html").read_text(encoding="utf-8")
                self.assertIn("Matching NTLM hash examples:", report)
                self.assertIn("training05", report)
                self.assertNotIn("a" * 32, report.lower())

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
                load_domain_policy=DEFAULT,
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
            values["load_domain_policy"].return_value = {
                "Domain": "example.test", "Minimum Password Length": "12",
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

    def test_cli_version_reports_installed_package_version(self):
        output = io.StringIO()
        arguments = ["password-audit", "--version"]
        with (
            patch.object(sys, "argv", arguments),
            patch.object(cli_main, "version", return_value="1.1.0"),
            redirect_stdout(output),
            self.assertRaises(SystemExit) as exit_info,
        ):
            cli_main.main()

        self.assertEqual(exit_info.exception.code, 0)
        self.assertEqual(output.getvalue(), "password-audit 1.1.0\n")

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
