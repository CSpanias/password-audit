import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import DEFAULT, patch

from rich.console import Console

import analysis.workflow as analysis_workflow
import auditing.workflow as audit_workflow
import cli.audit as cli_audit
import cli.main as cli_main
from reports.html import render_html
from reports.json import write_findings

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
            )

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
                [Path(directory) / "password-audit" / "company-words.txt"],
            )
            self.assertEqual(
                result["report"],
                Path(directory) / "password-audit-report.html",
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
