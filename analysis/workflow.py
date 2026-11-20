"""
Password analysis workflow.

This module provides reusable password analysis workflows
for report generation and audit orchestration.
"""

import sys
from pathlib import Path

from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from analysis.executive_summary import executive_summary
from analysis.findings import build_findings_dict
from analysis.parsers import (
    load_company_words,
    load_domain_policy,
    load_list,
    load_lm_users,
    load_passwords,
    load_privileged_users,
)
from analysis.remediation_guidance import remediation_guidance, remediation_references
from analysis.results import build_results
from analysis.technical_commentary import technical_commentary
from common.console import console, warn
from reports.html import render_html
from reports.json import write_findings
from reports.sureformat import write_sureformat


def analyse_passwords(
    mapped_ntlm_passwords,
    domain_admins,
    company_words,
    pass_policy,
    enabled_users,
    lm_users=None,
    mapped_lm_passwords=None,
    output_file="password-audit-report.html",
    csacyber=False,
    findings_file=None,
    privileged_users=None,
):
    """
    Analyse recovered passwords and generate a report.

    Args:
        mapped_ntlm_passwords:
            Recovered NTLM passwords.

        domain_admins:
            Domain administrator dataset.

        company_words:
            Organisation-specific words.

        pass_policy:
            Domain password policy.

        enabled_users:
            Enabled user dataset.

        lm_users:
            LM users dataset.

        output_file:
            Output report path.

        mapped_lm_passwords:
            Recovered LM passwords.

        csacyber:
            Export SureFormat XML instead of JSON findings.

        findings_file:
            Optional findings output path.

        privileged_users:
            Optional organiser-generated privileged group membership dataset.

    Returns:
        dict:
            Password analysis results.
    """

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task("Loading and analyzing datasets", total=3)
        results = _build_analysis_results(
            mapped_ntlm_passwords=mapped_ntlm_passwords,
            domain_admins=domain_admins,
            company_words=company_words,
            pass_policy=pass_policy,
            enabled_users=enabled_users,
            lm_users=lm_users,
            mapped_lm_passwords=mapped_lm_passwords,
            privileged_users=privileged_users,
        )
        progress.advance(task_id)

        if csacyber:
            domain_name = results.get("domain_name")
            if not isinstance(domain_name, str) or domain_name.strip().lower() in {
                "", "none",
            }:
                raise ValueError(
                    "SureFormat export requires a domain name in the domain password policy."
                )

        progress.update(task_id, description="Building report")
        findings = build_findings_dict(results)
        report = {
            "summary": {
                "total_passwords": results["total_passwords"],
                "enabled_users": results["enabled_users"],
                "unique_passwords": results["unique_passwords"],
                "crack_rate": results["crack_rate"],
                "lm_hashes": results["lm_hashes"]["count"],
                "lm_passwords_recovered": results["lm_passwords"]["count"],
                "lm_recovery_rate": results["lm_passwords"]["recoveryRate"],
            },
            "executive_summary": executive_summary(results),
            "technical_commentary": technical_commentary(results),
            "remediation_guidance": remediation_guidance(results),
            "references": remediation_references(results),
            "findings": findings,
        }
        progress.advance(task_id)

        progress.update(task_id, description="Writing report files")
        report_path = Path(output_file).with_suffix(".html")
        report_path.write_text(render_html(report), encoding="utf-8")
        if csacyber:
            findings_path = findings_file or "password-audit-findings.xml"
            write_sureformat(findings_path, domain_name.strip(), findings)
        else:
            findings_path = findings_file or "password-audit-findings.json"
            write_findings(findings_path, findings)
        progress.advance(task_id)

    _print_console_summary(results, findings, report_path, findings_path)

    return results


def _build_analysis_results(
    mapped_ntlm_passwords,
    domain_admins,
    company_words,
    pass_policy,
    enabled_users,
    lm_users,
    mapped_lm_passwords,
    privileged_users,
):
    """Load analysis inputs and build the structured results."""
    enabled_users = load_list(enabled_users)
    domain_admins = load_list(domain_admins)
    policy = load_domain_policy(pass_policy)
    domain_name = policy.get("Domain")
    company_words = load_company_words(company_words)
    privileged_users = load_privileged_users(privileged_users)
    if privileged_users["status"] != "available":
        warn("Privileged group analysis is incomplete: " + " ".join(
            privileged_users["warnings"]
        ))

    ntlm_passwords = []
    if mapped_ntlm_passwords and Path(mapped_ntlm_passwords).exists():
        ntlm_passwords = load_passwords(mapped_ntlm_passwords)

    if lm_users and Path(lm_users).exists():
        lm_users = load_lm_users(lm_users)
    else:
        lm_users = []

    try:
        minimum_length = int(policy["Minimum Password Length"])
    except (KeyError, TypeError, ValueError):
        warn(
            "Unable to determine Minimum Password Length from domain-policy.txt"
        )
        warn(
            "Password policy data appears to be unavailable within the "
            "supplied dataset."
        )
        sys.exit(1)

    lm_passwords = []
    if mapped_lm_passwords and Path(mapped_lm_passwords).exists():
        lm_passwords = load_passwords(mapped_lm_passwords)

    return build_results(
        ntlm_mapped_passwords=ntlm_passwords,
        domain_admins=domain_admins,
        company_words=company_words,
        minimum_length=minimum_length,
        enabled_users=enabled_users,
        lm_users=lm_users,
        lm_mapped_passwords=lm_passwords,
        domain_name=domain_name,
        privileged_users=privileged_users,
    )


def _print_console_summary(results, findings, report_path, findings_path):
    """
    Display a rich-formatted console summary of the password audit results.

    Args:
        results:
            Analysis results dictionary.
        findings:
            List of finding dictionaries.
        report_path:
            Path to the generated HTML report.

        findings_path:
            Path to the generated findings export.
    """
    console.print()
    console.print(Panel.fit(
        "[bold]Password Audit Results[/bold]",
        border_style="cyan",
    ))
    console.print()

    # Summary table
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Label", style="bold cyan")
    table.add_column("Value", style="white")

    table.add_row("Total passwords", str(results.get("total_passwords", 0)))
    table.add_row("Enabled users", str(results.get("enabled_users", 0)))
    table.add_row("Unique passwords", str(results.get("unique_passwords", 0)))
    table.add_row("Crack rate", f"{results.get('crack_rate', 0)}%")
    table.add_row(
        "Accounts with LM hashes",
        str(results.get("lm_hashes", {}).get("count", 0)),
    )
    table.add_row(
        "LM passwords recovered",
        str(results.get("lm_passwords", {}).get("count", 0)),
    )

    console.print(table)
    console.print()

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    severity_style = {
        "critical": "bold white on red",
        "high": "bold red",
        "medium": "bold yellow",
        "low": "blue",
        "info": "dim",
    }

    finding_table = Table(title="Findings", header_style="bold magenta")
    finding_table.add_column("Severity", style="bold")
    finding_table.add_column("ID", style="dim")
    finding_table.add_column("Finding")
    finding_table.add_column("Category")

    ordered_findings = sorted(
        findings,
        key=lambda finding: (
            severity_order.get(finding.get("severity", "info"), 99),
            finding.get("title", ""),
        ),
    )
    for finding in ordered_findings:
        severity = finding.get("severity", "info")
        finding_table.add_row(
            Text(severity.upper(), style=severity_style.get(severity, "white")),
            Text(finding.get("id", "")),
            Text(finding.get("title", "")),
            Text(finding.get("category", "general")),
        )

    if not ordered_findings:
        finding_table.add_row("None", "", "No findings generated", "")

    console.print(finding_table)
    console.print()

    console.print(Text(f"Report written to: {report_path}", style="green"))
    console.print(Text(f"Findings written to: {findings_path}", style="green"))
    console.print()