"""
Password analysis workflow.

This module provides reusable password analysis workflows
for report generation and audit orchestration.
"""

import sys

from pathlib import Path

from analysis.parsers import load_passwords, load_list, load_domain_policy, load_company_words, load_lm_users
from analysis.results import build_results
from analysis.executive_summary import executive_summary
from analysis.technical_commentary import technical_commentary
from analysis.remediation_guidance import remediation_guidance, remediation_references
from analysis.findings import build_findings_dict
from reports.json import write_findings
from reports.markdown import render_markdown, write_markdown
from common.console import warn, ok
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def analyse_passwords(
    mapped_ntlm_passwords,
    domain_admins,
    company_words,
    pass_policy,
    enabled_users,
    lm_users=None,
    mapped_lm_passwords=None,
    output_file="password-audit-report.md",
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

    Returns:
        dict:
            Password analysis results.
    """


    # Enabled user objects
    enabled_users = load_list(enabled_users)

    # Domain admins
    domain_admins = load_list(domain_admins)

    # Domain password policy
    policy = load_domain_policy(pass_policy)
    domain_name = policy.get("Domain")

    # Domain-based generate company file
    company_words = load_company_words(company_words)

    # Recovered NTLM passwords
    ntlm_passwords = []

    if (mapped_ntlm_passwords and Path(mapped_ntlm_passwords).exists()):
            
            ntlm_passwords = load_passwords(mapped_ntlm_passwords)

    # Presence of LM hashes
    loaded_lm_users = []

    if (lm_users and Path(lm_users).exists()):

        loaded_lm_users = load_lm_users(lm_users)

    lm_users = loaded_lm_users

    # Length Compliance
    minimum_length = policy["Minimum Password Length"]

    try:
        minimum_length = int(minimum_length)

    except (TypeError, ValueError):
        warn(
            "Unable to determine Minimum Password Length from domain-policy.txt"
        )
        warn(
            "Password policy data appears to be unavailable within the "
            "supplied dataset."
        )
        sys.exit(1)

    # Recovered LM passwords 
    lm_passwords = []

    if (mapped_lm_passwords and Path(mapped_lm_passwords).exists()):
        lm_passwords = load_passwords(mapped_lm_passwords)

    results = build_results(
        ntlm_mapped_passwords=ntlm_passwords,
        domain_admins=domain_admins,
        company_words=company_words,
        minimum_length=minimum_length,
        enabled_users=enabled_users,
        lm_users=lm_users,
        lm_mapped_passwords=lm_passwords,
        domain_name=domain_name
    )

    # Markdown report export
    report = {
        "executive_summary": executive_summary(results),
        "technical_commentary": technical_commentary(results),
        "remediation_guidance": remediation_guidance(results),
        "references": remediation_references(results),
    }

    # Findings JSON export
    findings = build_findings_dict(results)

    # Export files to disc
    write_markdown(output_file, render_markdown(report))
    write_findings("password-audit-findings.json", findings)

    # Rich console output
    _print_console_summary(results, findings)

    return results


def _print_console_summary(results, findings):
    """
    Display a rich-formatted console summary of the password audit results.

    Args:
        results:
            Analysis results dictionary.
        findings:
            List of finding dictionaries.
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

    console.print(table)
    console.print()

    # Findings summary by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    severity_style = {
        "critical": "bold white on red",
        "high": "bold red",
        "medium": "bold yellow",
        "low": "blue",
        "info": "dim",
    }

    findings_by_severity = {}
    for f in findings:
        sev = f.get("severity", "info")
        findings_by_severity.setdefault(sev, []).append(f)

    finding_table = Table(title="Findings", header_style="bold magenta")
    finding_table.add_column("Severity", style="bold")
    finding_table.add_column("Count", justify="right")
    finding_table.add_column("Finding", style="white")

    for sev in sorted(findings_by_severity.keys(), key=lambda s: severity_order.get(s, 99)):
        count = len(findings_by_severity[sev])
        style = severity_style.get(sev, "white")
        finding_table.add_row(sev.upper(), str(count), style=style)

    console.print(finding_table)
    console.print()

    # Detail for critical/high findings
    important = [f for f in findings if f.get("severity") in ("critical", "high")]
    if important:
        console.print(Panel(
            "[bold red]Critical / High Findings[/bold red]",
            border_style="red",
        ))
        for f in important:
            console.print(f"  [bold]{f['id']}[/bold] - {f['title']}")
            console.print(f"    {f['description']}")
        console.print()

    ok("Report written to: report.md")
    ok("Findings written to: password-audit-findings.json")
    console.print()