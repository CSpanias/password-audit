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
from analysis.findings import build_findings
from reports.json import write_findings
from reports.markdown import render_markdown, write_markdown
from common.console import warn


def analyse_passwords(
    mapped_ntlm_passwords,
    domain_admins,
    company_words,
    pass_policy,
    enabled_users,
    lm_users=None,
    mapped_lm_passwords=None,
    output_file="report.md",
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
            "Unable to determine Minimum Password Length "
            "from domain-policy.txt"
        )
        warn(
            "Password policy data appears to be unavailable "
            "within the supplied dataset."
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
    findings = build_findings(results)

    # Export files to disc
    write_markdown(output_file, render_markdown(report))
    write_findings("findings.json", findings)

    return results