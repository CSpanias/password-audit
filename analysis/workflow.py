"""
Password analysis workflow.

This module provides reusable password analysis workflows
for report generation and audit orchestration.
"""

from analysis.parsers import load_passwords, load_list, load_domain_policy, load_company_words, load_lm_users
from analysis.results import build_results
from analysis.executive_summary import executive_summary
from analysis.technical_commentary import technical_commentary
from analysis.remediation_guidance import remediation_guidance, remediation_references
from reports.markdown import render_markdown, write_markdown


def analyse_passwords(
    mapped_passwords,
    domain_admins,
    company_words,
    pass_policy,
    enabled_users,
    lm_users=None,
    output_file="report.md",
):
    """
    Analyse recovered passwords and generate a report.

    Args:
        mapped_passwords:
            Password dataset.

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

    Returns:
        dict:
            Password analysis results.
    """

    passwords = load_passwords(mapped_passwords)

    domain_admins = load_list(domain_admins)
    company_words = load_company_words(company_words)
    enabled_users = load_list(enabled_users)
    lm_users = load_lm_users(lm_users)

    policy = load_domain_policy(pass_policy)

    results = build_results(
        passwords=passwords,
        domain_admins=domain_admins,
        company_words=company_words,
        minimum_length=int(
            policy["Minimum Password Length"]
        ),
        enabled_users=enabled_users,
        lm_users=lm_users
    )

    print(results["lm_hashes"])

    report = {
        "executive_summary": executive_summary(results),
        "technical_commentary": technical_commentary(results),
        "remediation_guidance": remediation_guidance(results),
        "references": remediation_references(results),
    }

    write_markdown(
        output_file,
        render_markdown(report),
    )

    return results