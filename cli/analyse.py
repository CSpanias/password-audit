"""
Password Analyser command-line interface.

This module coordinates password analysis by loading input
datasets, generating analysis results, producing report
content, and exporting the final Markdown report.
"""

from common.constants import (
    COLOR_GREEN,
    COLOR_RESET,
)

from analyse.parsers import (
    load_passwords,
    load_list,
    load_domain_policy,
    load_company_words,
)

from analyse.results import (
    build_results,
)

from analyse.executive_summary import (
    executive_summary,
)

from analyse.technical_commentary import (
    technical_commentary,
)

from analyse.remediation_guidance import (
    remediation_guidance,
)

from reports.markdown import (
    render_markdown,
    write_markdown,
)


def run_password_analysis(args):
    """
    Execute the password analysis workflow.

    Command-line arguments are parsed and the required input
    datasets are loaded. Analysis results are generated and
    subsequently transformed into executive summary, technical
    commentary, and remediation guidance sections.

    The completed report is then rendered as Markdown and
    written to disk.

    Returns:
        None
    """


    passwords = load_passwords(args.mapped_passwords)
    domain_admins = load_list(args.domain_admins)
    company_words = load_company_words(args.company_words)
    enabled_users = load_list(args.enabled_users)

    policy = load_domain_policy(args.pass_policy)

    results = build_results(
        passwords=passwords,
        domain_admins=domain_admins,
        company_words=company_words,
        minimum_length=int(policy["Minimum Password Length"]),
        enabled_users=enabled_users,
    )

    report = {
        "executive_summary": executive_summary(results),
        "technical_commentary": technical_commentary(results),
        "remediation_guidance": remediation_guidance(results),
    }

    write_markdown("report.md", render_markdown(report))

    print()
    print(
        f"{COLOR_GREEN}[+] Markdown report written to: report.md{COLOR_RESET}"
    )
    print()