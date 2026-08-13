"""
Password Analyser command-line interface.

This module coordinates password analysis by loading input
datasets, generating analysis results, producing report
content, and exporting the final Markdown report.
"""

from common.console import (
    ok,
)

from analysis.workflow import (
    analyse_passwords,
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


    analyse_passwords(
        mapped_passwords=args.mapped_passwords,
        domain_admins=args.domain_admins,
        company_words=args.company_words,
        pass_policy=args.pass_policy,
        enabled_users=args.enabled_users,
        lm_users=args.lm_users,
    )

    print()
    ok("Markdown report written to: report.md")
    print()