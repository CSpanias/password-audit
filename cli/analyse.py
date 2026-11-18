"""
Password Analyser command-line interface.

This module coordinates password analysis by loading input
datasets, generating analysis results, producing report
content, and exporting the final Markdown report.
"""

from pathlib import Path

from analysis.workflow import analyse_passwords


def run_password_analysis(args):
    """
    Execute the password analysis workflow.

    Command-line arguments are parsed and the required input
    datasets are loaded. Analysis results are generated and
    subsequently transformed into executive summary, technical
    commentary, and remediation guidance sections.

    The completed report is rendered in the requested formats
    and written to disk.

    Returns:
        None
    """


    generated_words = Path("password-audit/company-words.txt")
    company_words = [generated_words] if generated_words.is_file() else []
    custom_words = args.company_words

    if custom_words is None:
        conventional_words = Path("company-words.txt")
        if conventional_words.is_file():
            custom_words = conventional_words

    if custom_words:
        custom_words = Path(custom_words)
        if custom_words.resolve() != generated_words.resolve():
            company_words.append(custom_words)

    analyse_passwords(
        mapped_ntlm_passwords=args.mapped_ntlm_passwords,
        domain_admins=args.domain_admins,
        company_words=company_words,
        pass_policy=args.pass_policy,
        enabled_users=args.enabled_users,
        lm_users=args.lm_users,
        mapped_lm_passwords=args.mapped_lm_passwords,
        output_file=args.output,
        report_formats=getattr(args, "report_formats", None),
    )
