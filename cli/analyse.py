"""
Password Analyser command-line interface.

This module coordinates password analysis by loading input
datasets, generating analysis results, producing report
content, and writing the HTML report and findings sidecar.
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

    The completed HTML report and findings sidecar are written to disk.

    Returns:
        None
    """


    run_directory = Path(args.mapped_ntlm_passwords).parent
    generated_words = run_directory / "company-words.txt"
    company_words = [generated_words] if generated_words.is_file() else []
    custom_words = args.company_words

    if custom_words is None:
        conventional_words = Path("company-words.txt")
        if conventional_words.is_file():
            custom_words = conventional_words

    if custom_words:
        custom_words = Path(custom_words)
        if not company_words or custom_words.resolve() != generated_words.resolve():
            company_words.append(custom_words)

    privileged_users = args.privileged_users
    if privileged_users is None:
        default_privileged_users = run_directory / "privileged-users.json"
        if default_privileged_users.is_file():
            privileged_users = default_privileged_users

    ntds_users = args.ntds_users
    default_ntds_users = run_directory / "ntds-users-clean.txt"
    if ntds_users is None and default_ntds_users.is_file():
        ntds_users = default_ntds_users

    domain_admins = args.domain_admins
    default_domain_admins = run_directory / "domain-admins.txt"
    if domain_admins is None and default_domain_admins.is_file():
        domain_admins = default_domain_admins

    lm_users = args.lm_users
    default_lm_users = run_directory / "lm-users.txt"
    if lm_users is None and default_lm_users.is_file():
        lm_users = default_lm_users

    pass_policy = (
        args.pass_policy if args.pass_policy is not None else run_directory / "domain-policy.txt"
    )
    enabled_users = (
        args.enabled_users if args.enabled_users is not None else run_directory / "enabled-users.txt"
    )

    analyse_passwords(
        mapped_ntlm_passwords=args.mapped_ntlm_passwords,
        domain_admins=domain_admins,
        privileged_users=privileged_users,
        ntds_users=ntds_users,
        hibp=args.hibp,
        company_words=company_words,
        pass_policy=pass_policy,
        enabled_users=enabled_users,
        lm_users=lm_users,
        mapped_lm_passwords=args.mapped_lm_passwords,
        output_file=args.output,
        csacyber=args.csacyber,
    )
