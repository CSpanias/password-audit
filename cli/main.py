"""
Password Audit command-line interface.

This module provides the primary command-line entry point and
dispatches execution to individual framework components.
"""

import argparse
from textwrap import dedent

from rich_argparse import RawDescriptionRichHelpFormatter

from cli.analyse import run_password_analysis
from cli.audit import run_audit_workflow
from cli.crack import run_cracking_campaign
from cli.lm import run_lm_candidates, run_lm_mapping
from cli.organise import run_ntds_organiser
from cracking.estimate import print_campaign_estimate
from cracking.statistics import print_phase_statistics
from reports.renderers import REPORT_RENDERERS


def main():
    """
    Execute the Password Audit command-line interface.

    Command-line arguments are parsed and execution is
    dispatched to the selected framework component.

    Returns:
        None
    """

    # Parsers configuration
    class CustomFormatter(
        argparse.ArgumentDefaultsHelpFormatter,
        RawDescriptionRichHelpFormatter,
    ):
        pass

    parser = argparse.ArgumentParser(
        description="Password Audit Framework",
        formatter_class=CustomFormatter,
        epilog=(
            "Recommended workflow: password-audit audit. "
            "Use organise, crack, analyse, and lm for advanced standalone "
            "or partial workflows."
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    #-----------------------------------------------
    # Audit module
    #-----------------------------------------------

    audit_parser = subparsers.add_parser(
        "audit",
        help="Execute an end-to-end password audit",
        description=(
            "Perform an end-to-end password audit by "
            "orchestrating the organise, crack, and "
            "analyse modules, then generate reports."
        ),
        formatter_class=CustomFormatter,
        epilog=dedent("""
        Example:

            password-audit audit \\
                -N company.ntds \\
                -B bloodhound.zip \\
                -C config.json \\
                -G internal-password-audit \\
                --format markdown html
        """)
    )

    # Group required and options arguments
    required_audit_parser = audit_parser.add_argument_group(
        "required arguments"
    )

    optional_audit_parser = audit_parser.add_argument_group(
        "optional arguments"
    )

    # Required arguments
    required_audit_parser.add_argument(
        "-N",
        "--ntds",
        required=True,
        help="Secretsdump NTDS file"
    )

    required_audit_parser.add_argument(
        "-B",
        "--bloodhound",
        required=True,
        help="BloodHound ZIP export"
    )

    required_audit_parser.add_argument(
        "-C",
        "--campaign",
        required=True,
        help="Campaign configuration file"
    )

    required_audit_parser.add_argument(
        "-G",
        "--campaign-name",
        required=True,
        help="Campaign identifier"
    )

    # Optional arguments
    optional_audit_parser.add_argument(
        "-F",
        "--filter",
        help="Comma-separated usernames to exclude",
    )

    optional_audit_parser.add_argument(
        "-M",
        "--mapped-ntlm-passwords",
        default="./password-audit/mapped-ntlm-passwords.txt",
        help="Recovered NTLM passwords",
    )

    optional_audit_parser.add_argument(
            "-U",
            "--lm-users",
            default="./password-audit/lm-users.txt",
            help="Accounts storing LM password hashes",
        )

    optional_audit_parser.add_argument(
            "-L",
            "--mapped-lm-passwords",
            default="./password-audit/mapped-lm-passwords.txt",
            help="Recovered LM passwords",
        )

    optional_audit_parser.add_argument(
        "-D",
        "--domain-admins",
        default="./password-audit/domain-admins.txt",
        help="Domain Admin account list",
    )

    optional_audit_parser.add_argument(
        "-P",
        "--pass-policy",
        default="./password-audit/domain-policy.txt",
        help="Domain password policy",
    )

    optional_audit_parser.add_argument(
        "-W",
        "--company-words",
        default=None,
        help=(
            "Optional curated company wordlist to add to generated terms; "
            "defaults to ./company-words.txt when present"
        ),
    )

    optional_audit_parser.add_argument(
        "-E",
        "--enabled-users",
        default="./password-audit/enabled-users.txt",
        help="Enabled user accounts list",
    )

    optional_audit_parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Skip completed campaign phases and restart the interrupted phase; "
            "legacy ntds-organiser results are not migrated"
        ),
    )

    optional_audit_parser.add_argument(
        "--format",
        dest="report_formats",
        nargs="+",
        metavar="FORMAT",
        choices=tuple(REPORT_RENDERERS),
        default=argparse.SUPPRESS,
        help=(
            "One or more report formats to generate "
            "(default: markdown and html)"
        ),
    )

    audit_parser.set_defaults(
        func=run_audit_workflow,
    )

    #-----------------------------------------------
    # Organise module
    #-----------------------------------------------

    organise_parser = subparsers.add_parser(
        "organise",
        help="Advanced standalone NTDS/BloodHound processing",
        description=(
            "Parse NTDS, BloodHound, and Hashcat datasets and "
            "generate analysis artefacts."
        ),
        formatter_class=CustomFormatter,
        epilog=dedent("""
        Example:

            password-audit organise \\
                -N company.ntds \\
                -B bloodhound.zip
        """)
    )

    # Group required and options arguments
    required_organise_parser = organise_parser.add_argument_group(
        "required arguments"
    )

    optional_organise_parser = organise_parser.add_argument_group(
        "optional arguments"
    )

    # Required arguments
    required_organise_parser.add_argument(
        "-N",
        "--ntds",
        required=True,
        help="Secretsdump NTDS file"
    )

    required_organise_parser.add_argument(
        "-B",
        "--bloodhound",
        required=True,
        help="BloodHound ZIP export"
    )

    # Optional arguments
    optional_organise_parser.add_argument(
        "-F",
        "--filter",
        help="Comma-separated usernames to exclude"
    )

    optional_organise_parser.add_argument(
        "-O",
        "--output",
        default="password-audit",
        help="Output directory"
    )

    optional_organise_parser.add_argument(
        "-P",
        "--potfile",
        help="Hashcat potfile containing recovered passwords"
    )

    organise_parser.set_defaults(
        func=run_ntds_organiser
    )

    #-----------------------------------------------
    # Crack module
    #-----------------------------------------------

    crack_parser = subparsers.add_parser(
        "crack",
        help="Advanced standalone password recovery campaigns",
        description=(
            "Advanced standalone Hashcat campaigns. Campaign estimates and "
            "historical statistics are experimental; use audit for the "
            "recommended end-to-end workflow."
        ),
        epilog="""
    Examples:

        password-audit crack estimate \\
            -C config.json

        password-audit crack run \\
            -H password-audit/ntlm-hashes.txt \\
            -C config.json \\
            -G internal-audit

        password-audit crack stats
    """,
        formatter_class=CustomFormatter,
    )

    crack_subparsers = crack_parser.add_subparsers(
        dest="crack_command",
        required=True,
    )

    #-----------------------------------------------
    # Crack estimate submodule
    #-----------------------------------------------

    estimate_parser = crack_subparsers.add_parser(
        "estimate",
        help="Experimental campaign duration estimate",
        description=(
            "Estimate the duration of a cracking campaign "
            "before execution using the supplied configuration "
            "file and historical data."
        ),
        formatter_class=CustomFormatter,
        epilog=dedent("""
        Example:

            password-audit crack estimate \\
                -C config.json
        """)
    )

    # Group required and options arguments
    required_estimate_parser = estimate_parser.add_argument_group(
        "required arguments"
    )

    required_estimate_parser.add_argument(
        "-C",
        "--campaign",
        required=True,
        help="Campaign configuration file",
    )

    estimate_parser.set_defaults(
        func=print_campaign_estimate,
    )

    #-----------------------------------------------
    # Crack run submodule
    #-----------------------------------------------

    run_parser = crack_subparsers.add_parser(
        "run",
        help="Execute a cracking campaign",
        description=(
            "Execute a Hashcat password recovery campaign "
            "using the supplied hash dataset and campaign "
            "configuration file."
        ),
        epilog="""
    Example:

        password-audit crack run \\
            -H password-audit/ntlm-hashes.txt \\
            -C config.json \\
            -G internal-audit
    """,
        formatter_class=CustomFormatter,
    )

    # Group required and options arguments
    required_run_parser = run_parser.add_argument_group(
        "required arguments"
    )

    optional_run_parser = run_parser.add_argument_group(
        "optional arguments"
    )

    # Required arguments
    required_run_parser.add_argument(
        "-H",
        "--hashes",
        required=True,
        help="Hash file to crack",
    )

    required_run_parser.add_argument(
        "-C",
        "--campaign",
        required=True,
        help="Campaign configuration file"
    )

    required_run_parser.add_argument(
        "-G",
        "--campaign-name",
        required=True,
        help="Campaign identifier"
    )

    # Optional arguments
    optional_run_parser.add_argument(
        "--debug",
        action="store_true",
        help="Display verbose Hashcat output",
    )

    run_parser.set_defaults(
        func=run_cracking_campaign,
    )

    #-----------------------------------------------
    # Crack stats submodule
    #-----------------------------------------------

    stats_parser = crack_subparsers.add_parser(
        "stats",
        help="Experimental historical cracking statistics",
        description=(
            "Display statistics for previously executed "
            "cracking campaigns, including password recovery "
            "counts, attack performance, and campaign history."
        ),
        formatter_class=CustomFormatter,
        epilog=dedent("""
        Example:

            password-audit crack stats
        """)
    )

    stats_parser.set_defaults(
        func=print_phase_statistics,
    )

    #-----------------------------------------------
    # Analyse module
    #-----------------------------------------------

    analyse_parser = subparsers.add_parser(
        "analyse",
        help="Advanced standalone password analysis and reporting",
        description=(
            "Analyse recovered NTLM and LM passwords, "
            "identify common weaknesses, and generate "
            "reports in Markdown, JSON, YAML, SARIF, or HTML "
            "with findings and remediation guidance."
        ),
        formatter_class=CustomFormatter,
        epilog=dedent("""
        Example:

            password-audit analyse \\
                -M password-audit/mapped-ntlm-passwords.txt
        """)
    )

    # Group required and options arguments
    required_analyse_parser = analyse_parser.add_argument_group(
        "required arguments"
    )

    optional_analyse_parser = analyse_parser.add_argument_group(
        "optional arguments"
    )

    # Required arguments
    required_analyse_parser.add_argument(
        "-M",
        "--mapped-passwords",
        "--mapped-ntlm-passwords",
        "--mapped-ntlm_passwords",
        dest="mapped_ntlm_passwords",
        required=True,
        help="Recovered NTLM passwords"
    )

    # Optional arguments
    optional_analyse_parser.add_argument(
        "-D",
        "--domain-admins",
        default="./password-audit/domain-admins.txt",
        help="Domain Admin account list"
    )

    optional_analyse_parser.add_argument(
        "-P",
        "--pass-policy",
        default="./password-audit/domain-policy.txt",
        help="Domain password policy"
    )

    optional_analyse_parser.add_argument(
        "-G",
        "--company-words",
        default=None,
        help=(
            "Optional curated company wordlist added to generated terms; "
            "defaults to ./company-words.txt when present"
        )
    )

    optional_analyse_parser.add_argument(
        "-E",
        "--enabled-users",
        default="./password-audit/enabled-users.txt",
        help="Enabled user accounts list"
    )

    optional_analyse_parser.add_argument(
        "-U",
        "--lm-users",
        default="./password-audit/lm-users.txt",
        help="Accounts storing LM password hashes"
    )

    optional_analyse_parser.add_argument(
        "-L",
        "--mapped-lm-passwords",
        #default="./password-audit/mapped-lm-passwords.txt",
        help="Recovered LM passwords"
    )

    optional_analyse_parser.add_argument(
        "-O",
        "--output",
        default="password-audit-report.md",
        help=(
            "Output report path; its extension is replaced with the "
            "selected format extension"
        ),
    )

    optional_analyse_parser.add_argument(
        "--format",
        dest="report_formats",
        nargs="+",
        metavar="FORMAT",
        choices=tuple(REPORT_RENDERERS),
        default=argparse.SUPPRESS,
        help=(
            "One or more report formats to generate "
            "(default: markdown and html)"
        ),
    )
    
    analyse_parser.set_defaults(
        func=run_password_analysis
    )

    #-----------------------------------------------
    # LM module
    #-----------------------------------------------

    lm_parser = subparsers.add_parser(
        "lm",
        help="Advanced standalone LM password utilities",
        description=(
            "LM password processing utilities used to "
            "reconstruct recovered LM passwords, map them "
            "to user accounts, and generate candidate "
            "password variants for privileged accounts."
        ),
        formatter_class=CustomFormatter,
        epilog=dedent("""
        Examples:

            password-audit lm map \\
                -N company.ntds \\
                -P hashcat.potfile \\
                -R lm-results.txt

            password-audit lm generate \\
                -L password-audit/mapped-lm-passwords.txt
        """)
    )

    lm_subparsers = lm_parser.add_subparsers(
        dest="lm_command",
        required=True,
    )

    #-----------------------------------------------
    # LM map submodule
    #-----------------------------------------------

    lm_map_parser = lm_subparsers.add_parser(
        "map",
        help="Map recovered LM passwords to user accounts",
        description=(
            "Reconstruct recovered LM passwords using "
            "Hashcat show results and map them back to "
            "user accounts within the NTDS dataset."
        ),
        formatter_class=CustomFormatter,
        epilog=dedent("""
        Example:

            password-audit lm map \\
                -N company.ntds \\
                -P hashcat.potfile \\
                -R lm-results.txt
        """)
    )

    required_lm_map_parser = lm_map_parser.add_argument_group(
        "required arguments"
    )

    optional_lm_map_parser = lm_map_parser.add_argument_group(
        "optional arguments"
    )

    # Required arguments
    required_lm_map_parser.add_argument(
        "-N",
        "--ntds",
        required=True,
        help="SecretsDump NTDS file",
    )

    required_lm_map_parser.add_argument(
        "-P",
        "--potfile",
        required=True,
        help="Hashcat potfile containing recovered passwords",
    )

    required_lm_map_parser.add_argument(
        "-R",
        "--lm-results",
        required=True,
        help="LM recovery results generated using hashcat --show",
    )

    # Optional arguments
    optional_lm_map_parser.add_argument(
        "-O",
        "--output-dir",
        default="password-audit",
        help="Output directory",
    )

    lm_map_parser.set_defaults(
        func=run_lm_mapping,
    )

    #-----------------------------------------------
    # LM generate submodule
    #-----------------------------------------------

    lm_generate_parser = lm_subparsers.add_parser(
        "generate",
        help="Generate LM Domain Admin candidates",
        description=(
            "Identify recovered LM passwords belonging "
            "to Domain Administrators and generate all "
            "possible password capitalisation variants."
        ),
        formatter_class=CustomFormatter,
        epilog=dedent("""
        Example:

            password-audit lm generate \\
                -L password-audit/mapped-lm-passwords.txt
        """)
    )

    required_lm_generate_parser = lm_generate_parser.add_argument_group(
        "required arguments"
    )

    optional_lm_generate_parser = lm_generate_parser.add_argument_group(
        "optional arguments"
    )

    # Required arguments
    required_lm_generate_parser.add_argument(
        "-L",
        "--mapped-lm-passwords",
        required=True,
        help="Recovered LM passwords",
    )

    # Optional arguments
    optional_lm_generate_parser.add_argument(
        "-D",
        "--domain-admins",
        default="./password-audit/domain-admins.txt",
        help="Domain Admin account list",
    )

    optional_lm_generate_parser.add_argument(
        "-O",
        "--output-dir",
        default="password-audit",
        help="Output directory",
    )

    lm_generate_parser.set_defaults(
        func=run_lm_candidates,
    )

    #-----------------------------------------------
    # Assembly parsers
    #-----------------------------------------------

    args = parser.parse_args()

    args.func(args)


if __name__ == "__main__":
    main()