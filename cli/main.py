"""
Password Audit command-line interface.

This module provides the primary command-line entry point and
dispatches execution to individual framework components.
"""

import argparse

from textwrap import dedent

from cli.analyse import run_password_analysis
from cli.audit import run_audit_workflow
from cli.crack import run_cracking_campaign
from cli.lm import run_lm_mapping, run_lm_candidates
from cli.organise import run_ntds_organiser
from cracking.statistics import print_phase_statistics
from cracking.estimate import print_campaign_estimate


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
        argparse.RawDescriptionHelpFormatter,
    ):
        pass

    parser = argparse.ArgumentParser(
        description="Password Audit Framework",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
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
            "analyse modules."
        ),
        formatter_class=CustomFormatter,
        epilog=dedent("""
        Example:

            password-audit audit \\
                -N company.ntds \\
                -B bloodhound.zip \\
                -C config.json \\
                -G internal-password-audit
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
        "--mapped-passwords",
        default="./ntds-organiser/mapped-ntlm-passwords.txt",
        help="Recovered password dataset",
    )

    optional_audit_parser.add_argument(
        "-D",
        "--domain-admins",
        default="./ntds-organiser/domain-admins.txt",
        help="Domain Admin account list",
    )

    optional_audit_parser.add_argument(
        "-P",
        "--pass-policy",
        default="./ntds-organiser/domain-policy.txt",
        help="Domain password policy",
    )

    optional_audit_parser.add_argument(
        "-W",
        "--company-words",
        default="./ntds-organiser/company-words.txt",
        help="Organisation-related strings",
    )

    optional_audit_parser.add_argument(
        "-E",
        "--enabled-users",
        default="./ntds-organiser/enabled-users.txt",
        help="Enabled user accounts list",
    )

    audit_parser.set_defaults(
        func=run_audit_workflow,
    )

    #-----------------------------------------------
    # Organise module
    #-----------------------------------------------

    organise_parser = subparsers.add_parser(
        "organise",
        help="Process NTDS, BloodHound, and Hashcat data",
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
        default="ntds-organiser",
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
        help="Password recovery campaigns",
        formatter_class=CustomFormatter
    )

    crack_subparsers = crack_parser.add_subparsers(
        dest="crack_command",
        required=True,
    )

    #-----------------------------------------------
    # Crack run submodule
    #-----------------------------------------------

    run_parser = crack_subparsers.add_parser(
        "run",
        help="Execute a cracking campaign",
        formatter_class=CustomFormatter
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
        "--resume",
        action="store_true",
        help="Resume an interrupted campaign"
    )

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
        help="Display historical cracking statistics",
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
    # Crack estimate submodule
    #-----------------------------------------------

    estimate_parser = crack_subparsers.add_parser(
        "estimate",
        help="Estimate campaign duration",
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
    # Analyse module
    #-----------------------------------------------

    analyse_parser = subparsers.add_parser(
        "analyse",
        help="Analyse recovered passwords and generate reports",
        description=(
            "Analyse recovered NTLM and LM passwords, "
            "identify common weaknesses, and generate "
            "a Markdown report with findings and "
            "remediation guidance."
        ),
        formatter_class=CustomFormatter,
        epilog=dedent("""
        Example:

            password-audit analyse \\
                -M ntds-organiser/mapped-ntlm-passwords.txt
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
        required=True,
        help="Recovered NTLM passwords"
    )

    # Optional arguments
    optional_analyse_parser.add_argument(
        "-D",
        "--domain-admins",
        default="./ntds-organiser/domain-admins.txt",
        help="Domain Admin account list"
    )

    optional_analyse_parser.add_argument(
        "-P",
        "--pass-policy",
        default="./ntds-organiser/domain-policy.txt",
        help="Domain password policy"
    )

    optional_analyse_parser.add_argument(
        "-G",
        "--company-words",
        default="./ntds-organiser/company-words.txt",
        help="Organisation-specific password analysis terms"
    )

    optional_analyse_parser.add_argument(
        "-E",
        "--enabled-users",
        default="./ntds-organiser/enabled-users.txt",
        help="Enabled user accounts list"
    )

    optional_analyse_parser.add_argument(
        "-U",
        "--lm-users",
        default="./ntds-organiser/lm-users.txt",
        help="Accounts storing LM password hashes"
    )

    optional_analyse_parser.add_argument(
        "-L",
        "--mapped-lm-passwords",
        default="./ntds-organiser/mapped-lm-passwords.txt",
        help="Recovered LM passwords"
    )
    
    analyse_parser.set_defaults(
        func=run_password_analysis
    )

    #-----------------------------------------------
    # LM module
    #-----------------------------------------------

    lm_parser = subparsers.add_parser(
        "lm",
        help="LM password recovery and candidate generation",
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
                -L ntds-organiser/mapped-lm-passwords.txt
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
        default="ntds-organiser",
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
                -L ntds-organiser/mapped-lm-passwords.txt
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
        default="./ntds-organiser/domain-admins.txt",
        help="Domain Admin account list",
    )

    optional_lm_generate_parser.add_argument(
        "-O",
        "--output-dir",
        default="ntds-organiser",
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