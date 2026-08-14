"""
Password Audit command-line interface.

This module provides the primary command-line entry point and
dispatches execution to individual framework components.
"""

import argparse

from cli.organise import run_ntds_organiser
from cli.crack import run_cracking_campaign
from cli.analyse import run_password_analysis
from cli.audit import run_audit_workflow
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

    parser = argparse.ArgumentParser(
        description="Password Audit Framework",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    #-----------------------------------------------
    # Audit
    #-----------------------------------------------

    audit_parser = subparsers.add_parser(
        "audit",
        help="Execute an end-to-end password audit",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    audit_parser.add_argument(
        "-N",
        "--ntds",
        required=True,
        help="Secretsdump NTDS file"
    )

    audit_parser.add_argument(
        "-B",
        "--bloodhound",
        help="BloodHound ZIP export"
    )

    audit_parser.add_argument(
        "-C",
        "--campaign",
        required=True,
        help="Campaign configuration file"
    )

    audit_parser.add_argument(
        "-G",
        "--campaign-name",
        required=True,
        help="Campaign identifier"
    )

    audit_parser.add_argument(
        "-M",
        "--mapped-passwords",
        default="./ntds-organiser/mapped-ntlm-passwords.txt",
        help="Recovered username:password dataset"
    )

    audit_parser.add_argument(
        "-A",
        "--domain-admins",
        default="./ntds-organiser/domain-admins.txt",
        help="Domain Admin account list"
    )

    audit_parser.add_argument(
        "-P",
        "--pass-policy",
        default="./ntds-organiser/domain-policy.txt",
        help="Domain password policy"
    )

    audit_parser.add_argument(
        "-W",
        "--company-words",
        default="./ntds-organiser/company-words.txt",
        help="Organisation-specific password analysis terms"
    )

    audit_parser.add_argument(
        "-E",
        "--enabled-users",
        default="./ntds-organiser/enabled-users.txt",
        help="Enabled user accounts list"
    )

    audit_parser.set_defaults(
        func=run_audit_workflow,
    )

    #-----------------------------------------------
    # NTDS Organiser
    #-----------------------------------------------

    organise_parser = subparsers.add_parser(
        "organise",
        help="Process NTDS, BloodHound, and Hashcat data",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    organise_parser.add_argument(
        "-N",
        "--ntds",
        required=True,
        help="Secretsdump NTDS file"
    )

    organise_parser.add_argument(
        "-O",
        "--output",
        default="ntds-organiser",
        help="Output directory"
    )

    organise_parser.add_argument(
        "-F",
        "--filter",
        help="Comma-separated testing account filters"
    )

    organise_parser.add_argument(
        "-B",
        "--bloodhound",
        help="BloodHound ZIP export"
    )

    organise_parser.add_argument(
        "-P",
        "--potfile",
        help="Hashcat potfile containing recovered passwords"
    )

    organise_parser.add_argument(
        "-L",
        "--lm-results",
        help="LM recovery results generated using hashcat --show",
    )

    organise_parser.set_defaults(
        func=run_ntds_organiser
    )

    #-----------------------------------------------
    # Hashcat Scheduler
    #-----------------------------------------------

    crack_parser = subparsers.add_parser(
        "crack",
        help="Password recovery campaigns",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    crack_subparsers = crack_parser.add_subparsers(
        dest="crack_command",
        required=True,
    )

    run_parser = crack_subparsers.add_parser(
        "run",
        help="Execute a cracking campaign",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    run_parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume an interrupted campaign"
    )

    run_parser.add_argument(
        "-C",
        "--campaign",
        required=True,
        help="Campaign configuration file"
    )

    run_parser.add_argument(
        "-H",
        "--hashes",
        required=True,
        help="Hash file to crack",
    )

    run_parser.add_argument(
        "-G",
        "--campaign-name",
        required=True,
        help="Campaign identifier"
    )

    run_parser.add_argument(
        "--debug",
        action="store_true",
        help="Display verbose Hashcat output",
    )

    run_parser.set_defaults(
        func=run_cracking_campaign,
    )

    #-----------------------------------------------
    # Hashcat Scheduler stats subcommand
    #-----------------------------------------------

    stats_parser = crack_subparsers.add_parser(
        "stats",
        help="Display historical cracking statistics",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    stats_parser.set_defaults(
        func=print_phase_statistics,
    )

    #-----------------------------------------------
    # Hashcat Scheduler estimate subcommand
    #-----------------------------------------------

    estimate_parser = crack_subparsers.add_parser(
        "estimate",
        help="Estimate campaign duration",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    estimate_parser.add_argument(
        "-C",
        "--campaign",
        required=True,
        help="Campaign configuration file",
    )

    estimate_parser.set_defaults(
        func=print_campaign_estimate,
    )

    #-----------------------------------------------
    # Password Analysis
    #-----------------------------------------------

    analyse_parser = subparsers.add_parser(
        "analyse",
        help="Analyse recovered passwords and generate reports",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    analyse_parser.add_argument(
        "-M",
        "--mapped-passwords",
        required=True,
        help="Recovered NTLM passwords"
    )

    analyse_parser.add_argument(
        "-A",
        "--domain-admins",
        default="./ntds-organiser/domain-admins.txt",
        help="Domain Admin account list"
    )

    analyse_parser.add_argument(
        "-P",
        "--pass-policy",
        default="./ntds-organiser/domain-policy.txt",
        help="Domain password policy"
    )

    analyse_parser.add_argument(
        "-G",
        "--company-words",
        default="./ntds-organiser/company-words.txt",
        help="Organisation-specific password analysis terms"
    )

    analyse_parser.add_argument(
        "-E",
        "--enabled-users",
        default="./ntds-organiser/enabled-users.txt",
        help="Enabled user accounts list"
    )

    analyse_parser.add_argument(
        "-U",
        "--lm-users",
        default="./ntds-organiser/lm-users.txt",
        help="Accounts storing LM password hashes"
    )

    analyse_parser.add_argument(
        "-L",
        "--mapped-lm-passwords",
        default="./ntds-organiser/mapped-lm-passwords.txt",
        help="Recovered LM passwords"
    )
    

    analyse_parser.set_defaults(
        func=run_password_analysis
    )

    args = parser.parse_args()

    args.func(args)


if __name__ == "__main__":
    main()