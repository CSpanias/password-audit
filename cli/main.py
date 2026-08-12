"""
Password Audit command-line interface.

This module provides the primary command-line entry point and
dispatches execution to individual framework components.
"""

import argparse
from cli.organise import run_ntds_organiser
from cli.crack import run_cracking_campaign
from cli.analyse import run_password_analysis


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

    # NTDS Organiser
    organise_parser = subparsers.add_parser(
        "organise",
        help="Process NTDS, BloodHound, and Hashcat data",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    organise_parser.add_argument(
        "-n",
        "--ntds",
        required=True,
        help="Secretsdump NTDS file"
    )

    organise_parser.add_argument(
        "-o",
        "--output",
        default="ntds-organiser",
        help="Output directory"
    )

    organise_parser.add_argument(
        "-f",
        "--filter",
        help="Comma-separated testing account filters"
    )

    organise_parser.add_argument(
        "-b",
        "--bloodhound",
        help="BloodHound ZIP export"
    )

    organise_parser.add_argument(
        "-p",
        "--potfile",
        help="Hashcat potfile containing recovered passwords"
    )

    organise_parser.set_defaults(
        func=run_ntds_organiser
    )

    crack_parser = subparsers.add_parser(
        "crack",
        help="Execute Hashcat cracking campaigns",
    )

    crack_parser.add_argument(
        "-C",
        "--campaign",
        required=True,
        help="Campaign configuration file"
    )

    crack_parser.add_argument(
        "-H",
        "--hashes",
        required=True,
        help="Hash dataset"
    )

    crack_parser.add_argument(
        "-N",
        "--campaign-name",
        required=True,
        help="Campaign name"
    )

    crack_parser.add_argument(
        "--debug",
        action="store_true",
        help="Show Hashcat commands and verbose output"
    )

    crack_parser.set_defaults(
        func=run_cracking_campaign
    )

    # Password Analysis
    analyse_parser = subparsers.add_parser(
        "analyse",
        help="Analyse recovered passwords and generate reports",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    analyse_parser.add_argument(
        "-M",
        "--mapped-passwords",
        required=True,
        help="Recovered username:password dataset"
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
        "-C",
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

    analyse_parser.set_defaults(
        func=run_password_analysis
    )

    args = parser.parse_args()

    args.func(args)


if __name__ == "__main__":
    main()