"""
Password Audit command-line interface.

This module provides the primary command-line entry point and
dispatches execution to individual framework components.
"""

import argparse

from cli.passwords import run_password_analysis
from cli.ntds import run_ntds_organiser


def main():
    """
    Execute the Password Audit command-line interface.

    Command-line arguments are parsed and execution is
    dispatched to the selected framework component.

    Returns:
        None
    """

    parser = argparse.ArgumentParser(
        description="Password Audit Framework"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # NTDS Organiser
    ntds_parser = subparsers.add_parser(
        "ntds",
        help="Process NTDS, BloodHound, and Hashcat data",
    )

    ntds_parser.add_argument(
        "-n",
        "--ntds",
        required=True,
        help="NTDS dump file"
    )

    ntds_parser.add_argument(
        "-o",
        "--output",
        default="ntds-organiser",
        help="Output directory"
    )

    ntds_parser.add_argument(
        "-f",
        "--filter",
        help="Testing account filter"
    )

    ntds_parser.add_argument(
        "-b",
        "--bloodhound",
        help="BloodHound zip file"
    )

    ntds_parser.add_argument(
        "-p",
        "--potfile",
        help="Hashcat potfile"
    )

    ntds_parser.set_defaults(
        func=run_ntds_organiser
    )

    # Password Analysis
    password_parser = subparsers.add_parser(
        "passwords",
        help="Analyse recovered passwords and generate reports",
    )
    
    password_parser.add_argument(
        "-M",
        "--mapped-passwords",
        required=True,
        help="Recovered NTLM passwords file"
    )

    password_parser.add_argument(
        "-A",
        "--domain-admins",
        default="./ntds-organiser/domain-admins.txt",
        help="Domain Admin account list"
    )

    password_parser.add_argument(
        "-P",
        "--pass-policy",
        default="./ntds-organiser/domain-policy.txt",
        help="Domain password policy"
    )

    password_parser.add_argument(
        "-C",
        "--company-words",
        default="./ntds-organiser/company-words.txt",
        help="Organisation-specific password analysis terms"
    )

    password_parser.add_argument(
        "-E",
        "--enabled-users",
        default="./ntds-organiser/enabled-users.txt",
        help="Enabled user accounts list"
    )

    password_parser.set_defaults(
        func=run_password_analysis
    )

    args = parser.parse_args()

    args.func(args)


if __name__ == "__main__":
    main()