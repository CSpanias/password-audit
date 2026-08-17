"""
NTDS Organiser command-line workflow.

This module coordinates NTDS parsing, analysis, password
mapping, dataset export, and summary generation.
"""

from rich.panel import Panel
from rich.table import Table
from pathlib import Path

from common.console import console, info, ok, warn
from ntds.workflow import organise_dataset


def run_ntds_organiser(args):
    """
    Execute the NTDS Organiser workflow.

    Args:
        args:
            Parsed command-line arguments.

    Returns:
        None
    """
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print()
    info("Password Audit Organise")
    print()

    results = organise_dataset(
        ntds_file=args.ntds,
        output_dir=output_dir,
        bloodhound_file=args.bloodhound,
        potfile=args.potfile,
        username_filter=args.filter,
    )

    # Print testing accounts to stdout
    filtered_users = results["filtered_users"]

    if filtered_users:

        warn(f"Filtered Accounts ({len(filtered_users)})")

        for account in filtered_users:
            print(f" - {account['username']}")

        print()

    table = Table(
        title="NTDS Summary", 
        title_style="bold cyan",
    )

    table.add_column("Object")
    table.add_column("Value", justify="right")

    table.add_row(
        "Enabled Accounts",
        str(len(results["enabled"]))
    )

    table.add_row(
        "Disabled Accounts",
        str(len(results["disabled"]))
    )

    table.add_row(
        "User Accounts",
        str(len(results["enabled_users"]))
    )

    table.add_row(
        "Machine Accounts",
        str(len(results["machines"]))
    )

    table.add_row(
        "NTLM Hashes",
        str(len(results["ntlm_hashes"]))
    )

    if results["lm_hashes"]:
        table.add_row(
            "LM Hashes",
            str(len(results["lm_hashes"]))
        )

    table.add_row(
        "Domain Admins",
        str(len(results["domain_admins"]))
    )

    table.add_row(
        "Company Words",
        str(len(results["company_words"]))
    )

    if results["mapped_ntlm_passwords"]:
        table.add_row(
            "Mapped Passwords",
            str(len(results["mapped_ntlm_passwords"]))
        )

    console.print(table)

    print()
    ok(f"Output written to: {output_dir}")