"""
LM candidate generation.

This module generates LM candidate datasets from recovered
LM passwords, optionally filtered to Domain Administrators.
"""

from pathlib import Path
from rich.table import Table

from common.utils import write_lines
from common.console import console, ok, warn
from analysis.parsers import load_list, load_passwords
from ntds.lm import build_lm_da_passwords, extract_lm_da_users, build_lm_candidates
from lm.workflow import map_lm_passwords


class LMCandidateInputError(ValueError):
    """A required LM candidate input file is missing."""


def run_lm_mapping(args):
    """
    Execute the LM password mapping workflow.

    Reconstruct recovered LM passwords from Hashcat
    output and map them back to user accounts within
    the NTDS dataset.

    Args:
    args:
    Parsed command-line arguments.

    Returns:
    None
    """

    results = map_lm_passwords(
        ntds_file=args.ntds,
        potfile=args.potfile,
        lm_results=args.lm_results,
        output_dir=args.output_dir,
        )

    print()
    table = Table(
        title="LM Password Mapping",
        title_style="bold cyan",
    )

    table.add_column("Object")
    table.add_column("Value", justify="right")

    table.add_row(
        "Mapped LM Passwords",
        str(len(results["mapped_lm_passwords"]))
    )

    console.print(table)

    print()
    ok(f"Output Directory: {args.output_dir}")


def run_lm_candidates(args):
    """
    Generate LM candidate datasets, optionally limited to Domain Administrators.

    Args:
        args:
            Parsed command-line arguments.
    """

    mapped_path = Path(args.mapped_lm_passwords)
    admins_path = (
        Path(args.domain_admins)
        if args.domain_admins is not None
        else mapped_path.parent / "domain-admins.txt"
    )

    try:
        lm_passwords = load_passwords(mapped_path)
    except FileNotFoundError as exc:
        raise LMCandidateInputError(
            f"Mapped LM passwords file not found: {mapped_path}."
        ) from exc
    try:
        domain_admins = load_list(admins_path)
    except FileNotFoundError as exc:
        if args.domain_admins is not None:
            raise LMCandidateInputError(
                f"Domain Administrator list not found: {admins_path}."
            ) from exc
        domain_admins = None

    if domain_admins is None:
        warn(
            f"Domain Administrator list not found: {admins_path}. "
            "Generating candidates for all mapped LM passwords."
        )
        selected_passwords = lm_passwords
        users = sorted({record["username"] for record in selected_passwords})
        prefix = "lm-all"
        label = "LM"
    else:
        selected_passwords = build_lm_da_passwords(lm_passwords, domain_admins)
        users = extract_lm_da_users(selected_passwords)
        prefix = "lm-da"
        label = "LM DA"

    candidates = build_lm_candidates(selected_passwords)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    write_lines(output_dir / f"{prefix}-users.txt", users)
    write_lines(output_dir / f"{prefix}-candidates.txt", candidates)
    write_lines(
        output_dir / f"{prefix}-passwords.txt",
        [
            f"{record['username']}:{record['password']}"
            for record in selected_passwords
        ],
    )

    print()
    table = Table(
        title="LM Candidate Generation",
        title_style="bold cyan",
    )

    table.add_column("Object")
    table.add_column("Value", justify="right")

    table.add_row(
        f"{label} Users",
        str(len(users))
    )

    table.add_row(
        f"{label} Candidates",
        str(len(candidates))
    )

    console.print(table)

    print()
    ok(f"Output Directory: {output_dir}")