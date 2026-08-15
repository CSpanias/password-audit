"""
LM Domain Administrator candidate generation.

This module generates LM Domain Administrator datasets
from recovered LM passwords and Domain Administrator
user lists.
"""

from pathlib import Path

from common.utils import write_lines
from common.console import info, summary
from analysis.parsers import load_list, load_passwords
from ntds.lm import build_lm_da_passwords, extract_lm_da_users, build_lm_candidates
from lm.workflow import map_lm_passwords


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
    info("LM Password Mapping")
    print()

    summary("Mapped LM Passwords", len(results["mapped_lm_passwords"]))

    print()
    summary("Output Directory", args.output_dir)

    print()


def run_lm_candidates(args):
    """
    Generate LM Domain Administrator candidate datasets.

    Args:
        args:
            Parsed command-line arguments.
    """

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    domain_admins = load_list(args.domain_admins)
    lm_passwords = load_passwords(args.mapped_lm_passwords)
    lm_da_passwords = build_lm_da_passwords(lm_passwords, domain_admins)
    lm_da_users = extract_lm_da_users(lm_da_passwords)
    lm_da_candidates = build_lm_candidates(lm_da_passwords)

    write_lines(output_dir / "lm-da-users.txt", lm_da_users)
    write_lines(output_dir / "lm-da-candidates.txt", lm_da_candidates)
    write_lines(
        output_dir / "lm-da-passwords.txt",
        [
            f"{record['username']}:{record['password']}"
            for record in lm_da_passwords
        ],
    )

    print()
    info("LM Candidate Generation")
    print()

    summary("LM DA Users", len(lm_da_users))
    summary("LM DA Candidates", len(lm_da_candidates))

    print()
    summary("Output Directory", output_dir)

    print()