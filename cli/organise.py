"""
NTDS Organiser command-line workflow.

This module coordinates NTDS parsing, analysis, password
mapping, dataset export, and summary generation.
"""


from pathlib import Path
from common.console import info, summary, warn
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
    info("NTDS Organiser")

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

    print()

    summary("Enabled Accounts", len(results["enabled"]))
    summary("Disabled Accounts", len(results["disabled"]))
    summary("User Accounts", len(results["enabled_users"]))
    summary("Machine Accounts", len(results["machines"]))
    summary("NTLM Hashes", len(results["ntlm_hashes"]))

    if results["lm_hashes"]:
        summary("LM Hashes", len(results["lm_hashes"]))

    summary("Domain Admins", len(results["domain_admins"]))
    summary("Company Words", len(results["company_words"]))
    
    if results["mapped_ntlm_passwords"]:
        summary("Mapped Passwords", len(results["mapped_ntlm_passwords"]))

    # if results["mapped_lm_passwords"]:
    #     summary("Mapped LM Passwords", len(results["mapped_lm_passwords"]))

    # if results["mapped_lm_da_passwords"]:
    #     summary("LM Domain Admins", len(results["mapped_lm_da_passwords"]))

    # if results["lm_da_candidates"]:
    #     summary("LM DA Candidates", len(results["lm_da_candidates"]))

    print()
    summary("Output Directory", output_dir)