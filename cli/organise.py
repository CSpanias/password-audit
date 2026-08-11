"""
NTDS Organiser command-line workflow.

This module coordinates NTDS parsing, analysis, password
mapping, dataset export, and summary generation.
"""


from pathlib import Path

from common.console import (
    info,
    warn,
    summary,
)

from ntds.parsers import (
    parse_ntds_file,
    load_bloodhound_zip,
    load_potfile,
)

from ntds.results import (
    build_results,
)

from ntds.exports import (
    export_results,
)


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

    info("NTDS Organiser")

    entries = parse_ntds_file(args.ntds)

    users_json = None
    groups_json = None
    domains_json = None

    if args.bloodhound:

        users_json, groups_json, domains_json = (
            load_bloodhound_zip(args.bloodhound)
        )

        if users_json is None:
            warn("users.json not found")

        if groups_json is None:
            warn("groups.json not found")

        if domains_json is None:
            warn("domains.json not found")

    hash_lookup = None

    if args.potfile:
        hash_lookup = load_potfile(args.potfile)

    results = build_results(
        entries=entries,
        username_filter=args.filter,
        users_json=users_json,
        groups_json=groups_json,
        domains_json=domains_json,
        hash_lookup=hash_lookup,
    )

    filtered_users = results["filtered_users"]

    if filtered_users:
        warn(f"Filtered Accounts ({len(filtered_users)})")

        for account in filtered_users:
            print(f" - {account['username']}")

        print()

    export_results(results, output_dir)

    print()

    summary("Enabled Accounts", len(results["enabled"]))
    summary("Disabled Accounts", len(results["disabled"]))
    summary("User Accounts", len(results["enabled_users"]))
    summary("Machine Accounts", len(results["machines"]))
    summary("NTLM Hashes", len(results["ntlm_hashes"]))
    summary("LM Hashes", len(results["lm_hashes"]))

    if results["company_words"]:
        summary("Company Words", len(results["company_words"]))

    if results["domain_admins"]:
        summary("Domain Admins", len(results["domain_admins"]))

    if results["mapped_ntlm_passwords"]:
        summary("Mapped Passwords", len(results["mapped_ntlm_passwords"]))

    if results["mapped_lm_passwords"]:
        summary("Mapped LM Passwords", len(results["mapped_lm_passwords"]))

    if results["mapped_lm_da_passwords"]:
        summary("LM Domain Admins", len(results["mapped_lm_da_passwords"]))

    if results["lm_da_candidates"]:
        summary("LM DA Candidates", len(results["lm_da_candidates"]))

    print()

    summary("Output Directory", output_dir)