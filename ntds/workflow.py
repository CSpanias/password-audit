"""
NTDS processing workflow.

This module provides reusable NTDS processing workflows
for dataset organisation, password mapping, and report
generation pipelines.
"""

import json

from ntds.parsers import parse_ntds_file, load_bloodhound_zip, load_potfile
from ntds.analysis import (
    UNCONFIRMED_DOMAIN_WARNING,
    extract_privileged_users,
    single_bloodhound_domain,
)
from ntds.results import build_results
from ntds.exports import export_results


def organise_dataset(
    ntds_file,
    output_dir,
    bloodhound_file=None,
    potfile=None,
    username_filter=None,
    confirm_domain=None,
    confirmed_domain_sid=None,
):
    """
    Process an NTDS dataset and export results.

    Args:
        ntds_file:
            NTDS dataset.

        output_dir:
            Output directory.

        bloodhound_file:
            BloodHound ZIP export.

        potfile:
            Hashcat potfile used for password mapping.

        username_filter:
            Usernames to exclude from processing.

        confirm_domain:
            Optional callback to confirm the single BloodHound source domain.

        confirmed_domain_sid:
            Previously confirmed domain SID, revalidated against the export.

    Returns:
        dict:
            Processed dataset results.
    """

    entries = parse_ntds_file(ntds_file)

    users_json = groups_json = domains_json = None

    if bloodhound_file:
        users_json, groups_json, domains_json = (
            load_bloodhound_zip(bloodhound_file)
        )

    # NTLM hashes
    hash_lookup = None
    
    if potfile:
        
        hash_lookup = load_potfile(potfile)

    results = build_results(
        entries=entries,
        username_filter=username_filter,
        users_json=users_json,
        groups_json=groups_json,
        domains_json=domains_json,
        hash_lookup=hash_lookup,
    )

    domain = single_bloodhound_domain(domains_json, users_json, groups_json)
    if confirmed_domain_sid and (
        domain is None or domain["sid"] != confirmed_domain_sid.upper()
    ):
        raise ValueError("The confirmed NTDS domain no longer matches the BloodHound data.")
    unconfirmed = any(
        warning.endswith(UNCONFIRMED_DOMAIN_WARNING)
        for warning in results["privileged_users"]["warnings"]
    )
    if domain and (confirmed_domain_sid or (confirm_domain is not None and unconfirmed)):
        scoped = extract_privileged_users(
            users_json, groups_json, results["enabled_users"], domain["sid"]
        )
        if confirmed_domain_sid or (
            scoped != results["privileged_users"] and confirm_domain(domain)
        ):
            scoped["confirmed_domain"] = domain
            results["privileged_users"] = scoped

    results["domain_admins_available"] = bool(users_json and groups_json)

    export_results(results, output_dir)

    (output_dir / "privileged-users.json").write_text(
        json.dumps(results["privileged_users"], indent=2) + "\n",
        encoding="utf-8",
    )

    return results