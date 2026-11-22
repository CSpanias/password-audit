"""
NTDS processing workflow.

This module provides reusable NTDS processing workflows
for dataset organisation, password mapping, and report
generation pipelines.
"""

import json

from ntds.parsers import parse_ntds_file, load_bloodhound_zip, load_potfile
from ntds.analysis import extract_privileged_users, single_bloodhound_domain
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
    source_domain_sid=None,
    progress_callback=None,
    potfile_progress_callback=None,
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
            Optional callback to choose a source when multiple domains are collected.

        confirmed_domain_sid:
            Previously user-confirmed domain SID, revalidated against the export.

        source_domain_sid:
            Previously detected domain SID, revalidated against the export.

        progress_callback:
            Optional callback receiving the current processing step.

        potfile_progress_callback:
            Optional callback receiving potfile bytes read and total bytes.

    Returns:
        dict:
            Processed dataset results.
    """

    if progress_callback:
        progress_callback("Loading NTDS data")
    entries = parse_ntds_file(ntds_file)

    users_json = groups_json = domains_json = None

    if bloodhound_file:
        if progress_callback:
            progress_callback("Loading BloodHound data")
        users_json, groups_json, domains_json = (
            load_bloodhound_zip(bloodhound_file)
        )

    # NTLM hashes
    hash_lookup = None
    
    if potfile:
        if progress_callback:
            progress_callback("Reading NTLM potfile")
        hash_lookup = load_potfile(potfile, progress_callback=potfile_progress_callback)

    if progress_callback:
        progress_callback("Mapping NTLM passwords")
    results = build_results(
        entries=entries,
        username_filter=username_filter,
        users_json=users_json,
        groups_json=groups_json,
        domains_json=domains_json,
        hash_lookup=hash_lookup,
    )

    records = domains_json.get("data", []) if domains_json else []
    candidates = [
        domain for record in records
        if (domain := single_bloodhound_domain(
            {"data": [record]}, users_json, groups_json
        )) is not None
    ]
    if confirmed_domain_sid and source_domain_sid:
        raise ValueError("Only one previously selected NTDS domain can be supplied.")
    previous_sid = confirmed_domain_sid or source_domain_sid
    domain = None
    user_confirmed = False
    if previous_sid:
        if source_domain_sid and (len(records) != 1 or len(candidates) != 1):
            raise ValueError("The detected NTDS domain no longer matches the BloodHound data.")
        domain = next(
            (candidate for candidate in candidates if candidate["sid"] == previous_sid.upper()),
            None,
        )
        if domain is None:
            raise ValueError("The selected NTDS domain no longer matches the BloodHound data.")
        user_confirmed = bool(confirmed_domain_sid)
    elif len(records) == 1 and len(candidates) == 1:
        domain = candidates[0]
    elif len(records) > 1 and confirm_domain is not None:
        for candidate in candidates:
            confirmation = confirm_domain(candidate)
            if confirmation is None:
                break
            if confirmation:
                domain = candidate
                user_confirmed = True
                break

    if domain:
        scoped = extract_privileged_users(
            users_json, groups_json, results["enabled_users"], domain["sid"]
        )
        scoped["source_domain"] = domain
        if user_confirmed:
            scoped["confirmed_domain"] = domain
        results["privileged_users"] = scoped
    elif results["privileged_users"]["status"] != "unavailable":
        privileged = results["privileged_users"]
        privileged["accounts"] = []
        privileged["status"] = "incomplete"
        privileged["warnings"].append(
            "The NTDS source domain could not be determined from the BloodHound data; "
            "privileged account matches were omitted."
        )

    results["domain_admins_available"] = bool(users_json and groups_json)

    if progress_callback:
        progress_callback("Exporting NTLM datasets")
    export_results(results, output_dir)

    (output_dir / "privileged-users.json").write_text(
        json.dumps(results["privileged_users"], indent=2) + "\n",
        encoding="utf-8",
    )

    return results