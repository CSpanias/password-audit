"""
NTDS processing workflow.

This module provides reusable NTDS processing workflows
for dataset organisation, password mapping, and report
generation pipelines.
"""

from ntds.parsers import parse_ntds_file, load_bloodhound_zip, load_potfile, load_lm_results
from ntds.results import build_results
from ntds.exports import export_results


def organise_dataset(
    ntds_file,
    output_dir,
    bloodhound_file=None,
    potfile=None,
    username_filter=None,
    lm_results=None
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

    hash_lookup = None
    lm_lookup = None

    if potfile:
        # NTLM
        hash_lookup = load_potfile(potfile)

        # LM
        lm_lookup = load_lm_results(lm_results)

    results = build_results(
        entries=entries,
        username_filter=username_filter,
        users_json=users_json,
        groups_json=groups_json,
        domains_json=domains_json,
        hash_lookup=hash_lookup,
        lm_lookup=lm_lookup
    )

    export_results(results, output_dir)

    return results