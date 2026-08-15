"""
NTDS result generation.

This module coordinates NTDS analysis functions and
constructs standardised result structures consumed by
export and reporting components.
"""

from ntds.filters import (
    get_enabled,
    get_disabled,
    get_machines,
    get_users,
    apply_filter,
    apply_username_filter,
)

from ntds.analysis import (
    extract_ntlm_hashes,
    extract_lm,
    extract_company_words,
    extract_username_domains,
    extract_domain_admins,
    extract_domain_policy,
)

from ntds.mapping import map_passwords, map_lm_passwords
from ntds.lm import build_lm_candidates, build_lm_da_passwords, extract_lm_da_users


def build_results(
    entries,
    username_filter=None,
    users_json=None,
    groups_json=None,
    domains_json=None,
    hash_lookup=None,
    lm_lookup=None,
):
    """
    Build the complete NTDS analysis results dataset.

    Parsed NTDS entries are filtered, analysed, enriched
    with BloodHound data where available, and optionally
    mapped to recovered plaintext passwords.

    Args:
        entries (list):
            Parsed NTDS account records.

        username_filter (str):
            Comma-separated username filters.

        users_json (dict):
            BloodHound users.json data.

        groups_json (dict):
            BloodHound groups.json data.

        domains_json (dict):
            BloodHound domains.json data.

        hash_lookup (dict):
            Hash-to-password mapping loaded from a
            Hashcat potfile.

    Returns:
        dict:
            Standardised NTDS analysis results.
    """

    # Split enabled accounts into users and machines.
    enabled = get_enabled(entries)
    disabled = get_disabled(entries)
    machines = get_machines(enabled)
    users = get_users(enabled)
    
    # Exclude testing accounts from the user dataset.
    users, filtered = apply_filter(users, username_filter)

    # Recalculate enabled account totals after filtering.
    enabled = users + machines

    ntlm_hashes = extract_ntlm_hashes(users)
    lm_users, lm_hashes = extract_lm(users)

    domain_admins: list = []
    policy: dict = {}
    company_words = set()

    if users_json and groups_json:
        domain_admins = extract_domain_admins(users_json, groups_json,)
        domain_admins = apply_username_filter(domain_admins, username_filter)

    if domains_json:
        policy = extract_domain_policy(domains_json)

        if policy and policy.get("domain"):
            company_words.update(extract_company_words([policy["domain"]]))

    username_domains = extract_username_domains(entries)
    company_words.update(extract_company_words(username_domains))

    mapped_ntlm_passwords = []
    mapped_lm_passwords = []

    if hash_lookup:
        mapped_ntlm_passwords = map_passwords(users, hash_lookup)

    if lm_lookup:
        mapped_lm_passwords = map_lm_passwords(lm_users, lm_lookup)

    mapped_lm_da_passwords = []
    lm_da_users = []
    lm_da_candidates = []

    if mapped_lm_passwords and domain_admins:
        mapped_lm_da_passwords = build_lm_da_passwords(mapped_lm_passwords,domain_admins)

        if mapped_lm_da_passwords:
            lm_da_users = extract_lm_da_users(mapped_lm_da_passwords)
            lm_da_candidates = build_lm_candidates(mapped_lm_da_passwords)

    results = {
        "entries": entries,
        "enabled": enabled,
        "disabled": disabled,
        "machines": machines,
        "enabled_users": users,
        "filtered_users": filtered,
        "ntlm_hashes": ntlm_hashes,
        "lm_users": lm_users,
        "lm_hashes": lm_hashes,
        "domain_admins": domain_admins,
        "policy": policy,
        "company_words": sorted(company_words),
        "mapped_ntlm_passwords": mapped_ntlm_passwords,
        "mapped_lm_passwords": mapped_lm_passwords,
        "mapped_lm_da_passwords": mapped_lm_da_passwords,
        "lm_da_users": lm_da_users,
        "lm_da_candidates": lm_da_candidates,
    }

    return results