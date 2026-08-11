"""
NTDS analysis functions.

This module contains analysis routines used to derive
security-relevant datasets from parsed NTDS and BloodHound
data. Functions focus on extracting hashes, identifying
privileged accounts, deriving organisation-related terms,
and extracting password policy information.

Functions in this module should analyse data and return
results. File loading and export operations should be
handled elsewhere.
"""

import re
from ntds.constants import (
    LM_EMPTY,
)



def extract_ntlm_hashes(entries):
    """
    Extract unique NTLM hashes from NTDS entries.

    Duplicate hashes are removed and results are returned
    in sorted order to provide deterministic output.

    Args:
        entries (list):
            Parsed NTDS account records.

    Returns:
        list:
            Unique NTLM hashes.
    """

    return sorted({
        e["ntlm"]
        for e in entries
    })


def extract_lm(entries):
    """
    Identify accounts using LM hashes.

    Accounts containing the known empty LM hash are excluded.
    Both affected accounts and unique LM hashes are returned.

    Args:
        entries (list):
            Parsed NTDS account records.

    Returns:
        tuple:
            - list: Accounts containing LM hashes.
            - list: Unique LM hashes.
    """

    lm_users = [
        e for e in entries
        if e["lm"] != LM_EMPTY
    ]

    lm_hashes = sorted({
        e["lm"]
        for e in lm_users
    })

    return lm_users, lm_hashes


def extract_company_words(domains):
    """
    Derive organisation-related terms from domain names.

    Top-level domains are removed and resulting names are
    further split into component words using non-alphanumeric
    delimiters. Terms shorter than three characters are
    excluded.

    Example:

        cia-medical.com

    Produces:

        cia-medical
        cia
        medical

    Args:
        domains (list):
            Domain names.

    Returns:
        list:
            Organisation-related terms.
    """

    words = set()

    for domain in domains:
        domain = domain.lower().strip()

        if not domain:
            continue

        # Remove TLD
        base = domain.rsplit(".", 1)[0]

        # Full company string
        words.add(base)

        # Special character split
        for token in re.split(r"[^a-z0-9]+", base):

            token = token.strip()

            if len(token) >= 3:
                words.add(token)

    return sorted(words)


def extract_username_domains(entries):
    """
    Extract domain prefixes from usernames.

    Usernames in DOMAIN\\username format are processed and
    unique domain values are returned.

    Args:
        entries (list):
            Parsed NTDS account records.

    Returns:
        list:
            Unique username domains.
    """

    domains = set()

    for entry in entries:
        username = entry["username"]

        if "\\" not in username:
            continue

        prefix = username.split("\\", 1)[0]

        if "." in prefix:
            domains.add(prefix)

    return sorted(domains)


def extract_domain_admins(users_data, groups_data):
    """
    Identify Domain Administrator accounts from BloodHound data.

    Members of groups whose SID ends in '-512' are treated as
    Domain Administrators in accordance with Active Directory
    conventions.

    Args:
        users_data (dict):
            BloodHound users.json data.

        groups_data (dict):
            BloodHound groups.json data.

    Returns:
        list:
            Domain Administrator usernames.
    """

    if not users_data or not groups_data:
        return []

    users_lookup = {
        user["ObjectIdentifier"]: user
        for user in users_data["data"]
    }

    domain_admins = []

    for group in groups_data["data"]:

        if not group["ObjectIdentifier"].endswith("-512"):
            continue

        for member in group.get("Members", []):

            sid = member["ObjectIdentifier"]

            if sid not in users_lookup:
                continue

            user = users_lookup[sid]
            username = user["Properties"].get("samaccountname")

            if username:
                domain_admins.append(username)

    return sorted(set(domain_admins))

def extract_domain_policy(domains_data):
    """
    Extract password policy information from BloodHound data.

    Relevant password policy values are extracted from the
    domain object and returned in a simplified dictionary
    structure suitable for reporting and analysis.

    Args:
        domains_data (dict):
            BloodHound domains.json data.

    Returns:
        dict:
            Domain password policy information.
    """

    if not domains_data:
        return {}

    domain = domains_data["data"][0]

    props = domain["Properties"]

    return {
        "domain": props.get("domain"),
        "minpwdlength": props.get("minpwdlength"),
        "pwdhistorylength": props.get("pwdhistorylength"),
        "lockoutthreshold": props.get("lockoutthreshold"),
        "minpwdage": props.get("minpwdage"),
        "maxpwdage": props.get("maxpwdage")
    }