"""
LM password analysis functions.

This module contains functionality relating to LM password
recovery, candidate generation, and Domain Administrator
identification based on recovered LM credentials.

Functions in this module should focus on LM-specific
processing and avoid parsing or export operations.
"""

from itertools import product
from common.utils import normalize_username


# ---------------------------------------------------------------------------
# LM Candidate Generation
# ---------------------------------------------------------------------------

def lm_variants(password):
    """
    Generate case permutations of an LM password.

    LM hashes are case-insensitive. This function generates
    all possible case variations for a recovered password to
    assist with password recovery and validation activities.

    Args:
        password (str):
            Recovered LM password.

    Yields:
        str:
            Candidate password variant.
    """

    chars = [
        (c.lower(), c.upper()) if c.isalpha() else (c,)
        for c in password.strip()
    ]

    for candidate in product(*chars):
        yield "".join(candidate)


def build_lm_candidates(lm_passwords):
    """
    Generate candidate passwords from recovered LM passwords.

    Args:
        lm_passwords (list):
            Recovered LM password records containing 
            username and password fields.

    Returns:
        list:
            Unique candidate passwords.
    """

    candidates = set()

    for record in lm_passwords:
        password = record["password"]

        if not password:
            continue

        for candidate in lm_variants(password):
            candidates.add(candidate)

    return sorted(candidates)


# ---------------------------------------------------------------------------
# Domain Administrator Analysis
# ---------------------------------------------------------------------------

def build_lm_da_passwords(lm_passwords, domain_admins):
    """
    Identify recovered LM passwords belonging to Domain
    Administrator accounts.

    Args:
        lm_passwords (list):
            Recovered LM password records containing 
            username and password fields.

        domain_admins (list):
            Domain Administrator usernames.

    Returns:
        list:
            LM password records associated with Domain
            Administrator accounts.
    """

    da_set = {
        normalize_username(username)
        for username in domain_admins
    }

    return [
        record
        for record in lm_passwords
        if normalize_username(
            record["username"]
        ) in da_set
    ]


def extract_lm_da_users(lm_da_passwords):
    """
    Extract Domain Administrator usernames from recovered
    LM password mappings.

    Args:
        lm_da_passwords (list):
            Domain Administrator LM password mappings.

    Returns:
        list:
            Unique Domain Administrator usernames.
    """

    return sorted({
        normalize_username(
            record["username"]
        )
        for record in lm_da_passwords
    })