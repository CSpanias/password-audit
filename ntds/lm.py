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


def build_lm_candidates(mapped_lm_passwords):
    """
    Generate candidate passwords from recovered LM passwords.

    Args:
        mapped_lm_passwords (list):
            Recovered LM username:password mappings.

    Returns:
        list:
            Unique candidate passwords.
    """

    candidates = set()

    for entry in mapped_lm_passwords:

        try:
            _, password = entry.split(":", 1)

        except ValueError:
            continue

        for candidate in lm_variants(password):
            candidates.add(candidate)

    return sorted(candidates)


# ---------------------------------------------------------------------------
# Domain Administrator Analysis
# ---------------------------------------------------------------------------

def build_lm_da_passwords(
    mapped_lm_passwords,
    domain_admins,
):
    """
    Identify recovered LM passwords belonging to Domain
    Administrator accounts.

    Args:
        mapped_lm_passwords (list):
            Recovered LM username:password mappings.

        domain_admins (list):
            Domain Administrator usernames.

    Returns:
        list:
            LM password mappings associated with Domain
            Administrator accounts.
    """

    da_set = {
        normalize_username(username)
        for username in domain_admins
    }

    return [
        entry
        for entry in mapped_lm_passwords
        if normalize_username(
            entry.split(":", 1)[0]
        ) in da_set
    ]


def extract_lm_da_users(mapped_lm_da_passwords):
    """
    Extract Domain Administrator usernames from recovered
    LM password mappings.

    Args:
        mapped_lm_da_passwords (list):
            Domain Administrator LM password mappings.

    Returns:
        list:
            Unique Domain Administrator usernames.
    """

    return sorted({
        normalize_username(
            entry.split(":", 1)[0]
        )
        for entry in mapped_lm_da_passwords
    })