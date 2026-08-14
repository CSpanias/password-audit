"""
Password mapping functions.

This module is responsible for mapping recovered NTLM and LM
hashes to plaintext passwords using Hashcat potfiles.

Functions in this module should focus on hash-to-password
mapping and avoid performing analysis or report generation.
"""

from ntds.constants import LM_EMPTY


def map_passwords(users, hash_lookup):
    """
    Map NTLM hashes to recovered plaintext passwords.

    User NTLM hashes are compared against entries in the
    supplied potfile and successful matches are returned in
    username:password format.

    Args:
        users (list):
            User account records containing NTLM hashes.

        hash_lookup (dict):
            Potfile hash-to-password mapping.

    Returns:
        list:
            Recovered username:password mappings.
    """

    mapped = []

    for user in users:
        nt_hash = user["ntlm"].lower()

        if nt_hash not in hash_lookup:
            continue

        mapped.append(f"{user['username']}:{hash_lookup[nt_hash]}")

    return mapped


def map_lm_passwords(users, hash_lookup):
    """
    Map LM hashes to recovered plaintext passwords.

    Accounts containing the known empty LM hash are excluded.
    Remaining LM hashes are compared against entries in the
    supplied potfile and successful matches are returned in
    username:password format.

    Args:
        users (list):
            User account records containing LM hashes.

        hash_lookup (dict):
                    Potfile hash-to-password mapping.

    Returns:
        list:
            Recovered username:password mappings derived from
            LM hashes.
    """

    mapped = []

    for user in users:

        lm_hash = user["lm"].lower()

        if lm_hash == LM_EMPTY:
            continue

        if lm_hash not in hash_lookup:
            continue

        mapped.append(f"{user['username']}:{hash_lookup[lm_hash]}")

    return mapped