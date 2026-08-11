"""
NTDS filtering functions.

This module contains helper functions used to filter and
categorise parsed NTDS account data.

Functions in this module should focus on selecting subsets
of data and avoid performing analysis or export operations.
"""

# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _build_filters(patterns):
    """
    Convert a comma-separated filter string into a list of
    normalised filter values.

    Args:
        patterns (str):
            Comma-separated filter string.

    Returns:
        list:
            Normalised filter values.
    """

    return [
        pattern.strip().lower()
        for pattern in patterns.split(",")
        if pattern.strip()
    ]


# ---------------------------------------------------------------------------
# Account Filters
# ---------------------------------------------------------------------------

def get_enabled(entries):
    """
    Return enabled accounts.

    Args:
        entries (list):
            Parsed NTDS account records.

    Returns:
        list:
            Enabled accounts.
    """

    return [entry for entry in entries if entry["enabled"]]


def get_disabled(entries):
    """
    Return disabled accounts.

    Args:
        entries (list):
            Parsed NTDS account records.

    Returns:
        list:
            Disabled accounts.
    """

    return [entry for entry in entries if not entry["enabled"]]


def get_machines(entries):
    """
    Return machine accounts.

    Args:
        entries (list):
            Parsed NTDS account records.

    Returns:
        list:
            Machine accounts.
    """

    return [entry for entry in entries if entry["machine"]]


def get_users(entries):
    """
    Return user accounts.

    Args:
        entries (list):
            Parsed NTDS account records.

    Returns:
        list:
            User accounts.
    """

    return [entry for entry in entries if not entry["machine"]]


# ---------------------------------------------------------------------------
# Pattern-Based Filtering
# ---------------------------------------------------------------------------

def apply_filter(entries, patterns):
    """
    Filter accounts using username patterns.

    Entries whose usernames contain one or more supplied
    patterns are removed and returned separately.

    Patterns should be supplied as a comma-separated string.

    Args:
        entries (list):
            Parsed NTDS account records.

    patterns (str):
        Comma-separated username filters.

    Returns:
        tuple:
            - list: Accounts retained.
            - list: Accounts removed.
    """

    if not patterns:
        return entries, []

    kept = []
    removed = []

    filters = _build_filters(patterns)

    for entry in entries:
        username = entry["username"].lower()

        if any(f in username for f in filters):
            removed.append(entry)
        else:
            kept.append(entry)

    return kept, removed


def apply_username_filter(usernames, patterns):
    """
    Filter usernames using matching patterns.

    Usernames containing one or more supplied patterns are
    excluded from the returned dataset.

    Patterns should be supplied as a comma-separated string.

    Args:
        usernames (list):
            Username values.

        patterns (str):
            Comma-separated username filters.

    Returns:
        list:
            Filtered usernames.
    """

    if not patterns:
        return usernames

    filters = _build_filters(patterns)

    return [
        username
        for username in usernames
        if not any(
            f in username.lower()
            for f in filters
        )
    ]