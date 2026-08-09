"""
Input parsing functions used by password analysis.

This module is responsible for loading datasets and configuration
files required during analysis, including recovered passwords,
domain policy information, organisation-specific terminology,
and supporting account lists.
"""


# ---------------------------------------------------------------------------
# Password Data
# ---------------------------------------------------------------------------

def load_passwords(path):
    """
    Load recovered plaintext passwords.

    Expected format:

        username:password

    Returns:
        List[dict]
    """

    passwords = []

    with open(path, encoding="utf-8", errors="ignore") as f:

        for line in f:
            line = line.strip()

            if ":" not in line:
                continue

            username, password = line.split(":", 1)

            passwords.append({
                "username": username,
                "password": password
            })

    return passwords


# ---------------------------------------------------------------------------
# Generic Lists
# ---------------------------------------------------------------------------

def load_list(path):
    """
    Load a newline-delimited list of values.

    Empty lines are ignored.

    Returns:
        List[str]
    """

    if not path:
        return []

    with open(path, encoding="utf-8", errors="ignore") as f:

        return [
            line.strip()
            for line in f
            if line.strip()
        ]


# ---------------------------------------------------------------------------
# Domain Policy
# ---------------------------------------------------------------------------

def load_domain_policy(path):
    """
    Load domain password policy information.

    Expected format:

        Key: Value

    Returns:
        Dict[str, str]
    """

    policy = {}

    with open(path, encoding="utf-8") as f:

        for line in f:

            if ":" not in line:
                continue

            key, value = line.split(":", 1)

            policy[key.strip()] = value.strip()

    return policy


# ---------------------------------------------------------------------------
# Organisation Terms
# ---------------------------------------------------------------------------

def load_company_words(path):
    """
    Load organisation-specific words used during password analysis.

    Terms are normalised to lowercase to support
    case-insensitive matching.

    Returns:
        List[str]
    """

    if not path:
        return []

    with open(path, encoding="utf-8") as f:

        return [
            line.strip().lower()
            for line in f
            if line.strip()
        ]