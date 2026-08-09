"""
Common utility functions shared across audit-tool modules.

This module contains generic helper functions that are not tied
to any specific component (e.g. NTDS processing, password analysis, 
or Hashcat integration).

Functions in this module should be broadly reusable across the
entire codebase.
"""
import re
from .constants import NUMBER_WORDS


# ---------------------------------------------------------------------------
# Text Formatting
# ---------------------------------------------------------------------------

def natural_join(items):
    """
    Join a list of strings using natural language formatting.

    Examples:
        ["A"] -> "A"
        ["A", "B"] -> "A and B"
        ["A", "B", "C"] -> "A, B, and C"
    """

    if len(items) == 1:
        return items[0]

    if len(items) == 2:
        return f"{items[0]} and {items[1]}"

    return ", ".join(items[:-1]) + f", and {items[-1]}"


def num_to_word(value):
    """
    Convert small integers to their written representation.

    Values not present in NUMBER_WORDS are returned with
    thousand separators for readability.

    Examples:
        1 -> "one"
        5 -> "five"
        1250 -> "1,250"
    """

    if value in NUMBER_WORDS:
        return NUMBER_WORDS[value]

    return f"{value:,}"


# ---------------------------------------------------------------------------
# Username Handling
# ---------------------------------------------------------------------------

def username_base(username):
    """
    Derive the base username used for account comparison.

    Common administrative account suffixes and trailing
    numeric identifiers are removed to facilitate the
    identification of related accounts.

    Examples:
        john.smith -> john.smith
        john.smith_adm -> john.smith
        john.smith_da -> john.smith
        john.smith01 -> john.smith

    Returns:
        str: Base username value.
    """

    user = username.lower()

    if "\\" in user:
        user = user.split("\\")[-1]

    user = user.replace("_adm", "")
    user = user.replace("-adm", "")
    user = user.replace("_da", "")
    user = user.replace("-da", "")

    # Remove trailing digits
    user = re.sub(r"\d+$", "", user)

    return user


# ---------------------------------------------------------------------------
# Password Handling
# ---------------------------------------------------------------------------

def mask_password(password):
    """
    Partially mask a password for reporting purposes.

    For passwords longer than four characters, the first and
    last two characters are preserved while the remainder is
    replaced with asterisks.

    Examples:
        Password123! -> Pa*********!
        Test         -> Te**st
        abc          -> ***
    """

    if len(password) <= 4:
        return "*" * len(password)

    return (
        password[:2]
        + "*" * (len(password) - 4)
        + password[-2:]
    )


# ---------------------------------------------------------------------------
# Text Normalisation
# ---------------------------------------------------------------------------

def normalise_text(text):
    """
    Normalise text to improve matching accuracy.

    Common character substitutions are replaced with their
    alphabetic equivalents to account for simple leetspeak
    variations commonly observed in passwords.

    Examples:
        P@ssw0rd -> password
        C0tt0n   -> cotton
    """

    substitutions = {
        "@": "a",
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "$": "s",
    }

    text = text.lower()

    for old, new in substitutions.items():
        text = text.replace(old, new)

    return text


def normalise_password(password):
    """
    Normalise a password to improve matching accuracy.

    Common character substitutions are replaced with their
    alphabetic equivalents to account for simple leetspeak
    variations commonly observed in passwords.

    Examples:
        P@ssw0rd -> password
        Adm1n -> admin

    Returns:
        str: Normalised password value.
    """

    password = password.lower()

    substitutions = {
        "@": "a",
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "$": "s"
    }

    for old, new in substitutions.items():
        password = password.replace(old, new)

    return password