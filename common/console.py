"""
Console output helpers.

This module contains convenience functions used to standardise
console output across the password-audit framework.

Functions in this module should focus on user-facing console
messages and avoid implementing business logic.
"""

import sys

from rich.console import Console

from common.constants import (
    COLOR_GREEN,
    COLOR_YELLOW,
    COLOR_CYAN,
    COLOR_RESET,
)

# -----------------
# Console Messages
# -----------------

console = Console()

def confirm_ntds_domain(domain):
    """Confirm an NTDS source domain without blocking unattended runs."""
    if not sys.stdin.isatty():
        warn("NTDS source domain cannot be confirmed without an interactive terminal.")
        return None
    print()
    warn(
        "The BloodHound export does not identify a single source domain. "
        "Confirm only if you know the NTDS dump belongs to this domain.",
        end="\n\n",
    )
    try:
        answer = input(
            f"Does the NTDS dump belong to {domain['name']} ({domain['sid']})? [y/N] "
        )
    except EOFError:
        warn("NTDS source domain confirmation was not provided.")
        return None
    return answer.strip().casefold() in {"y", "yes"}


def confirm_without_password_policy():
    """Ask before skipping policy compliance, without blocking unattended runs."""
    if not sys.stdin.isatty():
        warn("Cannot continue without password policy confirmation in a non-interactive terminal.")
        return False
    try:
        answer = input("Continue without password length compliance analysis? [y/N] ")
    except EOFError:
        warn("Password policy confirmation was not provided.")
        return False
    return answer.strip().casefold() in {"y", "yes"}


def info(message):
    """
    Display an informational message.

    Args:
        message (str):
            Message to display.

    Returns:
        None
    """
    print(f"{COLOR_CYAN}[*]{COLOR_RESET} {message}")


def warn(message, end="\n"):
    """
    Display a warning message.

    Args:
        message (str):
            Message to display.

        end (str):
            Text appended after the message.

    Returns:
        None
    """

    print(f"{COLOR_YELLOW}[!]{COLOR_RESET} {message}", end=end)


# ---------------
# Summary Output
# ---------------

def summary(label, value):
    """
    Display a formatted summary entry.

    Args:
        label (str):
            Summary label.

    value:
        Summary value.

    Returns:
        None
    """

    print(f"    {label:<20}: {value}")


def ok(message):
    """
    Display a success message.

    Args:
        message (str):
            Message to display.

    Returns:
        None
    """

    print(f"{COLOR_GREEN}[+]{COLOR_RESET} {message}")