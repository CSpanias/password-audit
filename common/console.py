"""
Console output helpers.

This module contains convenience functions used to standardise
console output across the password-audit framework.

Functions in this module should focus on user-facing console
messages and avoid implementing business logic.
"""

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


def warn(message):
    """
    Display a warning message.

    Args:
        message (str):
            Message to display.

    Returns:
        None
    """

    print(f"{COLOR_YELLOW}[!]{COLOR_RESET} {message}")


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