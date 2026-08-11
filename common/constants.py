"""
Shared constants used throughout audit-tool.

This module contains static values and reference data that do not
change during execution, including console colours, password-analysis
patterns, and common reporting values.

Constants should remain application-agnostic wherever possible and
avoid containing business logic.
"""


# ---------------------------------------------------------------------------
# Console Colours
# ---------------------------------------------------------------------------

COLOR_GREEN = "\033[0;32m"
COLOR_RED = "\033[0;31m"
COLOR_YELLOW = "\033[1;33m"
COLOR_CYAN = "\033[0;36m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

#
# Written representations for commonly used small integers.
#
# Used to improve report readability:
#
#     1 -> "one"
#     5 -> "five"
#
NUMBER_WORDS = {
    0: "zero",
    1: "one",
    2: "two",
    3: "three",
    4: "four",
    5: "five",
    6: "six",
    7: "seven",
    8: "eight",
    9: "nine",
}