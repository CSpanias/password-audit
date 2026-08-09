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
# Password Analysis
# ---------------------------------------------------------------------------

#
# Common keyboard walking patterns frequently observed within passwords.
#
# These patterns are used to identify passwords containing predictable
# keyboard sequences that are commonly prioritised by attackers and
# represented within password-cracking wordlists and rule sets.
#
KEYBOARD_PATTERNS = [

    # QWERTY row
    "qwe",
    "qwer",
    "qwert",
    "qwerty",
    "qwertyuiop",
    "werty",
    "ertyuiop",
    "trewq",

    # ASDF row
    "asd",
    "asdf",
    "asdfg",
    "asdfgh",

    # ZXCV row
    "zxc",
    "zxcv",
    "zxcvbn",
    "zxcvbnm",

    # Diagonal walks
    "qaz",
    "qazwsx",
    "wsx",

    # Numeric / mixed walks
    "q1w2",
    "q1w2e3",

    # AZERTY layouts
    "azerty",

    # Frequently observed variants
    "aqwert",
    "vbnhb",
    "drews",
    "tress",
]


#
# Common password terms frequently observed within breach corpora
# and publicly available password dictionaries.
#
COMMON_PASSWORDS = {
    "password",
    "welcome",
    "letmein",
    "admin",
    "iloveyou",
    "starwars",
    "dragon",
    "monkey",
}


# ---------------------------------------------------------------------------
# Date-Related Terms
# ---------------------------------------------------------------------------

#
# Common day names often used within passwords.
#
DAYS = {
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
}


#
# Common month names often used within passwords.
#
MONTHS = {
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
}


#
# Seasonal references commonly observed in passwords.
#
SEASONS = {
    "spring",
    "summer",
    "autumn",
    "fall",
    "winter",
}


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