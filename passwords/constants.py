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