"""
NTDS-specific constants.

This module contains static values used throughout NTDS
processing, analysis, and export operations.

Constants in this module should be specific to NTDS and
Active Directory data handling.
"""


# ---------------------------------------------------------------------------
# NTDS Hashes
# ---------------------------------------------------------------------------

#
# Well-known empty LM hash value.
#
# The presence of this hash indicates that LM password storage
# is not enabled for the account.
#

LM_EMPTY = "aad3b435b51404eeaad3b435b51404ee"