"""
Campaign and Hashcat output parsing.

This module provides helpers for loading campaign
configurations and extracting recovery statistics from
Hashcat output.
"""

import json
import re

# ---------------------------------------------------------------------------
# Hashcat Output Parsing
# ---------------------------------------------------------------------------

def parse_recovery_details(output):
    """Return Hashcat's final unique-digest recovery counts, if available."""
    matches = []
    for line in output.splitlines():
        if line.startswith("Recovered"):
            match = re.search(
                r"Recovered\.+:\s+([\d,]+)/([\d,]+).*?,\s+([\d,]+)/([\d,]+)",
                line,
            )
            if match:
                matches.append(tuple(int(value.replace(",", "")) for value in match.groups()))

    if not matches:
        return None

    total_recovered, total_hashes, new_recovered, new_total = matches[-1]
    if (
        total_hashes != new_total
        or new_recovered > total_recovered
        or total_recovered > total_hashes
    ):
        return None
    return {
        "newRecovered": new_recovered,
        "totalRecovered": total_recovered,
        "totalHashes": total_hashes,
        "remainingBefore": total_hashes - total_recovered + new_recovered,
    }


def parse_recovery_statistics(output):
    """
    Extract password recovery statistics from Hashcat output.

    The total number of recovered passwords and the number of
    passwords recovered during the current phase are extracted
    from the final Hashcat status output.

    Args:
        output:
            Captured Hashcat output.

    Returns:
        tuple:
            New passwords recovered during the phase and the
            total number of recovered passwords.
    """

    details = parse_recovery_details(output)
    if details is not None:
        return details["newRecovered"], details["totalRecovered"]

    return 0, 0


# ---------------------------------------------------------------------------
# Campaign Parsing
# ---------------------------------------------------------------------------

def load_campaign(path):
    """
    Load a campaign configuration file.

    Args:
        path:
            Path to the campaign configuration file.

    Returns:
        dict:
            Parsed campaign configuration.
    """

    with open(path, encoding="utf-8") as handle:
        return json.load(handle)