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

    matches = []

    for line in output.splitlines():

        if line.startswith("Recovered"):

            match = re.search(
                r"Recovered\.+:\s+(\d+)/(\d+).*?,\s+(\d+)/(\d+)",
                line
            )

            if match:
                matches.append(match.groups())

    if matches:

        total_recovered = int(matches[-1][0])
        new_recovered = int(matches[-1][2])

        return new_recovered, total_recovered

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