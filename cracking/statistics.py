"""
Campaign statistics.

This module provides helpers for loading and analysing
historical campaign execution data.
"""

import json

from pathlib import Path

from cracking.constants import (
    HISTORY_DIR,
)

from common.utils import (
    human_time,
)


def load_history():
    """
    Load historical campaign results.

    Returns:
        list:
            Historical campaign result dictionaries.
    """

    if not HISTORY_DIR.exists():
        return []

    history = []

    for file in HISTORY_DIR.glob("*.json"):

        with open(file, encoding="utf-8") as handle:
            history.append(json.load(handle))

    return history


def phase_statistics():
    """
    Calculate statistics for each campaign phase.

    Returns:
        dict:
            Aggregated phase statistics.
    """

    stats = {}

    for campaign in load_history():

        for phase in campaign.get("phases", []):

            phase_id = phase["id"]

            stats.setdefault(
                phase_id,
                {
                    "runs": 0,
                    "duration": 0,
                    "newRecovered": 0,
                    "passwordsPerMinute": 0,
                }
            )

            stats[phase_id]["runs"] += 1
            stats[phase_id]["duration"] += phase["duration"]
            stats[phase_id]["newRecovered"] += phase["newRecovered"]
            stats[phase_id]["passwordsPerMinute"] += (
                            phase["passwordsPerMinute"]
            )

    return stats


def print_phase_statistics():
    """
    Display historical statistics for campaign phases.

    Returns:
        None
    """

    stats = phase_statistics()

    if not stats:

        print("No campaign history available.")
        return

    print("\n## Attack Statistics\n")

    for phase_id, data in sorted(stats.items()):

        average_duration = (
            data["duration"] / data["runs"]
        )

        average_recovered = round(
            data["newRecovered"] / data["runs"],
            2,
        )

        average_roi = round(
            data["passwordsPerMinute"] / data["runs"],
            2,
        )

        print(f"{phase_id}")
        print("-" * len(phase_id))

        print(
            f"Runs               : {data['runs']}"
        )

        print(
            f"Average Duration   : "
            f"{human_time(average_duration)}"
        )

        print(
            f"Average Recovery   : "
            f"{average_recovered}"
        )

        print(
            f"Average ROI        : "
            f"{average_roi} passwords/min"
        )

        print()