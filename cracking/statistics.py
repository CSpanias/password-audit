"""
Campaign statistics.

This module provides helpers for loading and analysing
historical campaign execution data.
"""

import json

from cracking.constants import HISTORY_DIR
from common.utils import human_time
from common.console import summary


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


def calculate_phase_statistics():
    """
    Calculate aggregated statistics for each phase.

    Returns:
        dict:
            Phase statistics including averages.
    """

    calculated = {}

    for phase_id, data in phase_statistics().items():

        calculated[phase_id] = {
            "runs": data["runs"],
            "averageDuration": round(data["duration"] / data["runs"], 2),
            "averageRecovered": round(data["newRecovered"] / data["runs"], 2),
            "averageROI": round(data["passwordsPerMinute"] / data["runs"], 2),
        }

    return calculated


def print_phase_statistics(_args=None):
    """
    Display historical statistics for campaign phases.

    Args:
        args:
            Parsed command-line arguments.

    Returns:
        None
    """

    stats = calculate_phase_statistics()

    if not stats:

        print("No campaign history available.")
        return

    print("\n## Attack Statistics\n")

    for phase_id, data in sorted(stats.items()):

        print(f"{phase_id}")
        print("-" * len(phase_id))

        summary("Runs", data["runs"])
        summary("Average Duration", human_time(data["averageDuration"]))
        summary("Average Recovery", round(data["averageRecovered"], 2))
        summary("Average ROI", f"{round(data['averageROI'], 2)} passwords/min")

        print()