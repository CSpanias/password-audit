"""
Campaign statistics.

This module provides helpers for loading and analysing
historical campaign execution data.
"""

import json

from rich.table import Table

from cracking.constants import HISTORY_DIR
from common.utils import human_time
from common.console import console


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
                    "bestRecovered": 0,
                    "bestROI": 0,
                }
            )

            stats[phase_id]["runs"] += 1
            stats[phase_id]["duration"] += phase["duration"]
            stats[phase_id]["newRecovered"] += phase["newRecovered"]
            stats[phase_id]["passwordsPerMinute"] += (
                phase["passwordsPerMinute"]
            )
            stats[phase_id]["bestRecovered"] = max(
                stats[phase_id]["bestRecovered"],
                phase["newRecovered"],
            )
            stats[phase_id]["bestROI"] = max(
                stats[phase_id]["bestROI"],
                phase["passwordsPerMinute"],
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
            "bestRecovered": data["bestRecovered"],
            "bestROI": round(data["bestROI"], 2),
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

    print()
    table = Table(
        title="Attack Statistics",
        title_style="bold cyan",
    )

    table.add_column("Phase")
    table.add_column("Runs", justify="right")
    table.add_column("Avg Duration", justify="right")
    table.add_column("Avg Recovery", justify="right")
    table.add_column("Avg ROI (pwd/min)", justify="right")
    table.add_column("Best Recovery", justify="right")
    table.add_column("Best ROI (pwd/min)", justify="right")

    for phase_id, data in sorted(stats.items()):

        table.add_row(
            phase_id,
            str(data["runs"]),
            human_time(data["averageDuration"]),
            str(data["averageRecovered"]),
            f"{data['averageROI']}",
            str(data["bestRecovered"]),
            f"{data['bestROI']}",
        )

    console.print(table)
    print()