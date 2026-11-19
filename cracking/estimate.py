"""
Campaign duration estimation.

This module estimates campaign duration from compatible local runs.
"""

from statistics import median

from rich.table import Table

from common.console import console
from common.utils import human_time
from cracking.parsers import load_campaign
from cracking.statistics import (
    attack_identity,
    describe_settings,
    local_statistics,
    phase_identity,
)
from cracking.validation import validate_campaign


def estimate_campaign(path):
    """
    Estimate campaign duration using historical statistics.

    Args:
        path:
            Path to the campaign configuration.

    Returns:
        dict:
            Campaign estimates keyed by campaign name.
    """

    campaigns = load_campaign(path)
    history, _ = local_statistics()

    results = {}

    for name, campaign in campaigns.items():

        estimates = []
        total_duration = 0
        incomplete = False

        enabled_phases = [
            phase
            for phase in campaign["phases"]
            if phase.get("enabled", True)
        ]

        if enabled_phases:
            validate_campaign(campaign)
        parameters = campaign["parameters"]
        settings = describe_settings(parameters.get("flags", []))

        for position, phase in enumerate(enabled_phases, start=1):
            phase_id = phase["id"]
            identity = phase_identity(parameters["hashMode"], phase, settings)
            samples = [
                record["duration"]
                for record, fingerprint in history
                if fingerprint == settings["localFingerprint"]
                and identity is not None and identity == attack_identity(record)
                and record["position"] == position
            ]

            if not samples:

                estimates.append(
                    {
                        "id": phase_id,
                        "duration": None,
                        "runs": 0,
                    }
                )

                incomplete = True
                continue

            duration = median(samples)

            estimates.append(
                {
                    "id": phase_id,
                    "duration": duration,
                    "runs": len(samples),
                }
            )

            total_duration += duration

        results[name] = {
            "estimates": estimates,
            "total_duration": total_duration,
            "incomplete": incomplete,
        }

    return results


def print_campaign_estimate(args):

    campaigns = estimate_campaign(args.campaign)

    print()

    for name, campaign in campaigns.items():

        table = Table(
            title=f"{name.upper()} Campaign Estimate",
            title_style="bold cyan",
        )

        table.add_column("Phase")
        table.add_column("Duration")
        table.add_column("Historical Runs", justify="right")

        for phase in campaign["estimates"]:

            if phase["duration"] is None:

                table.add_row(
                    phase["id"],
                    "Unknown",
                    str(phase["runs"]),
                )

            else:

                table.add_row(
                    phase["id"],
                    human_time(phase["duration"]),
                    str(phase["runs"]),
                )

        table.add_section()

        table.add_row(
            "Estimated Total",
            (
                "Unknown" if campaign["incomplete"] and not any(
                    phase["duration"] is not None for phase in campaign["estimates"]
                ) else (
                    f"{human_time(campaign['total_duration'])}"
                    f"{' (partial)' if campaign['incomplete'] else ''}"
                )
            ),
            "-",
        )

        console.print(table)
        print(
            "Local medians require matching attack labels, settings and phase position. "
            "Hardware and prior recoveries can affect duration."
        )
        print()