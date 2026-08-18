"""
Campaign duration estimation.

This module estimates campaign duration based on
historical execution statistics.
"""

from rich.table import Table

from common.console import console
from common.utils import human_time
from cracking.parsers import load_campaign
from cracking.statistics import calculate_phase_statistics


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
    statistics = calculate_phase_statistics()

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

        for phase in enabled_phases:

            phase_id = phase["id"]

            if phase_id not in statistics:

                estimates.append(
                    {
                        "id": phase_id,
                        "duration": None,
                        "runs": 0,
                    }
                )

                incomplete = True
                continue

            duration = statistics[phase_id]["averageDuration"]

            estimates.append(
                {
                    "id": phase_id,
                    "duration": duration,
                    "runs": statistics[phase_id]["runs"],
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
                f"{human_time(campaign['total_duration'])}"
                f"{' (partial)' if campaign['incomplete'] else ''}"
            ),
            "-",
        )

        console.print(table)
        print()