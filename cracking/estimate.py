"""
Campaign duration estimation.

This module estimates campaign duration based on
historical execution statistics.
"""

from common.utils import (
    human_time,
)

from cracking.parsers import (
    load_campaign,
)

from cracking.statistics import (
    calculate_phase_statistics,
)


def estimate_campaign(path):
    """
    Estimate campaign duration using historical statistics.

    Args:
        path:
            Path to the campaign configuration.

    Returns:
        tuple:
            Campaign phase estimates and estimated duration.
    """

    campaign = load_campaign(path)
    statistics = calculate_phase_statistics()

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
                }
            )

            incomplete = True
            continue

        duration = statistics[phase_id]["averageDuration"]

        estimates.append(
            {
                "id": phase_id,
                "duration": duration,
            }
        )

        total_duration += duration

    return estimates, total_duration, incomplete


def print_campaign_estimate(args):
    """
    Display a campaign duration estimate.

    Args:
        args:
            Parsed command-line arguments.

    Returns:
        None
    """

    estimates, total_duration, incomplete = (
        estimate_campaign(args.campaign)
    )

    print("\n## Campaign Estimate\n")

    for phase in estimates:

        if phase["duration"] is None:

            print(
                f"{phase['id']:<20}: "
                "Unknown (no history)"
            )

            continue

        print(
            f"{phase['id']:<20}: "
            f"{human_time(phase['duration'])}"
        )

    print()

    if incomplete:

        print(
            f"Estimated Total   : "
            f"{human_time(total_duration)} "
            "(partial estimate)"
        )

    else:

        print(
            f"Estimated Total   : "
            f"{human_time(total_duration)}"
        )

    print()