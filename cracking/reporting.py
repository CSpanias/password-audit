"""
Campaign reporting.

This module generates campaign execution summaries and other
operator-facing output.
"""

from common.utils import human_time
from common.console import info

def print_summary(results):
    """
    Display a campaign execution summary.

    A summary table is generated showing the duration and
    password recovery statistics for each phase executed
    during the campaign.

    Args:
        results:
            Campaign execution results.

    Returns:
        None
    """

    print()
    info("Campaign Summary")
    print()
    print("| Phase         | Duration | New Passwords | Total Passwords | ROI/min |")
    print("|---------------|----------|---------------|-----------------|---------|")

    for phase in results["phases"]:

        print(
            f"| {phase['id']:<13} "
            f"| {phase['durationHuman']:<8} "
            f"| {phase['newRecovered']:>13} "
            f"| {phase['totalRecovered']:>15} "
            f"| {phase['passwordsPerMinute']:>7.2f} |"
        )

    total_duration = sum(
        phase["duration"]
        for phase in results["phases"]
    )

    total_new = sum(
        phase["newRecovered"]
        for phase in results["phases"]
    )

    final_recovered = (
        results["phases"][-1]["totalRecovered"]
        if results["phases"]
        else 0
    )

    print()
    info("Campaign Totals")
    print("-------------------")

    print(f"Duration        : {human_time(total_duration)}")
    print(f"New Passwords   : {total_new}")
    print(f"Final Recovered : {final_recovered}")

    print()