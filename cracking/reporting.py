"""
Campaign reporting.

This module generates campaign execution summaries and other
operator-facing output.
"""

from rich.table import Table

from common.utils import human_time
from common.console import console

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

    # Campaing Summary table
    print()
    table = Table(
        title="Campaign Summary",
        title_style="bold cyan"
    )

    table.add_column("Phase")
    table.add_column("Duration", justify="right")
    table.add_column("New Passwords", justify="right")
    table.add_column("Total Passwords", justify="right")
    table.add_column("ROI (pwd/min)", justify="right")

    for phase in results["phases"]:

        table.add_row(
            phase["id"],
            phase["durationHuman"],
            str(phase["newRecovered"]),
            str(phase["totalRecovered"]),
            f"{phase['passwordsPerMinute']:.2f}",
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

    table.add_section()

    table.add_row(
        "Total",
        human_time(total_duration),
        str(total_new),
        str(final_recovered),
        "-",
    )

    console.print(table)
    print()