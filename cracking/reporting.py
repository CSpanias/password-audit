"""
Campaign reporting.

This module generates campaign execution summaries and other
operator-facing output.
"""


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

    print("\n## Campaign Summary\n")

    print("| Phase         | Duration | New Passwords | Total Passwords |")
    print("|---------------|----------|---------------|-----------------|")

    for phase in results["phases"]:

        print(
            f"| {phase['id']:<13} "
            f"| {phase['durationHuman']:<8} "
            f"| {phase['newRecovered']:>13} "
            f"| {phase['totalRecovered']:>15} |"
        )

    print()