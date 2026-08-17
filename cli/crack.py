"""
Hashcat Scheduler command-line workflow.

This module coordinates campaign execution, result generation,
and campaign summary reporting.
"""

from cracking.parsers import load_campaign
from cracking.scheduler import run_campaign
from cracking.reporting import print_summary
from cracking.statistics import print_phase_statistics
from common.console import info


def run_cracking_campaign(args):
    """
    Execute a cracking campaign.

    Args:
        args:
            Parsed command-line arguments.

    Returns:
        None
    """

    print()
    info("Password Audit Crack")

    config = load_campaign(args.campaign)

    results = run_campaign(
        config=config,
        hash_file=args.hashes,
        campaign_name=args.campaign_name,
        resume=args.resume,
        debug=args.debug,
    )

    print_summary(results)


def show_cracking_statistics(args):
    """
    Display historical cracking statistics.

    Args:
        args:
            Parsed command-line arguments.

    Returns:
        None
    """

    print_phase_statistics()