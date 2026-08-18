"""
Hashcat Scheduler command-line workflow.

This module coordinates campaign execution, result generation,
and campaign summary reporting.
"""

from cracking.parsers import load_campaign
from cracking.scheduler import run_campaign
from cracking.reporting import print_summary
from cracking.statistics import print_phase_statistics
from common.console import info, warn


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
    print()

    config = load_campaign(args.campaign)

    campaign_types = {"ntlm", "lm"} & set(config)

    if len(campaign_types) > 1:

        warn("Dual NTLM/LM campaign files are not supported by the crack module.")
        info(
            "Use an NTLM-only or LM-only campaign file, or run the audit workflow for combined "
             "NTLM and LM recovery."
        )

        return

    if "ntlm" in config:
        config = config["ntlm"]
        info("Running ntlm campaign")

    elif "lm" in config:
        config = config["lm"]
        info("Running lm campaign")

    else:

        warn("Campaign file must contain either an 'ntlm' or 'lm' section.")

        return

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