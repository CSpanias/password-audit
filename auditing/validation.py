"""
Audit workflow validation.
"""

from pathlib import Path

from cracking.parsers import load_campaign
from common.console import ok, warn


def has_enabled_phases(config):
    """
    Determine whether a campaign contains at least one
    enabled phase.
    """

    return any(
        phase.get("enabled", True)
        for phase in config.get("phases", [])
    )


def validate_audit_inputs(
    ntds_file,
    bloodhound_file,
    campaign_file,
):
    """
    Validate audit workflow inputs.

    Raises:
        ValueError:
            If a required input is invalid.
    """

    if not Path(ntds_file).exists():
        raise ValueError(f"NTDS file not found: {ntds_file}")

    ok("NTDS dataset found")

    if not Path(bloodhound_file).exists():
        raise ValueError(f"BloodHound export not found: {bloodhound_file}")

    ok("BloodHound export found")

    if not Path(campaign_file).exists():
        raise ValueError(f"Campaign file not found: {campaign_file}")

    ok("Campaign file found")

    campaign = load_campaign(campaign_file)

    if "ntlm" not in campaign:
        raise ValueError("Campaign file must contain an NTLM campaign.")

    ok("NTLM campaign validated")

    ntlm_enabled = has_enabled_phases(campaign["ntlm"])

    if not ntlm_enabled:
        warn("NTLM campaign contains no enabled phases")

    if "lm" in campaign:

        ok("LM campaign validated")

        lm_enabled = has_enabled_phases(campaign["lm"])

        if not lm_enabled:
            warn("LM campaign contains no enabled phases")

    else:
        warn("No LM campaign configured")

    if not ntlm_enabled and not lm_enabled:
        print()
        raise ValueError("Campaign does not contain any enabled phases.")