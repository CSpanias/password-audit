"""
Audit workflow validation.
"""

from pathlib import Path

from cracking.parsers import load_campaign
from common.console import ok, warn


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

    if "lm" in campaign:
        ok("LM campaign validated")
    else:
        warn("No LM campaign configured")