"""
Audit workflow orchestration.

This module provides an end-to-end Active Directory
password auditing workflow by coordinating the organiser,
cracking, and analysis modules.
"""

import os

from pathlib import Path

from ntds.workflow import (
    organise_dataset,
)

from analysis.workflow import (
    analyse_passwords,
)

from cracking.parsers import (
    load_campaign,
)

from cracking.scheduler import (
    run_campaign,
)

from cracking.constants import (
    DEFAULT_HASHCAT_DIR,
)

from common.console import (
    info,
    summary,
)


def run_audit(
    ntds_file,
    bloodhound_file,
    campaign_file,
    campaign_name,
):
    """
    Execute an end-to-end password audit workflow.

    Args:
        ntds_file:
            NTDS dataset.

        bloodhound_file:
            BloodHound ZIP export.

        campaign_file:
            Campaign configuration.

        campaign_name:
            Campaign identifier.

    Returns:
        dict:
            Workflow execution results.
    """

    output_dir = Path("ntds-organiser")

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    info("Stage 1/4 - Organising Data")

    organise_dataset(
        ntds_file=ntds_file,
        output_dir=output_dir,
        bloodhound_file=bloodhound_file,
    )

    campaign = load_campaign(campaign_file)

    parameters = campaign["parameters"]

    hashcat_dir = parameters.get(
        "hashcatDir",
        DEFAULT_HASHCAT_DIR,
    )

    hashcat_potfile = os.path.join(
        hashcat_dir,
        "hashcat.potfile",
    )

    hash_file = output_dir / "ntlm-hashes.txt"

    info("Stage 2/4 - Recovering Passwords")

    campaign_results = run_campaign(
        config=campaign,
        hash_file=hash_file,
        campaign_name=campaign_name,
    )

    info("Stage 3/4 - Mapping Passwords")

    organise_dataset(
        ntds_file=ntds_file,
        output_dir=output_dir,
        potfile=hashcat_potfile,
    )

    mapped_passwords = (output_dir / "mapped-ntlm-passwords.txt")

    info("Stage 4/4 - Analysing Passwords")

    analyse_passwords(
        mapped_passwords=mapped_passwords,
        domain_admins=output_dir / "domain-admins.txt",
        company_words=output_dir / "company-words.txt",
        pass_policy=output_dir / "domain-policy.txt",
        enabled_users=output_dir / "enabled-users.txt",
    )

    report_file = Path("report.md")
    
    total_recovered = 0

    if campaign_results["phases"]:
        total_recovered = (campaign_results["phases"][-1]["totalRecovered"])


    info("Audit Complete")

    summary("Report", report_file)
    summary("Mapped Passwords", mapped_passwords)
    summary("Recovered Passwords", total_recovered)

    print()

    return {
        "campaign": campaign_results,
        "mappedPasswords": mapped_passwords,
        "recoveredPasswords": total_recovered,
        "report": report_file,
    }