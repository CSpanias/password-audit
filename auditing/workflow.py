"""
Audit workflow orchestration.

This module provides an end-to-end Active Directory
password auditing workflow by coordinating the organiser,
cracking, and analysis modules.
"""


import os

from pathlib import Path
from rich.table import Table

from ntds.workflow import organise_dataset
from analysis.workflow import analyse_passwords
from cracking.parsers import load_campaign
from cracking.scheduler import run_campaign
from cracking.constants import DEFAULT_HASHCAT_DIR
from common.console import console, ok, info, warn
from cracking.reporting import print_summary


def run_audit(
    ntds_file,
    bloodhound_file,
    campaign_file,
    campaign_name,
    username_filter=None,
    mapped_passwords=None,
    domain_admins=None,
    company_words=None,
    enabled_users=None,
    pass_policy=None
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

        username_filter:
            Usernames to exclude from processing.
            
        mapped_passwords:
            Override mapped password dataset.

        domain_admins:
            Override Domain Administrators dataset.

        company_words:
            Override organisation wordlist.

        enabled_users:
            Override enabled users dataset.

        pass_policy:
            Override domain password policy.

    Returns:
        dict:
            Workflow execution results.
    """

    output_dir = Path("ntds-organiser")

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Organising
    print()
    info("Stage 1/5 - Organising Data")

    organise_results = organise_dataset(
            ntds_file=ntds_file,
            username_filter=username_filter,
            output_dir=output_dir,
            bloodhound_file=bloodhound_file,
        )

    campaign = load_campaign(campaign_file)

    parameters = campaign["ntlm"]["parameters"]
    
    hashcat_dir = parameters.get(
        "hashcatDir",
        DEFAULT_HASHCAT_DIR,
    )
    hashcat_potfile = os.path.join(
        hashcat_dir,
        "hashcat.potfile",
    )

    # Summary output
    filtered_users = organise_results["filtered_users"]
    
    if filtered_users:
        print()
        warn(f"Filtered Accounts ({len(filtered_users)})")

        for account in filtered_users:
            print(f" - {account['username']}")

    print()

    table = Table(
        title="NTDS Summary",
        title_style="bold cyan",
    )

    table.add_column("Object")
    table.add_column("Count", justify="right")

    table.add_row(
        "User Accounts",
        str(len(organise_results["enabled_users"]))
    )

    table.add_row(
        "NTLM Hashes",
        str(len(organise_results["ntlm_hashes"]))
    )

    if organise_results["lm_hashes"]:
        table.add_row(
            "LM Hashes",
            str(len(organise_results["lm_hashes"]))
        )

    table.add_row(
        "Domain Admins",
        str(len(organise_results["domain_admins"]))
    )

    console.print(table)
    print()

    # Cracking
    info("Stage 2/5 - Recovering NTLM Passwords")

    ntlm_campaign = campaign["ntlm"]
        
    campaign_results = run_campaign(
        config=ntlm_campaign,
        hash_file=output_dir / "ntlm-hashes.txt",
        campaign_name=campaign_name,
    )

    print_summary(campaign_results)
    print()

    if organise_results["lm_hashes"]:

        info("Stage 3/5 - Recovering LM Passwords")
    
        lm_campaign = campaign["lm"]

        lm_campaign_results = run_campaign(
            config=lm_campaign,
            hash_file=output_dir / "lm-hashes.txt",
            campaign_name=f"{campaign_name}-lm",
        )

        print_summary(lm_campaign_results)
        print()
        
    # Mapping NTLM passwords back to their users
    info("Stage 4/5 - Mapping Passwords")
    print()

    # organise_dataset(
    #     ntds_file=ntds_file,
    #     output_dir=output_dir,
    #     potfile=hashcat_potfile,
    #     username_filter=username_filter
    # )

    mapping_results = organise_dataset(
        ntds_file=ntds_file,
        output_dir=output_dir,
        potfile=hashcat_potfile,
        username_filter=username_filter,
    )

    if mapping_results["mapped_ntlm_passwords"]:

        table = Table(
            title="Password Mapping Summary",
            title_style="bold cyan",
        )

        table.add_column("Object")
        table.add_column("Count", justify="right")

        table.add_row(
            "Mapped Passwords",
            str(len(mapping_results["mapped_ntlm_passwords"]))
        )

        console.print(table)
        print()

    info("Stage 5/5 - Analysing Passwords")
    print()

    mapped_passwords = (
        mapped_passwords
        or output_dir / "mapped-ntlm-passwords.txt"
    )

    domain_admins = (
        domain_admins
        or output_dir / "domain-admins.txt"
    )

    company_words = (
        company_words
        or output_dir / "company-words.txt"
    )

    pass_policy = (
        pass_policy
        or output_dir / "domain-policy.txt"
    )

    enabled_users = (
        enabled_users
        or output_dir / "enabled-users.txt"
    )

    analyse_passwords(
        mapped_passwords=mapped_passwords,
        domain_admins=domain_admins,
        company_words=company_words,
        pass_policy=pass_policy,
        enabled_users=enabled_users,
    )

    report_file = Path("report.md")
    findings_file = Path("findings.json")
    
    total_recovered = 0

    if campaign_results["phases"]:
        total_recovered = (campaign_results["phases"][-1]["totalRecovered"])


    ok("Audit Complete")
    print()
    ok(f"Report written to: {report_file}")
    ok(f"Findings written to: {findings_file}")

    return {
        "campaign": campaign_results,
        "mappedPasswords": mapped_passwords,
        "recoveredPasswords": total_recovered,
        "report": report_file,
    }