"""
Audit workflow orchestration.

This module provides an end-to-end Active Directory
password auditing workflow by coordinating the organiser,
cracking, and analysis modules.
"""


import os

from pathlib import Path
from rich.table import Table

from auditing.validation import validate_audit_inputs
from analysis.workflow import analyse_passwords
from cracking.parsers import load_campaign
from cracking.scheduler import run_campaign
from cracking.constants import DEFAULT_HASHCAT_DIR
from common.console import console, ok, info, warn
from cracking.reporting import print_summary
from lm.workflow import generate_lm_results, map_lm_passwords
from ntds.workflow import organise_dataset


def run_audit(
    ntds_file,
    bloodhound_file,
    campaign_file,
    campaign_name,
    username_filter=None,
    mapped_ntlm_passwords=None,
    mapped_lm_passwords=None,
    lm_users=None,
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
            
        mapped_ntlm_passwords:
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

    #---------------------------------------------------------------------------
    # Pre-flight checks
    #---------------------------------------------------------------------------
    print()
    info("Validating Inputs")
    print()

    try:

        validate_audit_inputs(
                ntds_file,
                bloodhound_file,
                campaign_file,
            )
        
        ok("Validation Successful")
        print()

    except ValueError as exc:

        warn(str(exc))
        print()

        return


    #---------------------------------------------------------------------------
    # Organising
    #---------------------------------------------------------------------------
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

    hashcat_binary = parameters.get(
        "hashcatBinary",
        os.path.join(hashcat_dir, "hashcat.exe"),
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

    #---------------------------------------------------------------------------
    # Cracking
    #---------------------------------------------------------------------------
    info("Stage 2/5 - Recovering NTLM Passwords")

    ntlm_campaign = campaign["ntlm"]
        
    campaign_results = run_campaign(
        config=ntlm_campaign,
        hash_file=output_dir / "ntlm-hashes.txt",
        campaign_name=campaign_name,
    )

    print_summary(campaign_results)
    print()

    lm_campaign = campaign.get("lm")

    if organise_results["lm_hashes"] and lm_campaign:

        info("Stage 3/5 - Recovering LM Passwords")

        lm_campaign_results = run_campaign(
            config=lm_campaign,
            hash_file=output_dir / "lm-hashes.txt",
            campaign_name=f"{campaign_name}-lm",
        )

        print_summary(lm_campaign_results)
        print()

    elif organise_results["lm_hashes"]:

        info("Stage 3/5 - Recovering LM Passwords")
        warn("No LM campaign configured - skipping")
        print()

    #--------------------------------------------------------------------------- 
    # Mapping NTLM passwords back to their users
    #---------------------------------------------------------------------------
    info("Stage 4/5 - Mapping Passwords")
    print()

    # NTLM mapping
    ntlm_mapping_results = organise_dataset(
        ntds_file=ntds_file,
        output_dir=output_dir,
        potfile=hashcat_potfile,
        username_filter=username_filter,
    )

    # LM mapping
    lm_results_file = None
    lm_mapping_results = None

    if organise_results["lm_hashes"]:

        lm_results_file = (output_dir / "lm-results.txt")

        generate_lm_results(
            hashcat_binary=hashcat_binary,
            hash_file=output_dir / "lm-hashes.txt",
            potfile=hashcat_potfile,
            output_file=lm_results_file,
        )

        lm_mapping_results = map_lm_passwords(
            ntds_file=ntds_file,
            potfile=hashcat_potfile,
            lm_results=lm_results_file,
            output_dir=output_dir,
        )

    # Create table
    if ntlm_mapping_results["mapped_ntlm_passwords"]:

        table = Table(
            title="Password Mapping Summary",
            title_style="bold cyan",
        )

        table.add_column("Object")
        table.add_column("Count", justify="right")

        table.add_row(
            "Mapped NTLM Passwords",
            str(len(ntlm_mapping_results["mapped_ntlm_passwords"]))
        )

        if lm_mapping_results:

            table.add_row(
                "Mapped LM Passwords",
                str(len(lm_mapping_results["mapped_lm_passwords"]))
            )

        console.print(table)
        print()

    #---------------------------------------------------------------------------
    info("Stage 5/5 - Analysing Passwords")
    #---------------------------------------------------------------------------
    print()

    mapped_ntlm_passwords = (
        mapped_ntlm_passwords
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

    lm_users = (
        lm_users
        or output_dir / "lm-users.txt"
    )

    mapped_lm_passwords = (
        mapped_lm_passwords
        or output_dir / "mapped-lm-passwords.txt"
    )

    analyse_passwords(
        mapped_ntlm_passwords=mapped_ntlm_passwords,
        domain_admins=domain_admins,
        company_words=company_words,
        pass_policy=pass_policy,
        enabled_users=enabled_users,
        lm_users=lm_users,
        mapped_lm_passwords=mapped_lm_passwords,
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
        "mappedPasswords": mapped_ntlm_passwords,
        "recoveredPasswords": total_recovered,
        "report": report_file,
    }