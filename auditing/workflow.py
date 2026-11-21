"""
Audit workflow orchestration.

This module provides an end-to-end Active Directory
password auditing workflow by coordinating the organiser,
cracking, and analysis modules.
"""


import os
from collections import Counter
from datetime import datetime
from pathlib import Path

from rich.table import Table

from analysis.hibp import HibpDataError
from analysis.workflow import analyse_passwords
from auditing.company_words import (
    prepare_company_word_sources,
    save_company_word_snapshot,
)
from auditing.validation import has_enabled_phases, validate_audit_inputs
from common.console import confirm_ntds_domain, console, info, ok, warn
from common.utils import format_count_warnings
from cracking.constants import DEFAULT_HASHCAT_DIR
from cracking.parsers import load_campaign
from cracking.reporting import print_summary
from cracking.scheduler import run_campaign
from lm.workflow import generate_lm_results, map_lm_passwords
from ntds.analysis import privileged_group_name
from ntds.workflow import organise_dataset


def create_audit_directory(output_root):
    output_root.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    suffix = 0
    while True:
        name = f"{timestamp}-{suffix}" if suffix else timestamp
        output_dir = output_root / name
        try:
            output_dir.mkdir()
        except FileExistsError:
            suffix += 1
        else:
            return output_dir


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
    pass_policy=None,
    csacyber=False,
    hibp=None,
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

        csacyber:
            Export SureFormat XML instead of JSON findings.

        hibp:
            Optional local Pwned Passwords NTLM range directory.

    Returns:
        dict:
            Workflow execution results.
    """

    #---------------------------------------------------------------------------
    # Pre-flight checks
    #---------------------------------------------------------------------------
    if hibp is not None and not Path(hibp).is_dir():
        raise HibpDataError(f"HIBP range directory does not exist: {hibp}")
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

    output_root = Path("password-audit")
    output_dir = create_audit_directory(output_root)
    ok(f"Audit output directory: {output_dir}")

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
            confirm_domain=confirm_ntds_domain,
        )

    if (
        organise_results.get("domain_admins_available")
        and not organise_results["domain_admins"]
    ):
        (output_dir / "domain-admins.txt").write_text("", encoding="utf-8")

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

    table.add_row("User Accounts", str(len(organise_results["enabled_users"])))
    table.add_row("NTLM Hashes", str(len(organise_results["ntlm_hashes"])))

    if organise_results["lm_hashes"]:
        table.add_row("LM Hashes", str(len(organise_results["lm_hashes"])))

    privileged = organise_results["privileged_users"]
    group_counts = Counter(
        group
        for account in privileged["accounts"]
        for group in {privileged_group_name(name) for name in account["groups"]}
    )
    table.add_row(
        "Domain Admins",
        "Unavailable" if privileged["status"] == "unavailable"
        else str(group_counts.pop("Domain Admins", 0)),
    )
    for group, count in sorted(group_counts.items(), key=lambda item: item[0].casefold()):
        table.add_row(group, str(count))

    console.print(table)
    console.print("Privileged group counts: matched enabled NTDS accounts.")
    if privileged["status"] != "available":
        warn(f"Privileged group coverage is {privileged['status']}: "
             + format_count_warnings(privileged["warnings"]))
    print()

    #---------------------------------------------------------------------------
    # Cracking
    #---------------------------------------------------------------------------
    info("Stage 2/5 - Recovering NTLM Passwords")

    campaign_results = {"phases": []}
    lm_campaign_results = {"phases": []}

    ntlm_campaign = campaign["ntlm"]

    if not has_enabled_phases(ntlm_campaign):

        warn("No enabled NTLM phases - skipping")
        print()

    else:

        campaign_results = run_campaign(
            config=ntlm_campaign,
            hash_file=output_dir / "ntlm-hashes.txt",
            campaign_name=campaign_name,
            session_prefix=f"{campaign_name}-{output_dir.name}",
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
            session_prefix=f"{campaign_name}-lm-{output_dir.name}",
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
        bloodhound_file=bloodhound_file,
        potfile=hashcat_potfile,
        username_filter=username_filter,
        confirmed_domain_sid=organise_results["privileged_users"].get(
            "confirmed_domain", {}
        ).get("sid"),
        source_domain_sid=(
            organise_results["privileged_users"].get("source_domain", {}).get("sid")
            if "confirmed_domain" not in organise_results["privileged_users"] else None
        ),
    )

    # LM mapping
    lm_results_file = None
    lm_mapping_results = None

    if organise_results["lm_hashes"]:

        lm_results_file = (output_dir / "lm-results.txt")
        lm_parameters = lm_campaign["parameters"] if lm_campaign else parameters
        lm_hashcat_dir = lm_parameters.get("hashcatDir", DEFAULT_HASHCAT_DIR)
        lm_hashcat_binary = lm_parameters.get(
            "hashcatBinary", os.path.join(lm_hashcat_dir, "hashcat.exe")
        )
        lm_hashcat_potfile = os.path.join(lm_hashcat_dir, "hashcat.potfile")

        generate_lm_results(
            hashcat_binary=lm_hashcat_binary,
            hash_file=output_dir / "lm-hashes.txt",
            potfile=lm_hashcat_potfile,
            output_file=lm_results_file,
        )

        lm_mapping_results = map_lm_passwords(
            ntds_file=ntds_file,
            potfile=hashcat_potfile,
            lm_results=lm_results_file,
            output_dir=output_dir,
            username_filter=username_filter,
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

    company_word_sources, company_word_snapshot = prepare_company_word_sources(
        generated_path=output_dir / "company-words.txt",
        custom_path=company_words,
        state_path=output_root / ".company-words-state.json",
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
        privileged_users=output_dir / "privileged-users.json",
        ntds_users=output_dir / "ntds-users-clean.txt",
        hibp=hibp,
        company_words=company_word_sources,
        pass_policy=pass_policy,
        enabled_users=enabled_users,
        lm_users=lm_users,
        mapped_lm_passwords=mapped_lm_passwords,
        output_file=output_dir / "password-audit-report.html",
        findings_file=output_dir / (
            "password-audit-findings.xml" if csacyber else "password-audit-findings.json"
        ),
        csacyber=csacyber,
    )

    if company_word_snapshot:
        save_company_word_snapshot(
            output_root / ".company-words-state.json",
            company_word_snapshot,
        )

    report_file = output_dir / "password-audit-report.html"
    
    total_recovered = 0

    if campaign_results["phases"]:
        total_recovered = (campaign_results["phases"][-1]["totalRecovered"])


    ok("Audit Complete")

    return {
        "campaign": campaign_results,
        "mappedPasswords": mapped_ntlm_passwords,
        "recoveredPasswords": total_recovered,
        "report": report_file,
        "outputDir": output_dir,
    }