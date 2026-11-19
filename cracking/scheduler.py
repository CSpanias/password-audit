"""
Campaign scheduling workflow.

This module coordinates the execution of Hashcat campaign
phases, tracks recovery statistics, and manages campaign
results.
"""

import os
import sys
from datetime import datetime
from uuid import uuid4

from common.console import summary, warn
from common.utils import human_time
from cracking.constants import DEFAULT_HASHCAT_DIR
from cracking.hashcat import run_phase, validate_file
from cracking.loopback import generate_loopback_wordlist
from cracking.results import archive_results, load_results, write_results
from cracking.statistics import describe_settings
from cracking.validation import validate_campaign


def run_campaign(
        config,
        hash_file,
        campaign_name,
        debug=False,
        session_prefix=None,
    ):
    """
    Execute a password recovery campaign.

    Enabled campaign phases are executed sequentially using
    Hashcat. Recovery statistics are collected throughout
    execution and written to campaign results files upon
    completion.

    Args:
        config:
            Campaign configuration.

        hash_file:
            Target hash dataset.

        campaign_name:
            Campaign identifier used for reporting.

        debug:
            Display verbose execution information.

        session_prefix:
            Optional prefix for Hashcat session names.

    Returns:
        dict:
            Campaign execution results.
    """

    validate_campaign(config)

    parameters = config["parameters"]

    hash_file = os.path.abspath(hash_file)

    hashcat_dir = parameters.get("hashcatDir", DEFAULT_HASHCAT_DIR)
    hashcat_binary = parameters.get("hashcatBinary", os.path.join(hashcat_dir, "hashcat.exe"))
    hashcat_potfile = os.path.join(hashcat_dir, "hashcat.potfile")
    wordlist_dir = os.path.join(hashcat_dir, "wordlists")
    rules_dir = os.path.join(hashcat_dir, "rules")
    hash_mode = parameters["hashMode"]
    flags = parameters.get("flags", [])

    existing_results = load_results(
            hash_file=hash_file,
            campaign_name=campaign_name,
        )

    if existing_results and existing_results.get("state") in {
        "running",
        "interrupted",
    }:
        warn("Previous campaign did not complete")
        summary("Phase", existing_results.get("currentPhase"))
        summary("Session", existing_results.get("currentSession"))
        print()
        warn(
            "Campaign resume is not supported. Use a new campaign name "
            "to start again from the first phase."
        )
        sys.exit(1)

    validate_file(hash_file)
    validate_file(hashcat_binary)

    results = {
        "campaign": campaign_name,
        "hashMode": hash_mode,
        "runId": str(uuid4()),
        "hashDataset": hash_file,
        "started": datetime.now().isoformat(),
        "state": "running",
        "currentPhase": None,
        "currentSession": None,
        "phases": [],
    }

    write_results(results)

    enabled_phases = [
        phase
        for phase in config["phases"]
        if phase.get("enabled", True)
    ]

    phase_numbers = {
        phase["id"]: index
        for index, phase in enumerate(enabled_phases, start=1)
    }

    total_phases = len(enabled_phases)

    for phase in enabled_phases:

        phase_number = phase_numbers[phase["id"]]
        session_name = f"{session_prefix or campaign_name}-{phase['id']}"

        results["currentPhase"] = phase["id"]
        results["currentSession"] = session_name

        write_results(results)

        if phase.get("type") == "loopback":
            wordlist = generate_loopback_wordlist(
                hashcat_potfile,
                hash_file,
            )

            if not wordlist:
                warn("No recovered passwords for loopback phase")
                continue

        else:
            wordlist = os.path.join(wordlist_dir, phase["wordlist"])
            validate_file(wordlist)

        rule = None

        if phase.get("rule"):

            rule = os.path.join(rules_dir, phase["rule"])
            validate_file(rule)

        try:

            result = run_phase(
                phase_id=phase_number,
                total_phases=total_phases,
                hashcat_binary=hashcat_binary,
                hash_file=hash_file,
                hash_mode=hash_mode,
                hashcat_potfile=hashcat_potfile,
                wordlist=wordlist,
                rule=rule,
                flags=flags,
                session_name=session_name,
                debug=debug
            )

        except KeyboardInterrupt:

            print()
            warn("Campaign interrupted")
            warn(
                "Campaign resume is not supported. Use a new campaign name "
                "to start again from the first phase."
            )
            print()

            results["state"] = "interrupted"
            results["interruption"] = {
                "phase": results["currentPhase"],
                "session": results["currentSession"],
                "occurred": datetime.now().isoformat(),
            }
            summary("Current Phase", results["currentPhase"])
            summary("Session", results["currentSession"])

            write_results(results)

            sys.exit(1)

        duration_minutes = result["duration"] / 60

        passwords_per_minute = (
            round(result["newRecovered"] / duration_minutes, 2)
            if duration_minutes
            else 0
        )

        results["phases"].append(
            {
                "id": phase["id"],
                "session": session_name,
                "wordlist": phase["wordlist"],
                "rule": phase.get("rule"),
                "duration": round(result["duration"], 2),
                "durationHuman": human_time(result["duration"]),
                "newRecovered": result["newRecovered"],
                "totalRecovered": result["totalRecovered"],
                "returnCode": result["returncode"],
                "passwordsPerMinute": passwords_per_minute,
                "statistics": {
                    "id": str(uuid4()),
                    "type": phase["type"],
                    "position": phase_number,
                    "settings": describe_settings(flags),
                    "recovery": result.get("recoveryDetails"),
                },
            }
        )

        write_results(results)

    results["currentPhase"] = None
    results["currentSession"] = None
    results["completed"] = datetime.now().isoformat()
    results["state"] = "completed"

    write_results(results)
    archive_results(results)

    return results