"""
Campaign scheduling workflow.

This module coordinates the execution of Hashcat campaign
phases, tracks recovery statistics, and manages campaign
results.
"""

import os
import sys

from datetime import datetime

from common.console import warn, ok, summary
from common.utils import human_time
from cracking.constants import DEFAULT_HASHCAT_DIR
from cracking.hashcat import run_phase, validate_file
from cracking.loopback import generate_loopback_wordlist
from cracking.results import write_results, archive_results, load_results
from cracking.validation import validate_campaign


def run_campaign(
        config,
        hash_file,
        campaign_name,
        resume=False,
        debug=False
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

        resume:
            Continue a previously interrupted campaign
            from the last recorded checkpoint.

        debug:
            Display verbose execution information.

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

    if (
        existing_results
        and existing_results.get("state") == "running"
        and not resume
    ):

        warn("Previous campaign appears to have been interrupted")
        summary("Phase", existing_results.get("currentPhase"))
        summary("Session", existing_results.get("currentSession"))
        summary(
            "Resume Command",
            (
                f"password-audit crack run "
                f"-C config.json "
                f"-H {hash_file} "
                f"-G {campaign_name} "
                f"--resume"
            )
        )
        print()

        warn("Restore the Hashcat session or remove the results file before starting a new campaign.")
        sys.exit(1)

    validate_file(hash_file)
    validate_file(hashcat_binary)

    completed_phases = set()

    if resume:

        if not existing_results:
            warn("No interrupted campaign found")
            sys.exit(1)

        if existing_results.get("state") != "running":
            warn("Campaign is already completed")
            sys.exit(1)

        results = existing_results

        completed_phases = {
            phase["id"]
            for phase in existing_results["phases"]
        }

        ok("Resuming interrupted campaign")

        for phase in completed_phases:
            summary("Skipping", phase)

        print()

    else:

        results = {
            "campaign": campaign_name,
            "hashMode": hash_mode,
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
        if (
            phase.get("enabled", True)
            and phase["id"] not in completed_phases
        )
    ]

    phase_numbers = {
        phase["id"]: index
        for index, phase in enumerate(enabled_phases, start=1)
    }

    total_phases = len(enabled_phases)

    for phase in enabled_phases:

        phase_number = phase_numbers[phase["id"]]
        session_name = (f"{campaign_name}-{phase['id']}")

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
            print()

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
                "passwordsPerMinute": passwords_per_minute
            }
        )

        write_results(results)

    results["currentPhase"] = None
    results["currentSession"] = None
    results["completed"] = datetime.now().isoformat()
    results["state"] = "completed"

    output_file = write_results(results)
    archive_file = archive_results(results)

    # ok(f"Results written to: {output_file}")
    # ok(f"Results archived to: {archive_file}")

    return results