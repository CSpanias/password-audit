"""
Campaign scheduling workflow.

This module coordinates the execution of Hashcat campaign
phases, tracks recovery statistics, and manages campaign
results.
"""

import os
import sys
import uuid
from datetime import datetime

from common.console import ok, summary, warn
from common.utils import human_time
from cracking.constants import DEFAULT_HASHCAT_DIR
from cracking.hashcat import run_phase, validate_file
from cracking.loopback import generate_loopback_wordlist
from cracking.results import archive_results, load_results, write_results
from cracking.resume import build_resume_fingerprint
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
            Continue a previously interrupted campaign by skipping
            completed phases. The interrupted phase starts over.

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
        and existing_results.get("state") in {"running", "interrupted"}
        and not resume
    ):

        warn("Previous campaign appears to have been interrupted")
        summary("Phase", existing_results.get("currentPhase"))
        summary("Session", existing_results.get("currentSession"))
        print()

        warn(
            "Resume is available only through `password-audit audit --resume`; "
            "standalone crack campaigns cannot be resumed. "
            "The interrupted Hashcat phase will restart from the beginning."
        )
        sys.exit(1)

    if resume and existing_results:
        if existing_results.get("state") not in {
            "running",
            "interrupted",
            "completed",
        }:
            warn("Campaign results have an unknown state; refusing to resume")
            sys.exit(1)

    validate_file(hash_file)
    validate_file(hashcat_binary)

    try:
        resume_fingerprint = build_resume_fingerprint(
            config=config,
            hash_file=hash_file,
            campaign_name=campaign_name,
            hashcat_binary=hashcat_binary,
            hashcat_potfile=hashcat_potfile,
            wordlist_dir=wordlist_dir,
            rules_dir=rules_dir,
        )
    except OSError as exc:
        warn(f"Unable to verify campaign inputs: {exc}")
        sys.exit(1)

    completed_phases = set()
    interrupted_phase = None

    if resume and existing_results:

        if existing_results.get("resumeFingerprint") != resume_fingerprint:
            warn(
                "Campaign inputs differ from the saved run, or its "
                "results lack a compatibility fingerprint. Refusing to skip "
                "completed phases. Use a new campaign name to start a new run."
            )
            sys.exit(1)

        results = existing_results

        if results.get("state") == "completed":
            ok("Campaign already completed; reusing its recorded results")
            return results

        interrupted_phase = results.get("currentPhase")

        completed_phases = {
            phase["id"]
            for phase in existing_results["phases"]
        }

        print()
        ok("Continuing campaign from recorded results")

        for phase in completed_phases:
            summary("Skipping", phase)

        if interrupted_phase and interrupted_phase not in completed_phases:
            warn(
                f"Interrupted phase '{interrupted_phase}' will restart from "
                "the beginning. Hashcat checkpoint restoration is not performed."
            )

        results["state"] = "running"
        results.pop("interruption", None)
        write_results(results)

        print()

    else:

        if resume:
            warn(
                "No prior campaign results found; starting this campaign "
                "from its first enabled phase."
            )

        results = {
            "campaign": campaign_name,
            "hashMode": hash_mode,
            "hashDataset": hash_file,
            "started": datetime.now().isoformat(),
            "state": "running",
            "currentPhase": None,
            "currentSession": None,
            "resumeFingerprint": resume_fingerprint,
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

        if (
            resume
            and phase["id"] == interrupted_phase
            and phase["id"] not in completed_phases
        ):
            session_name = (
                f"{session_name}-retry-{uuid.uuid4().hex[:8]}"
            )

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
                "The current Hashcat phase will restart from the beginning "
                "on resume; Hashcat checkpoint restoration is not performed."
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