"""
Hashcat execution helpers.

This module contains the functionality required to execute
Hashcat attacks, monitor progress, and collect runtime
statistics.
"""

import os
import subprocess
import sys
import time

from pathlib import Path

from common.console import info, warn, ok, summary
from common.utils import human_time
from cracking.parsers import parse_recovery_statistics


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_file(path):
    """
    Validate that a file exists.

    Args:
        path:
            Path to validate.

    Returns:
        None

    Raises:
        SystemExit:
            If the specified file does not exist.
    """

    if not Path(path).exists():
        warn(f"Missing file: {path}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def windows_path(path):
    """
    Convert a Linux path to a Windows path.

    The Hashcat Scheduler executes Hashcat within a Windows
    environment accessed via WSL. Paths are therefore converted
    using the wslpath utility before being supplied to Hashcat.

    Args:
        path:
            Linux filesystem path.

    Returns:
        str:
            Windows-formatted path.
    """

    return subprocess.check_output(["wslpath", "-w", path], text=True).strip()


def update_status(status, line):
    """
    Update Hashcat status information from a status line.

    Hashcat periodically outputs runtime statistics such as
    recovery counts, processing speed, estimated completion
    time, and execution progress. Relevant values are extracted
    and stored within the supplied status dictionary.

    Args:
        status:
            Dictionary containing the current phase status.

        line:
            Single line of Hashcat output.

    Returns:
        None
    """

    if "Status...........:" in line:
        status["status"] = line.split(":", 1)[1].strip()

    elif "Recovered........:" in line:
        status["recovered"] = line.split(":", 1)[1].strip()

    elif "Speed.#" in line:
        status["speed"] = line.split(":", 1)[1].strip()

    elif "Time.Estimated...:" in line:
        status["eta"] = line.split(":", 1)[1].strip()

    elif "Progress.........:" in line:
        status["progress"] = line.split(":", 1)[1].strip()


def status_complete(status):
    """
    Determine whether all required Hashcat status fields
    have been collected.

    Args:
        status:
            Dictionary containing Hashcat status information.

    Returns:
        bool:
            True if all required status fields are present,
            otherwise False.
    """

    return all(
        key in status
        for key in (
            "status",
            "recovered",
            "progress",
            "speed",
            "eta"
        )
    )


# ---------------------------------------------------------------------------
# Hashcat Execution
# ---------------------------------------------------------------------------

def run_phase(
        phase_id,
        total_phases,
        hashcat_binary,
        hash_file,
        hash_mode,
        hashcat_potfile,
        wordlist,
        rule,
        session_name,
        flags,
        debug=False
    ):
    """
    Execute a single Hashcat campaign phase.

    A Hashcat process is launched using the supplied attack
    parameters. Runtime statistics are monitored throughout
    execution and recovery metrics are collected upon
    completion.

    Args:
        phase_id:
            Current phase number.

        total_phases:
            Total number of phases within the campaign.

        hashcat_binary:
            Path to the Hashcat executable.

        hash_file:
            Path to the target hash dataset.

        hash_mode:
            Hashcat hash mode.

        hashcat_potfile:
            Path to the Hashcat potfile.

        wordlist:
            Wordlist used by the attack.

        rule:
            Rule file applied to the attack.

        session_name:
            Hashcat session identifier used for attack
            recovery and resume operations.

        flags:
            Additional Hashcat command-line arguments.

        debug:
            Display the generated Hashcat command.

    Returns:
        dict:
            Phase execution statistics and recovery metrics.
    """

    command = [
        hashcat_binary,
        "-m",
        str(hash_mode),
        windows_path(hash_file),
        windows_path(wordlist),
        "--potfile-path",
        windows_path(hashcat_potfile)
    ]

    if rule:
        command.extend(["-r", windows_path(rule)])

    command.extend(flags)
    command.extend(["--session", session_name])

    print()

    info(f"Phase {phase_id}/{total_phases}")

    print(f"    Wordlist : {os.path.basename(wordlist)}")

    if rule:
        print(f"    Rule     : {os.path.basename(rule)}")

    start = time.time()

    if debug:

        print()
        info("Executing")
        print()
        print(" ".join(command))
        print()

    process = subprocess.Popen(
        command,
        cwd=Path(hashcat_binary).parent,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    output = []
    status = {}

    for line in process.stdout or []:

        output.append(line)
        update_status(status=status, line=line)

        if "Progress.........:" in line and status_complete(status):

                print()
                print("    ---------------------------------------------------------------------------")
                           
                print(f"    Status    : {status['status']}")
                print(f"    Recovered : {status['recovered']}")
                print(f"    Progress  : {status['progress']}")
                print(f"    Speed     : {status['speed']}")
                print(f"    ETA       : {status['eta']}")
                print("    ---------------------------------------------------------------------------")

    process.wait()

    if process.returncode not in (0, 1):

        print()
        warn("Phase Failed")
        sys.exit(1)

    output = "".join(output)

    new_recovered, total_recovered = parse_recovery_statistics(output)
    duration = time.time() - start

    print()
    ok("Phase Complete")
    print()

    summary("Duration", human_time(duration))
    summary("New Passwords", new_recovered)
    summary("Total Passwords", total_recovered)

    print()

    return {
        "phase": phase_id,
        "duration": duration,
        "returncode": process.returncode,
        "output": output,
        "newRecovered": new_recovered,
        "totalRecovered": total_recovered
    }