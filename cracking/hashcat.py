"""
Hashcat execution helpers.

This module contains the functionality required to execute
Hashcat attacks, monitor progress, and collect runtime
statistics.
"""

import os
import re
import subprocess
import sys
import time
from pathlib import Path

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)

from common.console import console, info, warn
from cracking.parsers import parse_recovery_details

HASHCAT_STATUS_INTERVAL = 5


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
        progress = line.split(":", 1)[1].strip()
        status["progress"] = progress
        match = re.match(r"([\d,]+)/([\d,]+)", progress)
        if match:
            status["progress_completed"] = int(
                match.group(1).replace(",", "")
            )
            status["progress_total"] = int(
                match.group(2).replace(",", "")
            )


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
            "progress_completed",
            "progress_total",
            "speed",
            "eta"
        )
    )


def live_status_flags(flags):
    cleaned_flags = []
    index = 0

    while index < len(flags):
        flag = flags[index]

        if flag in {"--status", "--status-json"}:
            index += 1
            continue

        if flag == "--status-timer":
            if (
                index + 1 >= len(flags)
                or str(flags[index + 1]).startswith("-")
            ):
                raise ValueError("--status-timer requires a value.")
            index += 2
            continue

        if (
            isinstance(flag, str)
            and flag.startswith("--status-timer=")
        ):
            index += 1
            continue

        cleaned_flags.append(flag)
        index += 1

    return [
        *cleaned_flags,
        "--status",
        f"--status-timer={HASHCAT_STATUS_INTERVAL}",
    ]


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
            Hashcat session identifier for this execution.

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

    command.extend(live_status_flags(flags))
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

    output = []
    status = {}
    displayed_status = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn(
            "Recovered {task.fields[recovered]} | "
            "Speed {task.fields[speed]} | ETA {task.fields[eta]}",
            markup=False,
        ),
        console=console,
    ) as progress:
        task_id = progress.add_task(
            f"Phase {phase_id}/{total_phases}",
            total=None,
            recovered="waiting",
            speed="waiting",
            eta="estimating",
        )
        process = subprocess.Popen(
            command,
            cwd=Path(hashcat_binary).parent,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        for line in process.stdout or []:
            output.append(line)
            update_status(status=status, line=line)

            if status_complete(status) and status != displayed_status:
                recovered_match = re.match(
                    r"([\d,]+/[\d,]+\s+\([^)]*\))",
                    status["recovered"],
                )
                eta_match = re.search(
                    r"\(([^()]*)\)\s*$",
                    status["eta"],
                )
                progress.update(
                    task_id,
                    total=status["progress_total"],
                    completed=status["progress_completed"],
                    recovered=(
                        recovered_match.group(1)
                        if recovered_match
                        else status["recovered"].split(",", 1)[0]
                    ),
                    speed=status["speed"].split(" @ ", 1)[0].split(
                        " (",
                        1,
                    )[0],
                    eta=eta_match.group(1) if eta_match else status["eta"],
                )
                displayed_status = status.copy()

        process.wait()

    if process.returncode not in (0, 1):

        print()
        warn("Phase Failed")
        sys.exit(1)

    output = "".join(output)

    recovery_details = parse_recovery_details(output)
    new_recovered = recovery_details["newRecovered"] if recovery_details else 0
    total_recovered = recovery_details["totalRecovered"] if recovery_details else 0
    duration = time.time() - start

    print()

    return {
        "phase": phase_id,
        "duration": duration,
        "returncode": process.returncode,
        "output": output,
        "newRecovered": new_recovered,
        "totalRecovered": total_recovered,
        "recoveryDetails": recovery_details,
    }