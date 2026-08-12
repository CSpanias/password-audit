"""
Campaign scheduling workflow.

This module coordinates the execution of Hashcat campaign
phases, tracks recovery statistics, and manages campaign
results.
"""

import os

from datetime import datetime

from common.console import (
    warn,
)

from common.utils import (
    human_time,
)

from cracking.constants import (
    DEFAULT_HASHCAT_DIR,
)

from cracking.hashcat import (
    run_phase,
    validate_file,
)

from cracking.loopback import (
    generate_loopback_wordlist,
)

from cracking.results import (
    write_results,
)


def run_campaign(
        config,
        hash_file,
        campaign_name,
        debug=False
    ):
    """
    Execute a password recovery campaign.

    Enabled campaign phases are executed sequentially using
    Hashcat. Recovery statistics are collected after each
    phase and written to a campaign results file.

    Args:
        config:
            Campaign configuration.

        hash_file:
            Target hash dataset.

        campaign_name:
            Campaign identifier used for reporting.

        debug:
            Display verbose execution information.

    Returns:
        dict:
            Campaign execution results.
    """

    parameters = config["parameters"]

    hash_file = os.path.abspath(hash_file)

    hashcat_dir = parameters.get("hashcatDir", DEFAULT_HASHCAT_DIR)
    hashcat_binary = parameters.get(
        "hashcatBinary",
        os.path.join(hashcat_dir, "hashcat.exe")
    )
    hashcat_potfile = os.path.join(hashcat_dir, "hashcat.potfile")
    wordlist_dir = os.path.join(hashcat_dir, "wordlists")
    rules_dir = os.path.join(hashcat_dir, "rules")

    hash_mode = parameters["hashMode"]
    flags = parameters.get("flags", [])

    results = {
            "campaign": campaign_name,
            "hashMode": hash_mode,
            "hashDataset": hash_file,
            "started": datetime.now().isoformat(),
            "phases": [],
        }

    validate_file(hash_file)
    validate_file(hashcat_binary)

    enabled_phases = [
        phase
        for phase in config["phases"]
        if phase.get("enabled", True)
    ]

    for index, phase in enumerate(enabled_phases, start=1):

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

        result = run_phase(
            phase_id=index,
            total_phases=len(enabled_phases),
            hashcat_binary=hashcat_binary,
            hash_file=hash_file,
            hash_mode=hash_mode,
            hashcat_potfile=hashcat_potfile,
            wordlist=wordlist,
            rule=rule,
            flags=flags,
            debug=debug
        )

        results["phases"].append(
            {
                "id": phase["id"],
                "wordlist": phase["wordlist"],
                "rule": phase.get("rule"),
                "duration": round(result["duration"], 2),
                "durationHuman": human_time(result["duration"]),
                "newRecovered": result["newRecovered"],
                "totalRecovered": result["totalRecovered"],
                "returnCode": result["returncode"]
            }
        )

        write_results(results)

    results["completed"] = datetime.now().isoformat()

    return results