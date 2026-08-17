"""
LM password workflows.
"""

import subprocess

from pathlib import Path

from cracking.hashcat import windows_path
from ntds.parsers import parse_ntds_file, load_potfile, load_lm_results
from ntds.results import build_results
from ntds.exports import export_results


def map_lm_passwords(
    ntds_file,
    potfile,
    lm_results,
    output_dir,
):
    """
    Map recovered LM passwords back to user accounts.

    Args:
        ntds_file:
            NTDS dataset.

        potfile:
            Hashcat potfile.

        lm_results:
            LM recovery results generated using
            hashcat --show.

        output_dir:
            Output directory.

    Returns:
        dict:
            Generated results.
    """

    output_dir = Path(output_dir)

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    entries = parse_ntds_file(ntds_file)

    results = build_results(
        entries=entries,
        hash_lookup=load_potfile(potfile),
        lm_lookup=load_lm_results(lm_results),
    )

    export_results(
        results,
        output_dir,
    )

    return results


def generate_lm_results(
    hashcat_binary,
    hash_file,
    potfile,
    output_file,
):
    """
    Generate LM recovery results using hashcat --show.

    Args:
        hashcat_binary:
            Hashcat executable.

        hash_file:
            LM hash dataset.

        potfile:
            Hashcat potfile.

        output_file:
            Destination file.

    Returns:
        Path:
            Generated results file.
    """

    command = [
        hashcat_binary,
        "-m",
        "3000",
        "--show",
        windows_path(str(hash_file)),
        "--potfile-path",
        windows_path(str(potfile)),
    ]

    result = subprocess.run(
        command,
        cwd=Path(hashcat_binary).parent,
        capture_output=True,
        text=True,
    )

    output_file = Path(output_file)

    output_file.write_text(
        result.stdout,
        encoding="utf-8",
    )

    return output_file