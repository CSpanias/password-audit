"""
Campaign results output.

This module provides helpers for writing campaign result data
to disk.
"""

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path

from common.console import ok
from cracking.constants import HISTORY_DIR


def _write_json_atomically(output_file, data):
    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output_file.parent,
            prefix=f".{output_file.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            json.dump(data, handle, indent=4)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary_path, output_file)
        temporary_path = None

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def write_results(results):
    """
    Write campaign results to disk.

    Campaign execution statistics are written to a JSON file
    located alongside the target hash dataset.

    Args:
        results:
            Campaign execution results.

    Returns:
        str:
            Path to the generated results file.
    """

    campaign = results["campaign"]

    output_file = (
        Path(results["hashDataset"]).parent
        / f"{campaign}-results.json"
    )

    _write_json_atomically(output_file, results)

    return output_file


def archive_results(results):
    """
    Archive campaign results to the history directory.

    Historical campaign results are retained to support attack
    effectiveness analysis, ROI reporting, and campaign
    duration estimation.

    Args:
        results:
            Campaign execution results.

    Returns:
        Path:
            Path to the archived results file.
    """

    HISTORY_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    archive_file = (
        HISTORY_DIR
        / f"{timestamp}-{results['campaign']}.json"
    )

    _write_json_atomically(archive_file, results)

    return archive_file

def load_results(hash_file, campaign_name):
    """
    Load an existing campaign results file.

    Args:
        hash_file:
            Target hash dataset.

        campaign_name:
            Campaign identifier.

    Returns:
        dict | None:
            Existing results, if present.
    """

    output_file = (
        Path(hash_file).parent
        / f"{campaign_name}-results.json"
    )

    if not output_file.exists():
        return None

    with open(output_file, encoding="utf-8") as handle:
        return json.load(handle)