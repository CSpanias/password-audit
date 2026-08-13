"""
Campaign results output.

This module provides helpers for writing campaign result data
to disk.
"""

import json

from pathlib import Path
from datetime import datetime

from common.console import (
    ok,
)

from cracking.constants import (
    HISTORY_DIR,
)


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

    with open(output_file, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=4)

    ok(f"Results written to: {output_file}")

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

    with open(archive_file, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=4)

    return archive_file