"""
Campaign results output.

This module provides helpers for writing campaign result data
to disk.
"""

import json

from pathlib import Path

from common.console import (
    ok,
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