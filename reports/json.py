"""
JSON findings export.

This module exports analysis findings in a machine-readable
format suitable for integration with external tools and
reporting platforms.
"""

import json


def write_findings(path, findings):
    """
    Write findings to a JSON file.

    Args:
        path:
            Output file path.

        findings:
            Analysis findings.

    Returns:
        None
    """

    output = {
        "findings": findings
    }

    with open(path, "w", encoding="utf-8") as handle:
        json.dump(
            output,
            handle,
            indent=4,
        )