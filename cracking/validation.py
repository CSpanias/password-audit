"""
Campaign validation.

This module validates campaign configurations before
execution to ensure required settings and phases are
present and correctly defined.
"""

import re

VALID_PHASE_TYPES = {
    "wordlist",
    "loopback",
}

LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def validate_public_label(label):
    if not isinstance(label, dict) or set(label) != {"name", "version"}:
        raise ValueError("Public labels must contain only name and version.")
    if any(not isinstance(value, str) or not LABEL_PATTERN.fullmatch(value)
           for value in label.values()):
        raise ValueError("Public label names and versions must be short identifiers.")


def validate_campaign(config):
    """
    Validate a campaign configuration.

    Args:
        config:
            Campaign configuration.

    Raises:
        ValueError:
            If the campaign configuration is invalid.

    Returns:
        None
    """

    if "parameters" not in config:
        raise ValueError("Campaign is missing parameters section.")

    if "phases" not in config:
        raise ValueError("Campaign is missing phases section.")

    parameters = config["parameters"]
    phases = config["phases"]

    if "hashMode" not in parameters:
        raise ValueError("Campaign is missing hashMode parameter.")

    mode = parameters["hashMode"]
    if (
        isinstance(mode, bool)
        or not isinstance(mode, (str, int))
        or not str(mode).isascii()
        or not str(mode).isdigit()
        or len(str(mode)) > 8
    ):
        raise ValueError("hashMode must be a non-negative numeric Hashcat mode.")
    flags = parameters.get("flags", [])
    if not isinstance(flags, list) or not all(isinstance(flag, str) for flag in flags):
        raise ValueError("Campaign flags must be a list of strings.")

    profile = parameters.get("hardwareProfile")
    if profile is not None and (not isinstance(profile, str) or not profile.strip()):
        raise ValueError("hardwareProfile must be a non-empty string.")

    if not phases:
        raise ValueError("Campaign does not contain any phases.")

    enabled_phases = [
        phase
        for phase in phases
        if phase.get("enabled", True)
    ]

    if not enabled_phases:
        raise ValueError("Campaign does not contain any enabled phases.")

    seen_ids = set()

    for phase in phases:

        phase_id = phase.get("id")

        if not phase_id:
            raise ValueError("Campaign phase is missing an id.")

        if phase_id in seen_ids:
            raise ValueError(
                f"Duplicate phase id detected: {phase_id}"
            )

        seen_ids.add(phase_id)

        phase_type = phase.get("type")

        if phase_type not in VALID_PHASE_TYPES:
            raise ValueError(
                f"Invalid phase type '{phase_type}' in phase '{phase_id}'."
            )

        if phase_type == "wordlist":

            if not phase.get("wordlist"):
                raise ValueError(
                    f"Wordlist phase '{phase_id}' is missing a wordlist."
                )

        if phase_type == "loopback":

            if not phase.get("rule"):
                raise ValueError(
                    f"Loopback phase '{phase_id}' is missing a rule."
                )

        labels = phase.get("statistics", {})
        if not isinstance(labels, dict) or set(labels) - {"wordlist", "rule"}:
            raise ValueError(f"Invalid statistics labels in phase '{phase_id}'.")
        for label in labels.values():
            validate_public_label(label)
        if "wordlist" in labels and phase_type != "wordlist":
            raise ValueError("Loopback wordlists cannot have a public label.")
        if "rule" in labels and not phase.get("rule"):
            raise ValueError("A rule label requires a rule.")