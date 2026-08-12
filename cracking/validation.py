"""
Campaign validation.

This module validates campaign configurations before
execution to ensure required settings and phases are
present and correctly defined.
"""

VALID_PHASE_TYPES = {
    "wordlist",
    "loopback",
}


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