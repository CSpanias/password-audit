"""
Hashcat Scheduler constants.

This module contains configuration defaults and static values
used throughout the password recovery campaign workflow.
"""
from pathlib import Path


# Default Hashcat installation directory.
# May be overridden within campaign configurations.
DEFAULT_HASHCAT_DIR = "/mnt/c/pentest/tools/hashcat"

HISTORY_DIR = (
    Path.home()
    / ".password-audit"
    / "history"
)