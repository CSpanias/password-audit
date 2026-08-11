"""
NTDS parsing functions.

This module is responsible for loading and parsing NTDS,
BloodHound, and Hashcat potfile data used throughout the
password-audit framework.

Functions in this module should focus solely on converting
raw input data into structured Python objects.
"""


import json
import zipfile


# ---------------------------------------------------------------------------
# NTDS Parsing
# ---------------------------------------------------------------------------

def parse_ntds_line(line):
    """
    Parse a single NTDS account record.

    NTDS records are expected in secretsdump format. Account
    status and machine-account information are derived where
    possible.

    Args:
        line (str):
            Raw NTDS record.

    Returns:
        dict | None:
            Parsed account record, or None if the record
            cannot be processed.
    """

    line = line.strip()

    if not line:
        return None

    enabled = "(status=Enabled)" in line

    record = line.split()[0]

    fields = record.split(":")

    if len(fields) < 4:
        return None

    username = fields[0]
    rid = fields[1]
    lm_hash = fields[2]
    nt_hash = fields[3]

    return {
        "raw": record,
        "username": username,
        "rid": rid,
        "lm": lm_hash,
        "ntlm": nt_hash,
        "enabled": enabled,
        "machine": username.endswith("$")
    }


def parse_ntds_file(path):
    """
    Parse an NTDS dump file.

    Each line is processed individually and converted into a
    structured account record.

    Args:
        path (str | Path):
            NTDS dump file.

    Returns:
        list:
            Parsed NTDS account records.
    """

    entries = []

    with open(path, encoding="utf-8", errors="ignore") as f:

        for line in f:

            entry = parse_ntds_line(line)

            if entry:
                entries.append(entry)

    return entries


# ---------------------------------------------------------------------------
# BloodHound Data
# ---------------------------------------------------------------------------

def load_bloodhound_zip(zip_path):
    """
    Load BloodHound data from a ZIP archive.

    The archive is searched for users.json, groups.json,
    and domains.json files.

    Args:
        zip_path (str | Path):
            BloodHound ZIP archive.

    Returns:
        tuple:
            - dict | None: users.json data
            - dict | None: groups.json data
            - dict | None: domains.json data
    """

    users = None
    groups = None
    domains = None

    with zipfile.ZipFile(zip_path) as z:

        for name in z.namelist():
            lower = name.lower()

            if lower.endswith("users.json"):
                users = json.loads(z.read(name).decode("utf-8"))

            elif lower.endswith("groups.json"):
                groups = json.loads(z.read(name).decode("utf-8"))

            elif lower.endswith("domains.json"):
                domains = json.loads(z.read(name).decode("utf-8"))

    return users, groups, domains


# ---------------------------------------------------------------------------
# Potfile Parsing
# ---------------------------------------------------------------------------

def load_potfile(path):
    """
    Load a Hashcat potfile.

    Hash values are normalised to lowercase to support
    case-insensitive lookups during password mapping.

    Args:
        path (str | Path):
            Potfile path.

    Returns:
        dict:
            Hash-to-password mapping.
    """

    mapping = {}

    try:
        with open(path, encoding="utf-16") as f:
            lines = f.readlines()

    except UnicodeError:
        with open(path, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

    for line in lines:

        line = line.rstrip()

        if ":" not in line:
            continue

        hash_value, password = line.split(":", 1)
        mapping[hash_value.lower()] = password

    return mapping