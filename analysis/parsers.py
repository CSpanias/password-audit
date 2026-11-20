"""
Input parsing functions used by password analysis.

This module is responsible for loading datasets and configuration
files required during analysis, including recovered passwords,
domain policy information, organisation-specific terminology,
and supporting account lists.
"""

import json
import re
from os import PathLike

from ntds.parsers import parse_ntds_line

# ---------------------------------------------------------------------------
# Password Data
# ---------------------------------------------------------------------------

def load_passwords(path):
    """
    Load recovered plaintext passwords.

    Expected format:

        username:password

    Returns:
        List[dict]
    """

    passwords = []

    with open(path, encoding="utf-8", errors="ignore") as f:

        for line in f:
            line = line.strip()

            if ":" not in line:
                continue

            username, password = line.split(":", 1)

            passwords.append({
                "username": username,
                "password": password
            })

    return passwords


def load_ntds_users(path):
    """Load organiser-generated user records for NTLM hash comparisons."""
    accounts = {}
    with open(path, encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            if not line.strip():
                continue
            entry = parse_ntds_line(line)
            if (
                entry is None
                or not entry["username"]
                or entry["machine"]
                or entry["raw"] != line.strip()
                or not entry["rid"].isdigit()
                or not re.fullmatch(r"[0-9a-fA-F]{32}", entry["ntlm"])
            ):
                raise ValueError(f"Invalid NTDS user record at {path}, line {line_number}.")
            key = entry["username"].casefold()
            previous = accounts.get(key)
            if previous and (
                previous["rid"] != entry["rid"]
                or previous["ntlm"].casefold() != entry["ntlm"].casefold()
            ):
                raise ValueError(f"Conflicting NTDS user records at {path}, line {line_number}.")
            accounts[key] = entry
    return list(accounts.values())


# ---------------------------------------------------------------------------
# Generic Lists
# ---------------------------------------------------------------------------

def _valid_privileged_domain(domain):
    return (
        isinstance(domain, dict)
        and isinstance(domain.get("name"), str)
        and bool(domain["name"].strip())
        and isinstance(domain.get("sid"), str)
        and bool(re.fullmatch(
            r"S-1-5-21-(?:\d+-){2}\d+", domain["sid"], re.IGNORECASE
        ))
    )


def load_privileged_users(path):
    """Load the organiser's privileged membership dataset."""
    if path is None:
        return {
            "status": "unavailable",
            "accounts": [],
            "warnings": ["No privileged group membership dataset was supplied."],
        }

    with open(path, encoding="utf-8") as file:
        data = json.load(file)
    if (
        not isinstance(data, dict)
        or data.get("status") not in {"available", "incomplete", "unavailable"}
        or not isinstance(data.get("accounts"), list)
        or not isinstance(data.get("warnings"), list)
        or any(not isinstance(warning, str) or not warning for warning in data["warnings"])
        or (data["status"] != "available" and not data["warnings"])
        or (data["status"] == "available" and data["warnings"])
        or (data["status"] == "unavailable" and data["accounts"])
        or any(
            not isinstance(account, dict)
            or not isinstance(account.get("username"), str)
            or not account["username"]
            or not isinstance(account.get("groups"), list)
            or not account["groups"]
            or any(not isinstance(group, str) or not group for group in account["groups"])
            for account in data["accounts"]
        )
        or len({account["username"].casefold() for account in data["accounts"]})
        != len(data["accounts"])
        or any(
            key in data and not _valid_privileged_domain(data[key])
            for key in ("confirmed_domain", "source_domain")
        )
        or (
            "confirmed_domain" in data and "source_domain" in data
            and (
                data["confirmed_domain"]["sid"].casefold()
                != data["source_domain"]["sid"].casefold()
                or data["confirmed_domain"]["name"].casefold()
                != data["source_domain"]["name"].casefold()
            )
        )
    ):
        raise ValueError(f"Invalid privileged group membership dataset: {path}")
    return data


def load_list(path):
    """
    Load a newline-delimited list of values.

    Empty lines are ignored.

    Returns:
        List[str]
    """

    if not path:
        return []

    with open(path, encoding="utf-8", errors="ignore") as f:

        return [
            line.strip()
            for line in f
            if line.strip()
        ]


# ---------------------------------------------------------------------------
# Domain Policy
# ---------------------------------------------------------------------------

def load_domain_policy(path):
    """
    Load domain password policy information.

    Expected format:

        Key: Value

    Returns:
        Dict[str, str]
    """

    policy = {}

    with open(path, encoding="utf-8") as f:

        for line in f:

            if ":" not in line:
                continue

            key, value = line.split(":", 1)

            policy[key.strip()] = value.strip()

    return policy


# ---------------------------------------------------------------------------
# Organisation Terms
# ---------------------------------------------------------------------------

def load_company_words(path):
    """
    Load one or more organisation-specific wordlists.

    Terms are normalised to lowercase and deduplicated while preserving their
    first-seen order.

    Returns:
        List[str]
    """

    if not path:
        return []

    paths = [path] if isinstance(path, (str, PathLike)) else path
    words = []
    seen = set()

    for wordlist_path in paths:
        with open(wordlist_path, encoding="utf-8") as wordlist:
            for line in wordlist:
                term = line.strip().lower()
                if term and term not in seen:
                    words.append(term)
                    seen.add(term)

    return words


# ---------------------------------------------------------------------------
# LM Users
# ---------------------------------------------------------------------------

def load_lm_users(path):
    """
    Load accounts identified as storing LM password hashes.

    The input file is produced by NTDS Organiser and contains
    NTDS records for accounts where an LM hash was present.
    Username, RID, LM hash, and NTLM hash values are extracted
    to provide a structured dataset suitable for reporting and
    further analysis.

    Args:
        path (str):
            Path to the lm-users.txt file.

    Returns:
        list:
            List of dictionaries containing:

            - username
            - rid
            - lm_hash
            - nt_hash
    """

    if not path:
        return []

    users = []

    with open(path, encoding="utf-8") as f:

        for line in f:

            fields = line.strip().split(":")

            if len(fields) < 4:
                continue

            users.append({
                "username": fields[0],
                "rid": fields[1],
                "lm_hash": fields[2],
                "nt_hash": fields[3],
            })

    return users