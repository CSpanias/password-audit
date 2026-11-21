"""Offline matching against Pwned Passwords NTLM range files."""

import re
from pathlib import Path

_RANGE_LINE = re.compile(r"([0-9A-Fa-f]{27}):([0-9]+)")


def check_hibp(accounts, directory):
    """Match organised users against the ranges needed for their NT hashes."""
    directory = Path(directory)
    if not directory.is_dir():
        raise ValueError(f"HIBP range directory does not exist: {directory}")
    if accounts is None:
        raise ValueError("HIBP analysis requires organised NTDS user records (--ntds-users).")

    prefixes = {}
    for account in accounts:
        ntlm = account["ntlm"].upper()
        prefixes.setdefault(ntlm[:5], {}).setdefault(ntlm[5:], []).append(
            account["username"]
        )

    matches = []
    for prefix, suffixes in prefixes.items():
        path = directory / prefix
        official_path = directory / f"{prefix}.txt"
        if path.is_file() and official_path.is_file():
            raise ValueError(f"Multiple HIBP files exist for range {prefix}: {directory}")
        if official_path.is_file():
            path = official_path
        if not path.is_file():
            raise ValueError(f"Missing HIBP NTLM range {prefix} in {directory}.")

        entries = 0
        matched_suffixes = set()
        with path.open(encoding="ascii") as file:
            for line_number, line in enumerate(file, 1):
                match = _RANGE_LINE.fullmatch(line.rstrip("\r\n"))
                if match is None or int(match[2]) <= 0:
                    raise ValueError(f"Invalid HIBP NTLM range at {path}, line {line_number}.")
                entries += 1
                suffix = match[1].upper()
                if suffix in suffixes:
                    if suffix in matched_suffixes:
                        raise ValueError(f"Duplicate HIBP NTLM hash at {path}, line {line_number}.")
                    matched_suffixes.add(suffix)
                    matches.extend(suffixes[suffix])
        if not entries:
            raise ValueError(f"Empty HIBP NTLM range: {path}")

    matches.sort(key=str.casefold)
    return {"checked": len(accounts), "accounts": matches, "count": len(matches)}
