"""Offline matching against Pwned Passwords NTLM range files."""

import re
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

from common.utils import mask_password

_RANGE_LINE = re.compile(r"([0-9A-Fa-f]{27}):([0-9]+)")
_RANGE_WORKERS = 4


class HibpDataError(ValueError):
    """Raised when the supplied local Pwned Passwords data cannot be checked."""


def _check_range(directory, prefix, suffixes):
    path = directory / prefix
    official_path = directory / f"{prefix}.txt"
    if path.is_file() and official_path.is_file():
        raise HibpDataError(
            f"Multiple HIBP files exist for range {prefix}: {directory}"
        )
    if official_path.is_file():
        path = official_path
    if not path.is_file():
        raise HibpDataError(
            f"HIBP dataset is incomplete or still downloading: required NTLM "
            f"range {prefix} is missing from {directory}. Complete and verify "
            "the download, then run the check again."
        )

    matches = []
    entries = 0
    matched_suffixes = set()
    with path.open(encoding="ascii") as file:
        for line_number, line in enumerate(file, 1):
            match = _RANGE_LINE.fullmatch(line.rstrip("\r\n"))
            if match is None or int(match[2]) <= 0:
                raise HibpDataError(
                    f"Invalid HIBP NTLM range at {path}, line {line_number}. "
                    "Ensure the download has completed and the range is intact."
                )
            entries += 1
            suffix = match[1].upper()
            if suffix in suffixes:
                if suffix in matched_suffixes:
                    raise HibpDataError(
                        f"Duplicate HIBP NTLM hash at {path}, line {line_number}."
                    )
                matched_suffixes.add(suffix)
                masked_hash = mask_password((prefix + suffix).lower())
                matches.extend(
                    {"username": username, "masked_hash": masked_hash}
                    for username in suffixes[suffix]
                )
    if not entries:
        raise HibpDataError(f"Empty HIBP NTLM range: {path}")
    return matches


def check_hibp(accounts, directory, progress_callback=None):
    """Match organised users against the ranges needed for their NT hashes."""
    directory = Path(directory)
    if not directory.is_dir():
        raise HibpDataError(f"HIBP range directory does not exist: {directory}")
    if accounts is None:
        raise HibpDataError(
            "HIBP analysis requires organised NTDS user records (--ntds-users)."
        )

    prefixes = {}
    for account in accounts:
        ntlm = account["ntlm"].upper()
        prefixes.setdefault(ntlm[:5], {}).setdefault(ntlm[5:], []).append(
            account["username"]
        )

    if progress_callback is not None:
        progress_callback(0, len(prefixes))

    range_matches = [[] for _ in prefixes]
    if prefixes:
        work = iter(enumerate(prefixes.items()))
        with ThreadPoolExecutor(max_workers=_RANGE_WORKERS) as executor:
            in_flight = {}

            def submit_next():
                try:
                    index, (prefix, suffixes) = next(work)
                except StopIteration:
                    return
                in_flight[executor.submit(_check_range, directory, prefix, suffixes)] = index

            for _ in range(min(_RANGE_WORKERS, len(prefixes))):
                submit_next()
            completed = 0
            while in_flight:
                finished, _ = wait(in_flight, return_when=FIRST_COMPLETED)
                for future in finished:
                    index = in_flight.pop(future)
                    range_matches[index] = future.result()
                    completed += 1
                    if progress_callback is not None:
                        progress_callback(completed, len(prefixes))
                for _ in finished:
                    submit_next()

    matches = [match for range_result in range_matches for match in range_result]
    matches.sort(key=lambda account: account["username"].casefold())
    return {
        "checked": len(accounts),
        "accounts": [account["username"] for account in matches],
        "count": len(matches),
        "examples": matches[:5],
    }
