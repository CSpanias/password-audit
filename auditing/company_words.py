"""Company wordlist selection and reuse reminders for audit runs."""

import json
from pathlib import Path

from analysis.parsers import load_company_words
from common.console import info, warn


def prepare_company_word_sources(
    generated_path,
    custom_path=None,
    state_path=None,
    default_custom_path="company-words.txt",
):
    """Return generated and optional curated wordlists plus a reuse snapshot."""
    generated_path = Path(generated_path)
    if custom_path is None:
        candidate = Path(default_custom_path)
        custom_path = candidate if candidate.is_file() else None
    else:
        custom_path = Path(custom_path)

    if custom_path and custom_path.resolve() == generated_path.resolve():
        custom_path = None

    sources = [generated_path]
    if custom_path is None:
        info(
            "No curated company wordlist supplied. Using generated "
            "domain/account terms only. For stronger company-specific "
            "analysis, add roughly 10-20 terms to ./company-words.txt or "
            "pass --company-words PATH. This list is optional."
        )
        return sources, None

    custom_terms = load_company_words(custom_path)
    if not custom_terms:
        warn(f"Curated company wordlist is empty: {custom_path}")
        return sources, None

    sources.append(custom_path)
    stat = custom_path.stat()
    snapshot = {
        "name": custom_path.name,
        "size": stat.st_size,
        "modified_ns": stat.st_mtime_ns,
    }

    previous_snapshot = _read_snapshot(state_path)
    if previous_snapshot == snapshot:
        warn(
            "The curated company wordlist appears unchanged since the "
            "previous audit. Confirm it is tailored to this assessment."
        )
    elif previous_snapshot is None:
        info(
            f"Using {len(custom_terms)} curated company-specific terms from "
            f"{custom_path}. This file is reused, not regenerated; review it "
            "for each assessment."
        )
    else:
        info(
            f"Curated company wordlist updated since the previous audit "
            f"({len(custom_terms)} terms)."
        )

    return sources, snapshot


def save_company_word_snapshot(state_path, snapshot):
    """Persist only wordlist file metadata for the next audit's reminder."""
    try:
        Path(state_path).write_text(
            json.dumps(snapshot, sort_keys=True),
            encoding="utf-8",
        )
    except OSError as exc:
        warn(f"Unable to save company wordlist reminder state: {exc}")


def _read_snapshot(state_path):
    if state_path is None:
        return None

    state_path = Path(state_path)
    if not state_path.exists():
        return None

    try:
        snapshot = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        warn(f"Unable to read company wordlist reminder state: {exc}")
        return None

    return snapshot
