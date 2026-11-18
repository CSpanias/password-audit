"""Campaign input fingerprints used to validate safe phase skipping."""

import hashlib
import json
import os
from pathlib import Path

FINGERPRINT_VERSION = 1
CHUNK_SIZE = 1024 * 1024


def _file_fingerprint(path):
    path = Path(path)
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)

    return {
        "path": os.path.normcase(os.path.abspath(path)),
        "sha256": digest.hexdigest(),
    }


def _path_identity(path):
    return os.path.normcase(os.path.abspath(path))


def build_resume_fingerprint(
    config,
    hash_file,
    campaign_name,
    hashcat_binary,
    hashcat_potfile,
    wordlist_dir,
    rules_dir,
):
    """Fingerprint the campaign definition and its configured input files."""

    phase_inputs = []

    for phase in config["phases"]:
        if not phase.get("enabled", True):
            continue

        phase_input = {
            "id": phase["id"],
            "type": phase["type"],
        }

        if phase["type"] == "wordlist":
            phase_input["wordlist"] = _file_fingerprint(
                Path(wordlist_dir) / phase["wordlist"]
            )

        if phase.get("rule"):
            phase_input["rule"] = _file_fingerprint(
                Path(rules_dir) / phase["rule"]
            )

        phase_inputs.append(phase_input)

    manifest = {
        "campaign": campaign_name,
        "config": config,
        "hash_dataset": _file_fingerprint(hash_file),
        "hashcat_binary": _file_fingerprint(hashcat_binary),
        "hashcat_potfile": _path_identity(hashcat_potfile),
        "phase_inputs": phase_inputs,
    }
    encoded_manifest = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return {
        "version": FINGERPRINT_VERSION,
        "sha256": hashlib.sha256(encoded_manifest).hexdigest(),
    }
