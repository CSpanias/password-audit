"""Local campaign statistics and opt-in sharing."""

import hashlib
import json
import math
import statistics
from pathlib import Path
from uuid import UUID

from rich.table import Table

from common.console import console
from cracking.constants import HISTORY_DIR
from cracking.hashcat import live_status_flags
from cracking.results import _write_json_atomically
from cracking.validation import validate_public_label


def describe_settings(flags):
    """Describe shareable settings and retain a local-only compatibility fingerprint."""
    normalized = live_status_flags(flags)
    optimized = False
    other = False
    index = 0
    while index < len(normalized):
        flag = normalized[index]
        if flag in ("-O", "--optimized-kernel-enable"):
            optimized = True
        elif flag == "--status" or flag.startswith("--status-timer="):
            pass
        elif flag in ("-w", "--workload-profile", "-d", "--backend-devices",
                      "-D", "--opencl-device-types"):
            if index + 1 >= len(normalized) or str(normalized[index + 1]).startswith("-"):
                other = True
            else:
                index += 1
        elif flag.startswith(("--workload-profile=", "--backend-devices=",
                              "--opencl-device-types=")):
            pass
        else:
            other = True
        index += 1
    fingerprint = hashlib.sha256(
        json.dumps(normalized, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    return {"optimized": optimized, "otherFlags": other, "localFingerprint": fingerprint}


def load_history():
    if not HISTORY_DIR.exists():
        return []
    history = []
    for path in sorted(HISTORY_DIR.glob("*.json")):
        with path.open(encoding="utf-8") as handle:
            history.append(json.load(handle))
    return history


def _validate_record(record):
    fields = {
        "id", "hashMode", "type", "wordlist", "rule", "hasRule", "position",
        "optimized", "otherFlags", "totalHashes", "remainingBefore",
        "newRecovered", "duration",
    }
    if not isinstance(record, dict) or set(record) != fields:
        raise ValueError("Invalid statistics record fields.")
    try:
        identifier = UUID(record["id"])
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Invalid statistics record ID.") from exc
    if identifier.version != 4 or str(identifier) != record["id"]:
        raise ValueError("Statistics record IDs must be canonical random UUIDs.")
    if (
        not isinstance(record["hashMode"], str)
        or not record["hashMode"].isascii()
        or not record["hashMode"].isdigit()
        or len(record["hashMode"]) > 8
    ):
        raise ValueError("Invalid statistics hash mode.")
    if record["type"] not in ("wordlist", "loopback"):
        raise ValueError("Invalid statistics attack type.")
    if any(type(record[key]) is not bool for key in ("hasRule", "optimized", "otherFlags")):
        raise ValueError("Invalid statistics settings.")
    for key in ("wordlist", "rule"):
        if record[key] is not None:
            validate_public_label(record[key])
    if record["type"] == "loopback" and record["wordlist"] is not None:
        raise ValueError("Loopback wordlists cannot have a public label.")
    if record["rule"] is not None and not record["hasRule"]:
        raise ValueError("A rule label requires a rule.")
    if record["type"] == "loopback" and not record["hasRule"]:
        raise ValueError("A loopback attack requires a rule.")
    for key in ("position", "totalHashes", "remainingBefore", "newRecovered"):
        if type(record[key]) is not int or record[key] < 0:
            raise ValueError(f"Invalid statistics {key}.")
    if (
        record["position"] < 1
        or record["remainingBefore"] > record["totalHashes"]
        or record["newRecovered"] > record["remainingBefore"]
    ):
        raise ValueError("Inconsistent statistics recovery counts.")
    duration = record["duration"]
    if type(duration) not in (int, float) or not math.isfinite(duration) or duration < 0:
        raise ValueError("Invalid statistics duration.")
    return record


def _record_from_phase(campaign, phase):
    data = phase.get("statistics")
    if not isinstance(data, dict) or not isinstance(data.get("recovery"), dict):
        return None
    recovery = data["recovery"]
    settings = data["settings"]
    record = {
        "id": data["id"],
        "hashMode": str(campaign["hashMode"]),
        "type": data["type"],
        "wordlist": data["wordlist"],
        "rule": data["rule"],
        "hasRule": data["hasRule"],
        "position": data["position"],
        "optimized": settings["optimized"],
        "otherFlags": settings["otherFlags"],
        "totalHashes": recovery["totalHashes"],
        "remainingBefore": recovery["remainingBefore"],
        "newRecovered": recovery["newRecovered"],
        "duration": phase["duration"],
    }
    return _validate_record(record)


def local_statistics():
    """Return completed measured records with local-only estimation context."""
    entries = []
    skipped = 0
    for campaign in load_history():
        if campaign.get("state") != "completed":
            continue
        for phase in campaign.get("phases", []):
            record = _record_from_phase(campaign, phase)
            if record is None:
                skipped += 1
                continue
            entries.append((
                record,
                phase["statistics"]["settings"]["localFingerprint"],
            ))
    return entries, skipped


def _shared_file():
    return HISTORY_DIR.parent / "imported-statistics.json"


def _read_exchange(path):
    with Path(path).open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or set(data) != {"version", "records"}:
        raise ValueError("Invalid statistics exchange file.")
    if type(data["version"]) is not int or data["version"] != 1:
        raise ValueError("Unsupported statistics exchange version.")
    if not isinstance(data["records"], list):
        raise TypeError("Statistics records must be a list.")
    records = {}
    for item in data["records"]:
        record = _validate_record(item)
        if record["id"] in records and records[record["id"]] != record:
            raise ValueError("Conflicting statistics records share an ID.")
        records[record["id"]] = record
    return records


def imported_statistics():
    path = _shared_file()
    return _read_exchange(path) if path.exists() else {}


def _merge_records(*collections):
    merged = {}
    for records in collections:
        for record in records:
            key = record["id"]
            if key in merged and merged[key] != record:
                raise ValueError("Conflicting statistics records share an ID.")
            merged[key] = record
    return merged


def export_statistics(path):
    entries, skipped = local_statistics()
    records = _merge_records(record for record, _ in entries)
    if not records:
        raise ValueError("No measured local statistics are available to export.")
    data = {"version": 1, "records": list(records.values())}
    with Path(path).open("x", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, allow_nan=False)
        handle.write("\n")
    return len(records), skipped


def import_statistics(path):
    incoming = _read_exchange(path)
    existing = imported_statistics()
    local, _ = local_statistics()
    known = _merge_records(existing.values(), (record for record, _ in local))
    _merge_records(known.values(), incoming.values())
    added = {key: value for key, value in incoming.items() if key not in known}
    if added:
        target = _shared_file()
        target.parent.mkdir(parents=True, exist_ok=True)
        _write_json_atomically(target, {"version": 1, "records": list(
            _merge_records(existing.values(), added.values()).values()
        )})
    return len(added), len(incoming) - len(added)


def attack_identity(record):
    """Return an exact, contributor-labelled identity, or None if incomparable."""
    if (
        record["wordlist"] is None
        or (record["hasRule"] and record["rule"] is None)
        or record["otherFlags"]
    ):
        return None
    wordlist = record["wordlist"]
    rule = record["rule"]
    return (
        record["hashMode"], record["type"],
        wordlist["name"], wordlist["version"],
        rule["name"] if rule else None, rule["version"] if rule else None,
        record["optimized"],
    )


def phase_identity(hash_mode, phase, settings):
    labels = phase.get("statistics", {})
    return attack_identity({
        "hashMode": str(hash_mode),
        "type": phase["type"],
        "wordlist": labels.get("wordlist"),
        "rule": labels.get("rule"),
        "hasRule": bool(phase.get("rule")),
        "otherFlags": settings["otherFlags"],
        "optimized": settings["optimized"],
    })


def print_phase_statistics(args=None):
    if args is not None and getattr(args, "export_file", None):
        count, skipped = export_statistics(args.export_file)
        print(f"Exported {count} local phase records to {args.export_file}. Review before sharing.")
        if skipped:
            print(f"Excluded {skipped} phases without usable statistics.")
        return
    if args is not None and getattr(args, "import_file", None):
        added, duplicates = import_statistics(args.import_file)
        print(f"Imported {added} phase records; {duplicates} already present.")
        return

    local, skipped = local_statistics()
    records = _merge_records(
        (record for record, _ in local), imported_statistics().values()
    )
    groups = {}
    unmatched = {}
    for record in records.values():
        key = attack_identity(record)
        if key is None:
            category = (
                record["hashMode"],
                "loopback" if record["type"] == "loopback" else
                ("public" if record["wordlist"] else "custom"),
                "none" if not record["hasRule"] else
                ("public" if record["rule"] else "custom"),
                record["otherFlags"],
            )
            unmatched.setdefault(category, []).append(record)
            continue
        groups.setdefault(key, []).append(record)

    if not records and not skipped:
        print("No campaign history available.")
        return
    if groups:
        table = Table(title="Comparable Attack Statistics (contributor-labelled)")
        for name in ("Hash", "Wordlist", "Rule", "Optimized", "Runs", "Median yield",
                     "Median recovered/min", "Positions"):
            table.add_column(name)
        for key, items in sorted(groups.items(), key=lambda item: str(item[0])):
            mode, _, name, version, rule, rule_version, optimized = key
            yields = [
                100 * item["newRecovered"] / item["remainingBefore"]
                for item in items if item["remainingBefore"] > 0
            ]
            rates = [
                60 * item["newRecovered"] / item["duration"]
                for item in items if item["duration"] > 0
            ]
            positions = sorted({item["position"] for item in items})
            table.add_row(
                {"1000": "NTLM", "3000": "LM"}.get(mode, mode),
                f"{name} ({version})", f"{rule} ({rule_version})" if rule else "None",
                "Yes" if optimized else "No", str(len(items)),
                f"{statistics.median(yields):.2f}% (n={len(yields)})" if yields else "Unknown",
                f"{statistics.median(rates):.2f} (n={len(rates)})" if rates else "Unknown",
                ", ".join(str(position) for position in positions),
            )
        console.print(table)
        print("Yield is newly recovered Hashcat digests / digests remaining at phase start.")
        print("Order, prior recoveries, hardware and contributor labels affect comparisons.")
    if unmatched:
        table = Table(title="Broad Categories (different inputs, not identical attacks)")
        for name in ("Hash", "Wordlist", "Rule", "Other flags", "Runs", "Median yield"):
            table.add_column(name)
        for (mode, wordlist, rule, other), items in sorted(unmatched.items()):
            yields = [
                100 * item["newRecovered"] / item["remainingBefore"]
                for item in items if item["remainingBefore"] > 0
            ]
            table.add_row(
                {"1000": "NTLM", "3000": "LM"}.get(mode, mode),
                wordlist, rule, "Yes" if other else "No", str(len(items)),
                f"{statistics.median(yields):.2f}% (n={len(yields)})" if yields else "Unknown",
            )
        console.print(table)
        print("Broad-category observations may use different inputs and settings.")
    if skipped:
        print(f"Excluded {skipped} phases without usable statistics.")
