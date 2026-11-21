"""
Analysis findings.

This module converts analysis results into a structured
finding format suitable for export.

Finding definitions are loaded declaratively from YAML files in
the analysis/findings/ directory and combined with dynamic values
from analysis results to produce Finding dataclass instances.
"""

import os

import yaml

from analysis.finding import Finding
from common.utils import num_to_word


def _load_yaml_definitions():
    """
    Load all YAML finding definitions from the analysis/findings/ directory.

    Returns:
        dict: Mapping of finding id to definition dictionary.
    """
    definitions = {}
    findings_dir = os.path.join(os.path.dirname(__file__), "finding_defs")

    for filename in sorted(os.listdir(findings_dir)):
        if not filename.endswith((".yaml", ".yml")):
            continue

        filepath = os.path.join(findings_dir, filename)
        with open(filepath, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}

        for key, value in data.items():
            definitions[key] = value

    return definitions


def _other_privileged_count(results):
    admin_names = {account["username"].casefold() for account in results["admins"]["accounts"]}
    return sum(
        account["username"].casefold() not in admin_names
        for account in results["privileged_users"]["accounts"]
    )


# Mapping of finding definition keys to the results key that gates them.
# Each entry: (results_key, count_accessor)
# count_accessor is a callable that extracts the count from results[results_key]
_FINDING_GATES = {
    "password-audit": ("total_passwords", lambda r: r["total_passwords"]),
    "password-statistics": (None, lambda r: True),
    "domain-admin-passwords": ("admins", lambda r: r["admins"]["count"]),
    "privileged-passwords": ("privileged_users", _other_privileged_count),
    "lm-hashes-present": ("lm_hashes", lambda r: r["lm_hashes"]["count"]),
    "domain-admin-lm-hashes": ("lm_admins", lambda r: r["lm_admins"]["count"]),
    "non-compliant-passwords": ("password_length", lambda r: r["password_length"]["count"]),
    "password-reuse": ("password_reuse_general", lambda r: r["password_reuse_general"]["sharedPasswords"]),
    "shared-account-passwords": ("similar_account_reuse", lambda r: r["similar_account_reuse"]["count"]),
    "ntlm-hash-reuse": ("ntlm_hash_reuse", lambda r: len(r["ntlm_hash_reuse"]["groups"])),
    "hibp-passwords": ("hibp", lambda r: r["hibp"]["count"]),
    "username-derived-passwords": ("username_passwords", lambda r: r["username_passwords"]["count"]),
    "organisation-related-passwords": ("company_words", lambda r: r["company_words"]["count"]),
    "common-passwords": ("common_passwords", lambda r: r["common_passwords"]["count"]),
    "date-based-passwords": ("date_passwords", lambda r: r["date_passwords"]["count"]),
    "keyboard-patterns": ("keyboard_walks", lambda r: r["keyboard_walks"]["count"]),
}

# Metadata (severity, category, remediation) lives in the YAML definitions
# under analysis/finding_defs/ — that is the single source of truth.


def _format_description(template, count, **fmt_kwargs):
    """
    Format a finding description template with dynamic values.

    Args:
        template:
            Description template string or None.
        count:
            Numeric count for pluralisation.
        **fmt_kwargs:
            Additional keyword arguments substituted into the template.

    Returns:
        str: Formatted description.
    """
    if not template:
        return ""

    s = "s" if count != 1 else ""
    were_was = "were" if count != 1 else "was"

    values = {"count": num_to_word(count), "s": s, "were_was": were_was}
    values.update(fmt_kwargs)

    return template.format(**values)


def build_findings(results):
    """
    Build findings from analysis results.

    Finding definitions are loaded from YAML files and combined with
    dynamic values from the analysis results. Each finding is returned
    as a Finding dataclass instance.

    Args:
        results:
            Analysis results.

    Returns:
        list[Finding]:
            Findings.
    """
    definitions = _load_yaml_definitions()
    findings = []

    for finding_id, (results_key, count_accessor) in _FINDING_GATES.items():

        if results_key is None:
            count = 1
        else:
            try:
                count = count_accessor(results)
            except (KeyError, TypeError):
                continue

        if not count:
            continue

        definition = definitions.get(finding_id, {})

        title = definition.get("title", finding_id.replace("-", " ").title())
        description_template = definition.get("description_template")
        fmt_values = {}
        if finding_id == "password-audit":
            enabled = results.get("enabled_users", 0)
            fmt_values["enabled"] = num_to_word(enabled)
            fmt_values["enabled_s"] = "s" if enabled != 1 else ""
        description = _format_description(description_template, count, **fmt_values)
        if not description:
            description = definition.get("description", "")

        evidence = []
        affected_assets = []
        if finding_id == "hibp-passwords":
            affected_assets = results["hibp"]["accounts"]
        if finding_id == "ntlm-hash-reuse":
            groups = results["ntlm_hash_reuse"]["groups"]
            description += (
                f" A total of {num_to_word(results['ntlm_hash_reuse']['account_count'])} "
                "accounts are affected."
            )
            for index, group in enumerate(groups, 1):
                accounts = [
                    account["username"] + (
                        f" (selected privileged groups: {', '.join(account['groups'])})"
                        if account["groups"] else ""
                    )
                    for account in group["accounts"]
                ]
                evidence.append(f"Group {index}: " + ", ".join(accounts))
                affected_assets.extend(account["username"] for account in group["accounts"])

        finding = Finding(
            id=definition.get("id", finding_id.upper().replace("-", "-")),
            title=title,
            description=description,
            severity=definition.get("severity", "info"),
            category=definition.get("category", "general"),
            remediation=definition.get("remediation", ""),
            evidence=evidence,
            affected_assets=affected_assets,
        )

        findings.append(finding)

    return findings


def build_findings_dict(results):
    """
    Build findings from analysis results and return as plain dictionaries.

    Wrapper around build_findings() that serialises each Finding to a
    dict for backward compatibility with JSON reporting.

    Args:
        results:
            Analysis results.

    Returns:
        list[dict]:
            Findings as dictionaries.
    """
    return [f.to_dict() for f in build_findings(results)]