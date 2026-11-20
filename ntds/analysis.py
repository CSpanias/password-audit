"""
NTDS analysis functions.

This module contains analysis routines used to derive
security-relevant datasets from parsed NTDS and BloodHound
data. Functions focus on extracting hashes, identifying
privileged accounts, deriving organisation-related terms,
and extracting password policy information.

Functions in this module should analyse data and return
results. File loading and export operations should be
handled elsewhere.
"""

import re
from collections import defaultdict
from ntds.constants import LM_EMPTY


PRIVILEGED_GROUP_RIDS = {
    "512": "Domain Admins",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
    "544": "Administrators",
    "548": "Account Operators",
    "549": "Server Operators",
    "551": "Backup Operators",
    "517": "Cert Publishers",
}
PRIVILEGED_GROUP_NAMES = {
    "dnsadmins": "DNSAdmins",
    "exchange windows permissions": "Exchange Windows Permissions",
}
UNCONFIRMED_DOMAIN_WARNING = (
    "NTDS account(s) could not be matched to a BloodHound domain; "
    "NetBIOS names or UPN suffixes may differ from DNS names."
)


def _group_records(groups_data):
    groups = defaultdict(list)
    for group in groups_data["data"]:
        groups[group["ObjectIdentifier"].upper()].append(group)
    return groups


def single_bloodhound_domain(domains_data, users_data, groups_data):
    """Return the sole collected domain only when its SID and scope are clear."""
    domains = domains_data.get("data", []) if domains_data else []
    if len(domains) != 1 or users_data is None or groups_data is None:
        return None
    domain = domains[0]
    if not isinstance(domain, dict) or not isinstance(domain.get("Properties"), dict):
        return None
    sid = domain.get("ObjectIdentifier")
    name = domain["Properties"].get("domain")
    if not isinstance(sid, str) or not isinstance(name, str) or not name.strip():
        return None
    sid = sid.upper()
    if not re.fullmatch(
        r"S-1-5-21-(?:\d+-){2}\d+", sid
    ):
        return None
    property_sid = domain["Properties"].get("domainsid")
    if property_sid and (
        not isinstance(property_sid, str) or property_sid.upper() != sid
    ):
        return None
    for record in users_data["data"] + groups_data["data"]:
        identifier = record.get("ObjectIdentifier", "")
        if not isinstance(identifier, str):
            return None
        identifier = identifier.upper()
        match = re.fullmatch(r"(S-1-5-21-(?:\d+-){2}\d+)-\d+", identifier)
        if match and match.group(1) != sid:
            return None
        record_domain = record.get("Properties", {}).get("domain")
        if record_domain and (
            not isinstance(record_domain, str)
            or record_domain.casefold() != name.casefold()
        ):
            return None
    return {"name": name, "sid": sid}


def extract_privileged_users(users_data, groups_data, entries, confirmed_domain_sid=None):
    """Resolve selected group memberships and match them to NTDS accounts."""
    if confirmed_domain_sid is not None and not re.fullmatch(
        r"S-1-5-21-(?:\d+-){2}\d+", confirmed_domain_sid.upper()
    ):
        raise ValueError("Invalid confirmed domain SID.")
    if confirmed_domain_sid is not None:
        confirmed_domain_sid = confirmed_domain_sid.upper()
    if users_data is None or groups_data is None:
        return {"status": "unavailable", "accounts": [], "warnings": [
            "BloodHound users or groups data is unavailable."
        ]}

    users = {user["ObjectIdentifier"].upper(): user for user in users_data["data"]}
    groups = _group_records(groups_data)
    primary_groups = defaultdict(list)
    candidates = defaultdict(list)
    for sid, user in users.items():
        primary = user.get("PrimaryGroupSID")
        if primary:
            primary_groups[primary.upper()].append(sid)
        name = user.get("Properties", {}).get("samaccountname")
        if name and "-" in sid:
            candidates[(name.casefold(), sid.rsplit("-", 1)[-1])].append(sid)

    entry_matches = {}
    ambiguous_sids = set()
    ambiguous = 0
    unconfirmed_domains = 0
    for entry in entries:
        username = entry["username"]
        prefix, separator, name = username.rpartition("\\")
        if not separator:
            name = username
        matching = candidates.get((name.casefold(), str(entry["rid"])), [])
        if confirmed_domain_sid and matching:
            scoped_matches = [
                sid for sid in matching
                if sid.rsplit("-", 1)[0] == confirmed_domain_sid
            ]
            if not scoped_matches:
                unconfirmed_domains += 1
            matching = scoped_matches
        elif separator and matching:
            domain_matches = []
            for sid in matching:
                properties = users[sid].get("Properties", {})
                domain = properties.get("domain") or ""
                upn = properties.get("userprincipalname") or ""
                upn_suffix = upn.rpartition("@")[2] if "@" in upn else ""
                if prefix.casefold() in {domain.casefold(), upn_suffix.casefold()}:
                    domain_matches.append(sid)
            if not domain_matches:
                unconfirmed_domains += 1
            matching = domain_matches
        if len(matching) == 1:
            sid = matching[0]
            if sid in ambiguous_sids:
                continue
            if sid in entry_matches and entry_matches[sid].casefold() != username.casefold():
                del entry_matches[sid]
                ambiguous_sids.add(sid)
                ambiguous += 1
            else:
                entry_matches[sid] = username
        elif len(matching) > 1:
            ambiguous += 1

    memberships = defaultdict(set)
    unresolved = set()
    missing_members = set()
    selected_groups = set()
    conflicting_groups = set()
    for sid, group_records in groups.items():
        builtin = re.fullmatch(r"(?:.+-)?S-1-5-32-(\d+)", sid)
        domain_sid = re.fullmatch(r"S-1-5-21-(?:\d+-){3}(\d+)", sid)
        rid = builtin.group(1) if builtin else domain_sid.group(1) if domain_sid else None
        labels = set()
        domains = set()
        for group in group_records:
            props = group.get("Properties", {})
            raw_name = props.get("samaccountname") or props.get("name", "").split("@", 1)[0]
            label = PRIVILEGED_GROUP_NAMES.get(raw_name.casefold())
            if rid and (
                (builtin and rid in {"544", "548", "549", "551"})
                or (domain_sid and rid in {"512", "517", "518", "519"})
            ):
                label = PRIVILEGED_GROUP_RIDS[rid]
            if label:
                labels.add(label)
            if props.get("domain"):
                domains.add(props["domain"].casefold())
        if len(labels) > 1:
            conflicting_groups.add(sid)
            continue
        if not labels:
            continue
        label = labels.pop()
        selected_groups.add(label)
        if len(domains) > 1:
            conflicting_groups.add(sid)
        elif domains:
            label = f"{label} ({domains.pop()})"

        pending = [sid]
        visited = set()
        while pending:
            current = pending.pop()
            if current in visited:
                continue
            visited.add(current)
            if current in users:
                if current in entry_matches:
                    memberships[entry_matches[current]].add(label)
                continue
            nested_records = groups.get(current)
            if nested_records is None:
                unresolved.add(current)
                continue
            pending.extend(primary_groups.get(current, []))
            for nested in nested_records:
                if "Members" not in nested:
                    missing_members.add(current)
                for member in nested.get("Members", []):
                    member_sid = member["ObjectIdentifier"].upper()
                    if member.get("ObjectType", "").casefold() not in ("computer",):
                        pending.append(member_sid)

    warnings = []
    missing_groups = {"Domain Admins", "Administrators"} - selected_groups
    if missing_groups:
        warnings.append(
            "Expected privileged groups were not found in BloodHound data: "
            + ", ".join(sorted(missing_groups)) + "."
        )
    if unresolved:
        warnings.append(
            f"{len(unresolved)} group member object(s) could not be resolved."
        )
    if missing_members:
        warnings.append(
            f"{len(missing_members)} group(s) lacked membership data."
        )
    if conflicting_groups:
        warnings.append(
            f"{len(conflicting_groups)} group(s) had conflicting names or domains."
        )
    if ambiguous:
        warnings.append(
            f"{ambiguous} ambiguous NTDS/BloodHound account match(es) were omitted."
        )
    if unconfirmed_domains:
        warnings.append(f"{unconfirmed_domains} {UNCONFIRMED_DOMAIN_WARNING}")
    return {
        "status": "incomplete" if warnings else "available",
        "accounts": [
            {"username": username, "groups": sorted(labels)}
            for username, labels in sorted(memberships.items(), key=lambda item: item[0].casefold())
        ],
        "warnings": warnings,
    }


def extract_ntlm_hashes(entries):
    """
    Extract unique NTLM hashes from NTDS entries.

    Duplicate hashes are removed and results are returned
    in sorted order to provide deterministic output.

    Args:
        entries (list):
            Parsed NTDS account records.

    Returns:
        list:
            Unique NTLM hashes.
    """

    return sorted({
        e["ntlm"]
        for e in entries
    })


def extract_lm(entries):
    """
    Identify accounts using LM hashes.

    Accounts containing the known empty LM hash are excluded.
    Both affected accounts and unique LM hashes are returned.

    Args:
        entries (list):
            Parsed NTDS account records.

    Returns:
        tuple:
            - list: Accounts containing LM hashes.
            - list: Unique LM hashes.
    """

    lm_users = [
        e for e in entries
        if e["lm"] != LM_EMPTY
    ]

    lm_hashes = sorted({
        e["lm"]
        for e in lm_users
    })

    return lm_users, lm_hashes


def extract_company_words(domains):
    """
    Derive organisation-related terms from domain names.

    Top-level domains are removed and resulting names are
    further split into component words using non-alphanumeric
    delimiters. Terms shorter than three characters are
    excluded.

    Example:

        cia-medical.com

    Produces:

        cia-medical
        cia
        medical

    Args:
        domains (list):
            Domain names.

    Returns:
        list:
            Organisation-related terms.
    """

    words = set()

    for domain in domains:
        domain = domain.lower().strip()

        if not domain:
            continue

        # Remove TLD
        base = domain.rsplit(".", 1)[0]

        # Full company string
        words.add(base)

        # Special character split
        for token in re.split(r"[^a-z0-9]+", base):

            token = token.strip()

            if len(token) >= 3:
                words.add(token)

    return sorted(words)


def extract_username_domains(entries):
    """
    Extract domain prefixes from usernames.

    Usernames in DOMAIN\\username format are processed and
    unique domain values are returned.

    Args:
        entries (list):
            Parsed NTDS account records.

    Returns:
        list:
            Unique username domains.
    """

    domains = set()

    for entry in entries:
        username = entry["username"]

        if "\\" not in username:
            continue

        prefix = username.split("\\", 1)[0]

        if "." in prefix:
            domains.add(prefix)

    return sorted(domains)


def extract_domain_admins(users_data, groups_data):
    """
    Identify Domain Administrator accounts from BloodHound data.
    """

    if not users_data or not groups_data:
        return []

    users_lookup = {
        user["ObjectIdentifier"].upper(): user
        for user in users_data["data"]
    }

    groups_lookup = _group_records(groups_data)

    domain_admins = set()
    visited = set()

    def resolve_members(sid):
        """
        Recursively resolve group membership.
        """

        sid = sid.upper()
        if sid in visited:
            return

        visited.add(sid)

        # User
        if sid in users_lookup:

            username = (
                users_lookup[sid]
                .get("Properties", {})
                .get("samaccountname")
            )

            if username:
                domain_admins.add(username)

            return

        # Group
        group_records = groups_lookup.get(sid)

        if not group_records:
            return

        # Standard group members
        for group in group_records:
            for member in group.get("Members", []):
                resolve_members(member["ObjectIdentifier"])

        # PrimaryGroupSID members
        for user in users_data["data"]:
            if (user.get("PrimaryGroupSID") or "").upper() == sid:
                resolve_members(user["ObjectIdentifier"])

    # Resolve Domain Admins group membership
    for group in groups_data["data"]:
        if group["ObjectIdentifier"].endswith("-512"):
            resolve_members(group["ObjectIdentifier"])

    return sorted(domain_admins)


def extract_domain_policy(domains_data):
    """
    Extract password policy information from BloodHound data.

    Relevant password policy values are extracted from the
    domain object and returned in a simplified dictionary
    structure suitable for reporting and analysis.

    Args:
        domains_data (dict):
            BloodHound domains.json data.

    Returns:
        dict:
            Domain password policy information.
    """

    if not domains_data:
        return {}

    domain = domains_data["data"][0]

    props = domain["Properties"]

    return {
        "domain": props.get("domain"),
        "minpwdlength": props.get("minpwdlength"),
        "pwdhistorylength": props.get("pwdhistorylength"),
        "lockoutthreshold": props.get("lockoutthreshold"),
        "minpwdage": props.get("minpwdage"),
        "maxpwdage": props.get("maxpwdage")
    }