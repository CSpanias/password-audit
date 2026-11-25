"""
Technical commentary generation.

This module produces the detailed technical narrative used within password audit 
reports. Commentary functions convert analysis results into report-ready 
Markdown content, including supporting tables, observations, and contextual 
security guidance.
"""

from collections import Counter

from analysis.findings import build_findings_dict, finding_priority
from common.utils import (
    format_count_warnings, mask_password, natural_join, num_to_word, proportion_wording,
)
from ntds.analysis import privileged_group_name


def _display_username(username):
    return username.rpartition("\\")[2].replace("|", "\\|")


def _display_group(group):
    return privileged_group_name(group).replace("|", "\\|")


def _account_examples(accounts, separator=", "):
    examples = separator.join(accounts[:5])
    remaining = len(accounts) - 5
    if remaining > 0:
        examples += f"{separator}+{remaining:,} more"
    return examples


def _high_privileged_accounts(results):
    privileged = {
        account["username"].casefold(): account
        for account in results["privileged_users"]["accounts"]
    }
    accounts = {}
    for admin in results["admins"]["accounts"]:
        key = admin["username"].casefold()
        matched = privileged.get(key)
        groups = list(matched["groups"]) if matched else []
        accounts[key] = {**admin, "groups": groups, "legacy_da": True}
    for key, account in privileged.items():
        if any(
            privileged_group_name(group) in {"Domain Admins", "Enterprise Admins"}
            for group in account["groups"]
        ):
            accounts.setdefault(key, {**account, "legacy_da": False})
    return list(accounts.values())


# ---------------------------------------------------------------------------
# Privileged Accounts
# ---------------------------------------------------------------------------

def commentary_admins(results):
    """
    Generate commentary for recovered Domain and Enterprise Administrator passwords.

    The commentary includes a summary of the finding and a sample table of 
    affected privileged accounts where passwords were successfully recovered.

    Args:
        results (dict):
            Password analysis results.

    Returns:
        str:
            Markdown-formatted commentary.
    """

    admins = _high_privileged_accounts(results)
    count = len(admins)

    if not count:
        return ""

    if count:
        lines = []

        domain_admins = any(
            account["legacy_da"] or any(
                privileged_group_name(group) == "Domain Admins"
                for group in account["groups"]
            )
            for account in admins
        )
        enterprise_admins = any(
            privileged_group_name(group) == "Enterprise Admins"
            for account in admins for group in account["groups"]
        )
        role = (
            "Domain or Enterprise Administrator" if domain_admins and enterprise_admins
            else "Enterprise Administrator" if enterprise_admins
            else "Domain Administrator"
        )
        lines.append(
            f"A total of {num_to_word(count)} {role} account"
            f"{'s had passwords' if count != 1 else ' had a password'} "
            "successfully recovered during the password audit. "
            f"{'These accounts represent some of' if count != 1 else 'This account represents one of'} "
            "the most privileged identities within AD and typically "
            f"{'provide' if count != 1 else 'provides'} broad access to authentication services, directory "
            f"data, and domain-joined systems. Compromise of {'these credentials' if count != 1 else 'this credential'} significantly increases "
            "the potential impact of credential exposure and may facilitate privilege escalation or "
            "wider compromise of the environment."
        )

        lines.append("")
        lines.append("| Username | Groups | Password |")
        lines.append("| ---------- | ---------- | ---------- |")

        for account in admins:
            groups = list(dict.fromkeys(_display_group(group) for group in account["groups"]))
            if account["legacy_da"] and "Domain Admins" not in groups:
                groups.insert(0, "Domain Admins (name match only)")
            password = mask_password(account["password"]).replace("|", "\\|")
            lines.append(
                f"| {_display_username(account['username'])} | {', '.join(groups)} | "
                f"{password} |"
            )

        lines.append("")

    return "\n".join(lines)

def commentary_privileged_users(results):
    """Describe recovered passwords for members of selected groups."""
    privileged = results["privileged_users"]
    lines = []
    domain = privileged.get("confirmed_domain")
    membership_note = (
        "Group memberships include nested membership and are limited to the collected "
        "BloodHound data; they are not a complete assessment of all privileged access "
        "or attack paths."
    )
    if privileged["status"] == "incomplete":
        lines.append(
            "Privileged group coverage"
            + (f" for the confirmed domain {domain['name']}" if domain else "")
            + " is incomplete: " + format_count_warnings(privileged["warnings"])
            + " Some affected accounts may be missing."
            + (f" {membership_note}" if privileged["accounts"] else "")
        )
    elif privileged["status"] == "unavailable":
        lines.append(
            "Privileged group analysis is unavailable. "
            + format_count_warnings(privileged["warnings"], sentence_start=True)
        )
    elif domain:
        lines.append(f"Privileged group membership was assessed for the confirmed domain {domain['name']}.")
    high_accounts = {
        account["username"].casefold() for account in _high_privileged_accounts(results)
    }
    other_accounts = [
        account for account in privileged["accounts"]
        if account["username"].casefold() not in high_accounts
    ]
    if other_accounts:
        if lines:
            lines.append("")
        count = len(other_accounts)
        lines.append(
            f"{'Passwords were' if count != 1 else 'A password was'} recovered for {num_to_word(count)} "
            f"{'other ' if high_accounts else ''}account{'s' if count != 1 else ''} "
            "belonging to selected privileged groups."
            + (f" {membership_note}" if privileged["status"] != "incomplete" else "")
        )
        lines.extend(["", "| Username | Groups | Password |",
                      "| ---------- | ---------- | ---------- |"])
        for account in other_accounts:
            username = _display_username(account["username"])
            groups = ", ".join(dict.fromkeys(
                _display_group(group) for group in account["groups"]
            ))
            password = mask_password(account["password"]).replace("|", "\\|")
            lines.append(
                f"| {username} | {groups} | {password} |"
            )
    elif privileged["accounts"] and privileged["status"] != "incomplete":
        if lines:
            lines.append("")
        lines.append(membership_note)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# LM-related findings
# ---------------------------------------------------------------------------

def commentary_lm_hashes(results):
    """
    Generate commentary relating to LM hash exposure.

    The presence of LM password hashes is summarised together with associated 
    security risks. Where LM passwords have been recovered, recovery rates,
    partial recoveries, and any affected privileged accounts are also reported.
    Example accounts and masked LM hashes are included.

    Args:
        results (dict):
            Password analysis results.

    Returns:
        str:
            Markdown-formatted commentary.
    """

    lines = []

    lm_hash_count = results["lm_hashes"]["count"]
    unique_hashes = results["lm_hashes"]["uniqueHashes"]
    duplicate_hashes = results["lm_hashes"]["duplicateHashes"]
    lm_password_count = results["lm_passwords"]["count"]
    partial_lm_password_count = results["lm_passwords"]["partialCount"]
    lm_crack_rate = results["lm_passwords"]["recoveryRate"]
    da_count = results["lm_admins"]["count"]

    if not lm_hash_count:
        return ""

    lm_label = "LAN Manager (LM)"
    if da_count:
        lines.append(
            f"{lm_label} recovery results included {num_to_word(da_count)} Domain Administrator "
            f"account{'s' if da_count != 1 else ''}. Exposure of privileged credential "
            "material increases the potential impact of compromise and may facilitate "
            "privilege escalation."
        )
        lines.append("")
        lm_label = "LM"

    presence = (
        f"A single {lm_label} password hash was present for one account."
        if lm_hash_count == 1 else
        f"{lm_label} password hashes were present for {num_to_word(lm_hash_count)} accounts."
    )
    presence += (
        f" The presence of {'an LM hash' if lm_hash_count == 1 else 'LM hashes'} "
        "indicates that legacy password storage remains in use. "
        f"Analysis found {num_to_word(unique_hashes)} unique LM hash "
        f"value{'s' if unique_hashes != 1 else ''}"
    )
    if duplicate_hashes:
        presence += (
            f" and {num_to_word(duplicate_hashes)} duplicate LM hash "
            f"occurrence{'s' if duplicate_hashes != 1 else ''}. "
            "This indicates that multiple accounts are likely configured with identical passwords."
        )
    else:
        presence += "."
    lines.append(presence)

    if lm_password_count:

        lines.append("")

        recovery_text = (
            "Unlike NTLM password recovery, LM password recovery is facilitated by the design of "
            "the LM hashing algorithm, which processes passwords in two independent seven-character "
            "halves. This significantly reduces the effective search space and enables rapid "
            "password recovery using commonly available password dictionaries and rule sets.\n\n"
            f"{'Passwords were' if lm_password_count != 1 else 'A password was'} successfully recovered from {num_to_word(lm_password_count)} "
            f"account{'s' if lm_password_count != 1 else ''} that stored "
            f"{'LM hashes' if lm_password_count != 1 else 'an LM hash'}, representing "
            f"{lm_crack_rate}% of the affected account population"
        )

        if lm_crack_rate >= 90:
            recovery_text += ", which demonstrates the practical weakness of LM password storage."
        elif lm_crack_rate >= 50:
            recovery_text += (
                ", which demonstrates the practical weakness of LM password storage and illustrates "
                "the increased exposure associated with retaining legacy password hashing technologies."
            )
        else:
            recovery_text += (
                ". Whilst recovery was not universal, the results demonstrate that LM password "
                "storage remains susceptible to efficient offline attack."
            )

        if partial_lm_password_count:

            recovery_text += (
                f" A further {'account' if partial_lm_password_count == 1 else num_to_word(partial_lm_password_count) + ' accounts'}"
                " yielded a partial password "
                "recovery."
            )

        lines.append(recovery_text)

    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | ---: |")
    lines.append(f"| Account{'s' if lm_hash_count != 1 else ''} with LM Hash{'es' if lm_hash_count != 1 else ''} | {lm_hash_count} |")
    lines.append(f"| Unique LM Hash{'es' if unique_hashes != 1 else ''} | {unique_hashes} |")

    if duplicate_hashes:
        lines.append(f"| Duplicate LM Hash{'es' if duplicate_hashes != 1 else ''} | {duplicate_hashes} |")

    if lm_password_count:
        lines.append(f"| Fully Recovered LM Password{'s' if lm_password_count != 1 else ''} | {lm_password_count} |")

    if partial_lm_password_count:
        lines.append(f"| Partially Recovered LM Password{'s' if partial_lm_password_count != 1 else ''} | {partial_lm_password_count} |")

    if lm_password_count:
        lines.append(f"| Recovery Rate | {lm_crack_rate}% |")

    if da_count:
        lines.append(f"| LM Domain Administrator Account{'s' if da_count != 1 else ''} | {da_count} |")

    lines.append("")
    examples = results["lm_hashes"]["accounts"][:5]
    lines.append(
        "The following table shows an example account and its masked LM hash:"
        if len(examples) == 1 else
        "The following table shows a sample of accounts and their masked LM hashes:"
    )
    lines.append("")
    lines.append("| Username | LM Hash |")
    lines.append("| ---------- | ---------- |")
    for account in examples:
        lines.append(
            f"| {_display_username(account['username'])} | "
            f"{mask_password(account['lm_hash'].lower())} |"
        )
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Password Length Analysis
# ---------------------------------------------------------------------------

def commentary_password_lengths(results):
    """
    Generate commentary relating to password length policy compliance.

    Recovered passwords are compared against the configured minimum
    password length requirement and the most frequently observed
    password lengths are summarised.

    Args:
        results (dict):
            Password analysis results.

    Returns:
        str:
            Markdown-formatted commentary.
    """

    minimum_length = results["password_length"]["minimum_length"]
    if minimum_length is None:
        return (
            "Password length compliance could not be assessed because the domain "
            "minimum password length was unavailable."
        )
    failures = results["password_length"]["failures"]
    failure_count = results["password_length"]["count"]
    failure_percentage = results["password_length"]["percentage"]
    lengths = results["password_lengths"]["lengths"]

    if not lengths:
        return ""

    most_common_length = max(lengths, key=lambda item: item[1])[0]
    recovered_label = "the recovered password" if sum(count for _, count in lengths) == 1 else "recovered passwords"
    lines = []

    if failure_count:
        distribution = Counter(failure["length"] for failure in failures)
        most_common = distribution.most_common()
        highest = most_common[0][1]
        common_lengths = [length for length, frequency in most_common if frequency == highest]
        top_lengths = natural_join([num_to_word(length) for length in common_lengths])

        if (len(common_lengths) == 1 and int(common_lengths[0]) == most_common_length):

            top_length = int(common_lengths[0])

            lines.append(
                "The configured domain minimum password length was "
                f"{num_to_word(minimum_length)} character{'s' if minimum_length != 1 else ''}. "
                "Analysis of the recovered credentials "
                f"found {num_to_word(failure_count)} password{'s' if failure_count != 1 else ''} "
                f"({failure_percentage}% of {recovered_label}) shorter than this minimum. The most "
                f"frequently observed length below the minimum was {num_to_word(top_length)} "
                f"character{'s' if top_length != 1 else ''}, which was also the most "
                "commonly observed password length overall."
            )

        else:

            lines.append("The configured domain minimum password length was "
                f"{num_to_word(minimum_length)} character{'s' if minimum_length != 1 else ''}. "
                "Analysis of the recovered credentials "
                f"found {num_to_word(failure_count)} password{'s' if failure_count != 1 else ''} "
                f"({failure_percentage}% of {recovered_label}) shorter than this minimum. The most "
                "frequently observed password "
                f"length{'s were' if len(common_lengths) > 1 else ' was'} {top_lengths} "
                f"character{'s' if len(common_lengths) != 1 or int(common_lengths[0]) != 1 else ''}, "
                "while the most commonly "
                f"observed password length overall was {num_to_word(most_common_length)} "
                f"character{'s' if most_common_length != 1 else ''}."
            )

        lines.append("")
        lines.append(
            "Fine-grained policies or earlier policy changes may explain these results; "
            "verify each account's effective policy before treating them as violations."
        )
        lines.append("")
        lines.append(
            f"The following password "
            f"length{'s were' if len(common_lengths) > 1 else ' was'} observed "
            "most frequently below the domain minimum:"
        )

        lines.append("")
        lines.append("| Length | Count | Percentage |")
        lines.append("| ---------- | ---------- | ---------- |")
        
        for length, count in distribution.most_common(5):
            percentage = round(count / failure_count * 100, 1)
            lines.append(f"| {length} | {count:,} | {percentage}% |")

        lines.append("")
        lines.append(
            "The following table shows an account with a password below the domain minimum:"
            if len(failures[:5]) == 1 else
            "The following table shows a sample of accounts with passwords below the domain minimum:"
        )
        lines.append("")
        lines.append("| Username | Password |")
        lines.append("| ---------- | ---------- |")
        for account in failures[:5]:
            password = mask_password(account["password"]).replace("|", "\\|")
            lines.append(f"| {_display_username(account['username'])} | {password} |")
        lines.append("")

    else:
        return ""
        # lines.append(
        #     "All recovered passwords complied with the configured minimum "
        #     f"password length requirement of {num_to_word(minimum_length)} characters. "
        #     "This suggests that the domain password policy is being "
        #     "consistently enforced across the recovered credential "
        #     "population. The most commonly observed password length was "
        #     f"{num_to_word(most_common_length)} characters, indicating that users "
        #     "typically select passwords at or above the required minimum."
        # )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Password Reuse
# ---------------------------------------------------------------------------

def commentary_hibp(results):
    """Describe offline Pwned Passwords matching."""
    hibp = results.get("hibp")
    if hibp is None:
        return ""
    count = hibp["count"]
    paragraph = (
        "Have I Been Pwned (HIBP) maintains Pwned Passwords, a dataset of "
        "passwords exposed in known data breaches. "
        f"A total of {num_to_word(hibp['checked'])} enabled user "
        f"account{'s were' if hibp['checked'] != 1 else ' was'} checked "
        "against a locally downloaded copy of the dataset. "
        f"A total of {num_to_word(count)} account{'s' if count != 1 else ''} "
        f"had {'a matching password hash' if count == 1 else 'matching password hashes'}. "
        + (
            "However, it should be noted that a matching hash does not mean "
            "the account itself appeared in a breach."
            if count else
            "A matching hash would not mean the account itself appeared in a breach."
        )
    )
    if not count:
        return paragraph
    table = ["| Username | NTLM Hash |", "| ---------- | ---------- |"]
    table.extend(
        f"| {_display_username(account['username'])} | {account['masked_hash']} |"
        for account in hibp["examples"]
    )
    return "\n\n".join([
        paragraph,
        ("The following table shows an example account and its masked matching NTLM hash:"
         if len(hibp["examples"]) == 1 else
         "The following table shows a sample of accounts and their masked matching NTLM hashes:"),
        "\n".join(table),
    ])


def commentary_ntlm_hash_reuse(results):
    """Describe hash-based reuse independently of password recovery."""
    reuse = results["ntlm_hash_reuse"]
    if reuse["status"] == "unavailable":
        return "NTLM hash reuse analysis was unavailable; organised directory user records were not supplied."
    groups = reuse["groups"]
    if not groups:
        return ""
    privileged_groups = [
        group for group in groups
        if any(account["groups"] for account in group["accounts"])
    ]
    paragraph = (
        f"A total of {num_to_word(len(groups))} shared NTLM "
        f"hash{'es were' if len(groups) != 1 else ' was'} found across "
        f"{num_to_word(reuse['account_count'])} enabled user "
        f"account{'s' if reuse['account_count'] != 1 else ''}, regardless "
        "of whether their passwords were recovered. These results may overlap with "
        "the recovered-password reuse findings and should not be added together."
    )
    if privileged_groups:
        privileged_accounts = {
            account["username"].casefold()
            for group in privileged_groups for account in group["accounts"] if account["groups"]
        }
        accounts = ("an account in a selected privileged group" if len(privileged_accounts) == 1
                    else "accounts in selected privileged groups")
        paragraph += (
            f" Of these, {num_to_word(len(privileged_groups))} "
            f"{'include' if len(privileged_groups) != 1 else 'includes'} "
            f"{accounts}."
        )
    samples = groups[:5]
    privileged_samples = [
        group for group in samples if any(account["groups"] for account in group["accounts"])
    ]
    other_samples = [
        group for group in samples if not any(account["groups"] for account in group["accounts"])
    ]
    sections = [paragraph]
    if privileged_samples:
        table = [
            "| NTLM Hash | Privileged Accounts (Groups) | Other Accounts |",
            "| ---------- | ---------- | ---------- |",
        ]
        for group in privileged_samples:
            privileged_accounts = []
            other_accounts = []
            for account in group["accounts"]:
                username = _display_username(account["username"])
                if account["groups"]:
                    names = ", ".join(dict.fromkeys(
                        _display_group(name) for name in account["groups"]
                    ))
                    privileged_accounts.append(f"{username} ({names})")
                else:
                    other_accounts.append(username)
            table.append(
                f"| {group['masked_hash']} | {_account_examples(privileged_accounts, '; ')} | "
                f"{_account_examples(other_accounts) or '-'} |"
            )
        sections.extend([
            ("The following table shows an example masked NTLM hash shared by "
             if len(privileged_samples) == 1 else
             "The following table shows example masked NTLM hashes shared by ")
            + "accounts in selected privileged groups:",
            "\n".join(table),
        ])
    if other_samples:
        table = ["| NTLM Hash | Accounts |", "| ---------- | ---------- |"]
        for group in other_samples:
            accounts = _account_examples([
                _display_username(account["username"])
                for account in group["accounts"]
            ])
            table.append(f"| {group['masked_hash']} | {accounts} |")
        other = "other " if privileged_samples else ""
        description = (
            f"The following table shows {'another' if privileged_samples else 'an'} "
            "example masked NTLM hash and its associated accounts:"
            if len(other_samples) == 1 else
            f"The following table shows {other}example masked NTLM hashes and their associated accounts:"
        )
        sections.extend([description, "\n".join(table)])
    return "\n\n".join(sections)


def commentary_password_reuse(results):
    """
    Generate commentary relating to password reuse.

    The commentary summarises passwords observed across multiple
    accounts and highlights the associated security implications.

    Args:
        results (dict):
            Password analysis results.

    Returns:
        str:
            Markdown-formatted commentary.
    """

    reused_passwords = []

    for password, count in (results["password_frequency"]["passwords"]):
        if count < 2:
            continue

        reused_passwords.append({"password": password,"count": count})

    if not reused_passwords:
        return ""
        # return ("No password reuse was identified across the recovered passwords. This reduces the "
        #     "potential impact of credential compromise.")

    lines = []

    lines.append(
        f"{'Passwords were' if len(reused_passwords) != 1 else 'A password was'} reused across multiple user accounts "
        "within the recovered credential dataset. Reuse of credentials "
        "reduces password diversity and increases the potential impact "
        "of credential compromise, as a single recovered password may "
        "provide access to multiple accounts. This behaviour can also "
        "increase the effectiveness of password spraying and other "
        "credential-based attacks."
    )

    lines.append("")
    lines.append("| Password | Times Seen | Percentage | Accounts |")
    lines.append("| ---------- | ---------- | ---------- | ---------- |")

    total_passwords = results["total_passwords"]

    for entry in reused_passwords[:5]:
        percentage = round(entry["count"] / total_passwords * 100, 1)
        password = mask_password(entry["password"]).replace("|", "\\|")
        accounts = _account_examples([
            _display_username(username)
            for username in results["password_reuse_general"]["example_accounts"][entry["password"]]
        ])
        lines.append(f"| {password} | {entry['count']:,} | {percentage}% | {accounts} |")
    
    lines.append("")

    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Similarly-Named Password Reuse
# ---------------------------------------------------------------------------

def commentary_similar_account_reuse(results):
    """
    Generate commentary for password reuse between similarly named accounts.

    Examples may be based on recovered passwords or matching NTLM hashes.

    Args:
        results (dict):
            Password analysis results.

    Returns:
        str:
            Markdown-formatted commentary.
    """

    reuse_accounts = results["similar_account_reuse"]["accounts"]
    count = results["similar_account_reuse"]["count"]
    if count == 0:
        return ""

    lines = []

    lines.append(
        f"A total of {num_to_word(count)} account "
        f"pair{'s' if count != 1 else ''} with similar names shared credentials, "
        "based on recovered passwords or matching NTLM hashes. Similar names do not "
        "establish that accounts belong to the same person or have privileged roles. "
        "Where accounts serve different roles, shared credentials may undermine "
        "account separation and increase the impact of compromise."
    )

    examples = reuse_accounts[:5]
    for field, heading, label in (
        ("password", "Recovered password examples:", "Password"),
        ("masked_hash", "Matching NTLM hash examples:", "NTLM Hash"),
    ):
        matching = [account for account in examples if field in account]
        if not matching:
            continue
        lines.extend(["", heading, "", f"| Username | {label} | Shared With |",
                      "| ---------- | ---------- | ---------- |"])
        for account in matching:
            value = (
                mask_password(account[field]).replace("|", "\\|")
                if field == "password" else account[field]
            )
            lines.append(
                f"| {_display_username(account['username'])} | "
                f"{value} | {_display_username(account['shared_with'])} |"
            )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Username-Derived Passwords
# ---------------------------------------------------------------------------

def commentary_username_passwords(results):
    """
    Generate commentary for passwords containing username-derived content.

    Accounts whose passwords include usernames or common username
    variations are summarised and sample findings are presented.

    Args:
        results (dict):
            Password analysis results.

    Returns:
        str:
        Markdown-formatted commentary.
    """

    accounts = results["username_passwords"]["accounts"]
    count = results["username_passwords"]["count"]

    if not count:
        return ""

    lines = []

    lines.append(f"A total of {num_to_word(count)} recovered password{'s' if count != 1 else ''} "
        "contained the username or a variation thereof. Passwords incorporating username-related "
        "information reduce password entropy and may be more easily predicted by an attacker.")

    lines.append("")
    lines.append("| Username | Password |")
    lines.append("| ---------- | ---------- |")

    for account in accounts[:5]:
        lines.append(f"| {_display_username(account['username'])} | {mask_password(account['password'])} |")

    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Organisation-Related Terms
# ---------------------------------------------------------------------------

def commentary_company_words(results):
    """
    Generate commentary for organisation-related password content.

    The commentary summarises passwords containing organisation
    names, abbreviations, or other organisation-specific terms.

    Args:
        results (dict):
            Password analysis results.

    Returns:
        str:
            Markdown-formatted commentary.
    """

    accounts = results["company_words"]["accounts"]
    count = results["company_words"]["count"]
    stats = results["company_words"]["stats"]

    if not count:
        return ""
    #     return ("No recovered passwords were identified as containing organisation-related terminology. This reduces the "
    #         "effectiveness of targeted password guessing attacks that utilise publicly available organisational information.")

    lines = []

    lines.append(f"Organisation-related terms appeared in {num_to_word(count)} recovered "
        f"password{'s' if count != 1 else ''}. Organisation-specific terminology may be inferred from publicly "
        "available information and can therefore increase exposure to targeted authentication attacks.")

    lines.append("")
    lines.append("| Username | Password |")
    lines.append("| ---------- | ---------- |")

    for account in accounts[:5]:
        lines.append(f"| {_display_username(account['username'])} | {mask_password(account['password'])} |")

    if stats:
        lines.append("")
        term = ("term appeared" if len(stats) == 1 else "terms appeared most frequently")
        password = "the recovered password" if count == 1 else "recovered passwords"
        lines.append(f"The following organisation-related {term} in {password}:")

        lines.append("")
        lines.append("| Term | Occurrences |")
        lines.append("| ---------- | ---------- |")

        for term, frequency in stats[:5]:
            lines.append(f"| {term} | {frequency} |")

    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Date-Related Terms
# ---------------------------------------------------------------------------

def commentary_date_passwords(results):
    """
    Generate commentary for date-related password content.

    Passwords containing months, days, seasons, or similar temporal
    references are summarised together with common examples.

    Args:
        results (dict):
            Password analysis results.

    Returns:
        str:
            Markdown-formatted commentary.
    """

    accounts = results["date_passwords"]["accounts"]
    count = results["date_passwords"]["count"]
    stats = results["date_passwords"]["stats"]

    if not count:
        return ""
    #     return ("No recovered passwords were identified as containing date-related terminology such as days, months, or "
    #         "seasons. This reduces reliance on predictable and easily guessable password construction patterns.")

    lines = []

    lines.append(f"A total of {num_to_word(count)} recovered password{'s' if count != 1 else ''} "
        "contained references to days, months, seasons, or other date-related terms. Such references are commonly used "
        "to improve memorability but result in predictable password construction patterns.")

    lines.append("")
    lines.append("| Username | Password |")
    lines.append("| ---------- | ---------- |")

    for account in accounts[:5]:
        lines.append(f"| {_display_username(account['username'])} | {mask_password(account['password'])} |")

    if stats:

        lines.append("")
        term = ("term appeared" if len(stats) == 1 else "terms appeared most frequently")
        password = "the recovered password" if count == 1 else "recovered passwords"
        lines.append(f"The following date-related {term} in {password}:")

        lines.append("")
        lines.append("| Term | Occurrences |")
        lines.append("| ---------- | ---------- |")

        for term, frequency in stats[:5]:
            lines.append(f"| {term} | {frequency} |")

    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Keyboard Walking Patterns
# ---------------------------------------------------------------------------

def commentary_keyboard_walks(results):
    """
    Generate commentary for keyboard walking patterns.

    Passwords containing predictable keyboard sequences are
    summarised together with the most frequently observed patterns.

    Args:
        results (dict):
            Password analysis results.

    Returns:
        str:
            Markdown-formatted commentary.
    """

    accounts = results["keyboard_walks"]["accounts"]
    count = results["keyboard_walks"]["count"]
    stats = results["keyboard_walks"]["stats"]

    if not count:
        return ""

    lines = []

    lines.append(
        f"A total of {num_to_word(count)} recovered "
        f"password{'s' if count != 1 else ''} contained "
        f"{'a keyboard walking pattern' if len(stats) == 1 else 'keyboard walking patterns'}. "
        "Keyboard sequences are widely "
        "represented within password auditing wordlists and cracking rule sets "
        "due to their predictable structure."
    )

    lines.append("")
    lines.append("| Username | Password |")
    lines.append("| ---------- | ---------- |")

    for account in accounts[:5]:
        lines.append(f"| {_display_username(account['username'])} | {mask_password(account['password'])} |")

    if stats:
        lines.append("")

        if len(stats) == 1:
            lines.append("The following keyboard walk pattern was observed:")
        else:
            lines.append("The following keyboard walk patterns were observed:")

        lines.append("")
        lines.append("| Pattern | Occurrences |")
        lines.append("| ---------- | ---------- |")

        for pattern, frequency in stats[:5]:
            lines.append(f"| {pattern} | {frequency} |")

        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Common Password Analysis
# ---------------------------------------------------------------------------

def commentary_common_passwords(results):
    """
    Generate commentary for commonly used password terms.

    Passwords containing widely used password phrases and common
    weak password variants are summarised.

    Args:
        results (dict):
            Password analysis results.

    Returns:
        str:
            Markdown-formatted commentary.
    """

    accounts = results["common_passwords"]["accounts"]
    count = results["common_passwords"]["count"]
    stats = results["common_passwords"]["stats"]

    if not count:
        return ""
    #     return ("No recovered passwords were identified as containing commonly used password terms or well-known weak "
    #         "password variants. This suggests that users are generally avoiding predictable password selections "
    #         "that are commonly represented within attacker wordlists.")

    lines = []

    lines.append(f"A total of {num_to_word(count)} recovered password{'s' if count != 1 else ''} "
        "contained commonly used password terms or variants thereof. Common password terms remain prevalent "
        "within publicly available breach corpora and are routinely prioritised during password attacks.")

    lines.append("")
    lines.append("| Username | Password |")
    lines.append("| ---------- | ---------- |")

    for account in accounts[:5]:
        lines.append(f"| {_display_username(account['username'])} | {mask_password(account['password'])} |")

    if stats:

        lines.append("")
        if len(stats) == 1:
            lines.append("The following common password term was observed:")
        else:
            lines.append("The following common password terms appeared most frequently:")

        lines.append("")
        lines.append("| Term | Occurrences |")
        lines.append("| ---------- | ---------- |")

        for term, frequency in stats[:5]:
            lines.append(f"| {term} | {frequency} |")

    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Character Composition
# ---------------------------------------------------------------------------

def commentary_character_classes(results):
    """
    Generate commentary for character class adoption.

    The distribution of lowercase letters, uppercase letters,
    numeric characters, and special characters is summarised
    across the recovered password population.

    Args:
        results (dict):
            Password analysis results.

    Returns:
        str:
            Markdown-formatted commentary.
    """

    stats = results["character_classes"]

    if not stats:
        return ""
    #     return (
    #         "No recovered passwords were available for character class analysis.")

    lines = []

    lines.append(
        f"{'Recovered passwords were' if results['total_passwords'] != 1 else 'The recovered password was'} "
        "analysed to determine the adoption of common character classes. Whilst the "
        "presence of uppercase characters, numbers, and special characters may increase password complexity, "
        "their use alone does not guarantee resistance to password guessing or password-cracking attacks. "
        "Strict composition rules can encourage predictable choices and make passwords harder to remember.")

    lines.append("")
    lines.append("| Character Type | Adoption (%) |")
    lines.append("| ---------- | ---------- |")

    lines.append(f"| Lowercase | {stats['lower']} |")
    lines.append(f"| Uppercase | {stats['upper']} |")
    lines.append(f"| Numeric   | {stats['numeric']} |")
    lines.append(f"| Special   | {stats['special']} |")

    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Technical Commentary Assembly
# ---------------------------------------------------------------------------

def technical_commentary(results, findings_data=None):
    """
    Generate the complete technical commentary section.

    Individual commentary components are assembled into a single
    Markdown-formatted section suitable for inclusion within a
    password audit report.

    Args:
        results (dict):
            Password analysis results.

    Returns:
        str:
            Complete technical commentary in Markdown format.
    """

    lines = []
    if findings_data is None:
        findings_data = build_findings_dict(results)

    total = results["total_passwords"]
    enabled_users = results["enabled_users"]
    crack_rate = results["crack_rate"]

    introduction = ("A password audit was performed against NT LAN Manager (NTLM) password hashes extracted from "
        "Active Directory (AD) to assess the "
        "effectiveness of password selection practices and highlight weaknesses that could increase the likelihood "
        f"of credential compromise.\n\nThrough password-cracking techniques, it was possible to recover {num_to_word(total)} "
        f"plaintext password{'s' if total != 1 else ''}")
    if enabled_users:
        introduction += (
            f" from {num_to_word(enabled_users)} enabled user "
            f"account{'s' if enabled_users != 1 else ''}, representing approximately {crack_rate}% "
            "of the assessed population. "
        )
    else:
        introduction += ". No enabled user accounts were available to calculate a recovery rate. "
    if total:
        if enabled_users > 5:
            _, impact = proportion_wording(crack_rate)
            introduction += (
                f"This demonstrates that {impact} user credentials remain susceptible to "
                "password-cracking attacks following credential exposure. "
            )
        else:
            introduction += (
                f"{'The recovered password demonstrates' if total == 1 else 'The recovered credentials demonstrate'} "
                "susceptibility to password-cracking attacks "
                "following credential exposure. "
            )
        introduction = introduction.rstrip() + (
            f"\n\nThe recovered password{'s were' if total != 1 else ' was'} subsequently analysed for "
            "common password selection patterns, password length, and other indicators of weak password hygiene."
        )
    else:
        introduction += "Password composition could not be assessed without recovered passwords."
    lines.append(introduction)

    readability = ("To maintain report readability, example findings have been included throughout this section. Unless otherwise "
                   "stated, tables are intended to provide representative samples and may not contain all affected accounts found during "
                   "the assessment.")
    if total:
        lines[-1] += " " + readability
    else:
        lines.append(readability)

    sections = (
        ("Privileged Accounts", (commentary_admins, commentary_privileged_users),
         ("DOMAIN-ADMIN-001", "PRIV-ACCOUNT-001")),
        ("LM Hashes", (commentary_lm_hashes,), ("LM-AUTH-001", "DOMAIN-ADMIN-002")),
        ("Password Reuse", (
            commentary_password_reuse, commentary_ntlm_hash_reuse,
            commentary_similar_account_reuse,
        ), ("PWD-REUSE-001", "PWD-REUSE-002", "PWD-REUSE-003")),
        ("Passwords in Breach Data", (commentary_hibp,), ("PWD-BREACH-001",)),
        ("Password Compliance", (commentary_password_lengths,), ("PWD-POLICY-001",)),
        ("Common Patterns", (
            commentary_username_passwords, commentary_company_words,
            commentary_common_passwords, commentary_date_passwords,
            commentary_keyboard_walks,
        ), ("PWD-PATTERN-001", "PWD-PATTERN-002", "PWD-PATTERN-003",
            "PWD-PATTERN-004", "PWD-PATTERN-005")),
        ("Password Complexity", (commentary_character_classes,), ()),
    )
    for heading, functions, _ in sorted(
        sections, key=lambda section: finding_priority(findings_data, section[2])
    ):
        content = [
            text.strip() for function in functions if (text := function(results)).strip()
        ]
        if content:
            lines.append(f"### {heading}\n\n" + "\n\n".join(content))

    lines = [line.strip() for line in lines if line.strip()]
    return "\n\n".join(lines)