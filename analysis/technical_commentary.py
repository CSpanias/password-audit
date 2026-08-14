"""
Technical commentary generation.

This module produces the detailed technical narrative used within
password audit reports. Commentary functions convert analysis
results into report-ready Markdown content, including supporting
tables, observations, and contextual security guidance.
"""

from collections import Counter

from common.utils import mask_password, num_to_word


# NOTE:
# Table rendering is intentionally explicit for readability.
# Consider abstracting this if additional report formats are
# introduced in future.


# ---------------------------------------------------------------------------
# Privileged Accounts
# ---------------------------------------------------------------------------

def commentary_admins(results):
    """
    Generate commentary for recovered Domain Administrator passwords.

    The commentary includes a summary of the finding and a sample
    table of affected privileged accounts where passwords were
    successfully recovered.

    Args:
        results (dict):
            Password analysis results.

    Returns:
        str:
            Markdown-formatted commentary.
    """

    admins = results["admins"]["accounts"]
    count = results["admins"]["count"]

    if not count:

        return ("No Domain Administrator passwords were successfully recovered during the password audit. "
            "This is a positive outcome, as privileged accounts represent high-value targets and their compromise "
            "would significantly increase the potential impact of a successful attack.\n")

    lines = []

    lines.append(
        f"{num_to_word(count).capitalize()} Domain Administrator "
        f"account{'s were' if count > 1 else ' was'} successfully "
        "recovered during the password audit. Domain Administrator "
        "accounts represent some of the most privileged identities "
        "within Active Directory and typically provide broad access "
        "to authentication services, directory data, and domain-joined "
        "systems. Compromise of these credentials significantly increases "
        "the potential impact of credential exposure and may facilitate "
        "privilege escalation or wider compromise of the environment.\n"
    )

    lines.append("| Username | Password |")
    lines.append("| ---------- | ---------- |")

    for account in admins:
        lines.append(f"| {account['username']} | {mask_password(account['password'])} |")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Presence of LM hashes
# ---------------------------------------------------------------------------

def commentary_lm_hashes(results):
    """
    Generate commentary relating to LM hash exposure.

    Accounts identified as storing LM password hashes are
    summarised together with the associated security risks.

    Args:
        results (dict):
            Password analysis results.

    Returns:
        str:
            Markdown-formatted commentary.
    """

    count = results["lm_hashes"]["count"]
    unique_hashes = results["lm_hashes"]["uniqueHashes"]
    duplicate_hashes = results["lm_hashes"]["duplicateHashes"]

    if not count:
        return ""

    lines = []

    lines.append(
        f"LM password hashes were identified for {num_to_word(count)} account"
        f"{'s' if count != 1 else ''}. The presence of LM hashes indicates that "
        "legacy password storage mechanisms remain enabled for a subset of accounts "
        f"within the environment. The analysis identified {num_to_word(unique_hashes)} "
        f"unique LM hash value{'s' if unique_hashes != 1 else ''} and "
        f"{num_to_word(duplicate_hashes)} duplicate LM hash "
        f"occurrence{'s' if duplicate_hashes != 1 else ''}. This indicates that multiple "
        "accounts share identical LM hash values and are therefore likely to be "
        "configured with the same password.\n"
    )

    lines.append("| Metric | Value |")
    lines.append("| --- | ---: |")
    lines.append(f"| Accounts with LM Hashes | {count} |")
    lines.append(f"| Unique LM Hashes | {unique_hashes} |")
    lines.append(f"| Duplicate LM Hashes | {duplicate_hashes} |")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Recovered LM Passwords
# ---------------------------------------------------------------------------

def commentary_lm_passwords(results):
    """
    Generate technical commentary for recovered LM passwords.

    Passwords recovered through LM hash analysis indicate
    that legacy LM password storage remains enabled for a
    portion of the environment and that affected credentials
    are susceptible to efficient offline recovery attacks.

    The commentary summarises the number of recovered LM
    passwords and provides supporting context regarding the
    inherent weaknesses of the LM hashing algorithm.

    Args:
        results (dict):
            Standardised password analysis results
            containing LM password recovery data.

    Returns:
        str:
            Markdown-formatted narrative and supporting
            metrics table describing recovered LM password
            findings. Returns an empty string when no LM
            passwords have been recovered.
    """

    lines = []

    count = results["lm_passwords"]["count"]

    if not count:
        return ""

    lines.append(
        "Unlike NTLM password recovery, LM password recovery is "
        "facilitated by the design of the LM hashing algorithm, "
        "which processes passwords in two independent 7-character "
        "halves. This significantly reduces the effective search "
        "space and enables rapid password recovery using commonly "
        "available password dictionaries and rule sets. In this "
        f"instance, passwords were recovered from {num_to_word(count)} "
        f"account{'s' if count != 1 else ''} which demonstrates the "
        "practical weakness of LM password storage and the ease with "
        "which credentials may be recovered through offline attacks.\n"
    )

    lines.append("| Metric | Value |")
    lines.append("| --- | ---: |")
    lines.append(f"| Recovered LM Passwords | {count} |")
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
    failures = results["password_length"]["failures"]
    failure_count = results["password_length"]["count"]
    failure_percentage = results["password_length"]["percentage"]
    lengths = results["password_lengths"]["lengths"]

    if not lengths:
        return ""

    most_common_length = max(lengths, key=lambda item: item[1])[0]
    lines = []

    if failure_count:
        distribution = Counter(failure["length"] for failure in failures)
        most_common = distribution.most_common()
        highest = most_common[0][1]
        common_lengths = [str(length) for length, frequency in most_common if frequency == highest]
        top_lengths = " and ".join(common_lengths)

        if (len(common_lengths) == 1 and int(common_lengths[0]) == most_common_length):

            lines.append(f"The domain enforced a minimum password length requirement of {minimum_length} characters. "
                f"Analysis of the recovered credentials identified {num_to_word(failure_count)} passwords ({failure_percentage}% "
                "of recovered passwords) that did not comply with this requirement. The most frequently observed "
                f"non-compliant password length was {top_lengths} characters, which was also the most commonly "
                "observed password length overall.\n")

        else:

            lines.append(f"The domain enforced a minimum password length requirement of {minimum_length} characters. "
                f"Analysis of the recovered credentials identified {num_to_word(failure_count)} passwords ({failure_percentage}% "
                "of recovered passwords) that did not comply with this requirement. The most frequently observed "
                f"non-compliant password length{'s were' if len(common_lengths) > 1 else ' was'} "
                f"{top_lengths} character{'s' if len(common_lengths) == 1 else ''}, while the most commonly observed password length "
                f"overall was {most_common_length} characters.\n")

        lines.append("The following non-compliant password lengths were observed most frequently:\n")
        
        lines.append("| Length | Count | Percentage |")
        lines.append("| ---------- | ---------- | ---------- |")
        
        for length, count in distribution.most_common(5):
            percentage = round(count / failure_count * 100, 1)
            lines.append(f"| {length} | {count:,} | {percentage}% |")
        
        lines.append("")

    else:
        lines.append(
            "All recovered passwords complied with the configured minimum "
            f"password length requirement of {minimum_length} characters. "
            "This suggests that the domain password policy is being "
            "consistently enforced across the recovered credential "
            "population. The most commonly observed password length was "
            f"{most_common_length} characters, indicating that users "
            "typically select passwords at or above the required minimum.\n"
        )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Password Reuse
# ---------------------------------------------------------------------------

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
        return ("No password reuse was identified across the recovered passwords. This reduces the "
            "potential impact of credential compromise.\n")

    lines = []

    lines.append(
        "Password reuse was identified across multiple user accounts "
        "within the recovered credential dataset. Reuse of credentials "
        "reduces password diversity and increases the potential impact "
        "of credential compromise, as a single recovered password may "
        "provide access to multiple accounts. This behaviour can also "
        "increase the effectiveness of password spraying and other "
        "credential-based attacks.\n"
    )

    lines.append("| Password | Times Seen | Percentage |")
    lines.append("| ---------- | ---------- | ---------- |")

    total_passwords = results["total_passwords"]

    for entry in reused_passwords[:5]:
        percentage = round(entry["count"] / total_passwords * 100, 1)
        lines.append(f"| {mask_password(entry['password'])} | {entry['count']:,} | {percentage}% |")
    
    lines.append("")

    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Similarly-Named Password Reuse
# ---------------------------------------------------------------------------

def commentary_similar_account_reuse(results):
    """
    Generate commentary for password reuse between related accounts.

    Similar account names are evaluated to identify possible reuse
    between standard and privileged identities.

    Args:
        results (dict):
            Password analysis results.

    Returns:
        str:
            Markdown-formatted commentary.
    """

    reuse_accounts = results["similar_account_reuse"]["accounts"]
    count = results["similar_account_reuse"]["count"]
    similar_pairs = results["similar_account_reuse"]["similarPairs"]

    if similar_pairs == 0:

        return ""

    if count == 0:

        return (
            "No password reuse was identified between similarly named accounts. "
            "This suggests that standard and privileged accounts are generally "
            "configured with separate credentials, reducing the potential impact "
            "of credential compromise.\n"
        )

    lines = []

    lines.append(
        f"A total of {num_to_word(count)} account "
        f"pair{'s were' if count > 1 else ' was'} identified as "
        "sharing passwords between similarly named accounts. This "
        "behaviour is commonly observed where users maintain separate "
        "standard and privileged identities but reuse credentials "
        "across both accounts. Such reuse may undermine administrative "
        "account separation, increase the impact of credential "
        "compromise, and facilitate privilege escalation or lateral "
        "movement within the environment.\n"
    )

    lines.append("| Username | Password | Shared With |")
    lines.append("| ---------- | ---------- | ---------- |")

    for account in reuse_accounts[:5]:
        lines.append(
            f"| {account['username']} | "
            f"{mask_password(account['password'])} | "
            f"{account['shared_with']} |"
        )

    lines.append("")

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

    lines.append(f"{num_to_word(count).capitalize()} recovered password{'s were' if count != 1 else ' was'} "
        "identified as containing the username or a variation thereof. Passwords incorporating username-related "
        "information reduce password entropy and may be more easily predicted by an attacker.\n")

    lines.append("| Username | Password |")
    lines.append("| ---------- | ---------- |")

    for account in accounts:
        lines.append(f"| {account['username']} | {mask_password(account['password'])} |")

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

        return ("No recovered passwords were identified as containing organisation-related terminology. This reduces the "
            "effectiveness of targeted password guessing attacks that utilise publicly available organisational information.\n")

    lines = []

    lines.append(f"The organisation name, or a variation thereof, was identified within {num_to_word(count)} recovered "
        f"password{'s' if count != 1 else ''}. Organisation-specific terminology may be inferred from publicly "
        "available information and can therefore increase exposure to targeted authentication attacks.\n")

    lines.append("| Username | Password |")
    lines.append("| ---------- | ---------- |")

    for account in accounts[:5]:
        lines.append(f"| {account['username']} | {mask_password(account['password'])} |")

    if stats:
        lines.append("")
        if len(stats) == 1:
            lines.append("The following organisation-related term was identified within recovered passwords:\n")
        else:
            lines.append("The following organisation-related terms were identified most frequently within recovered passwords:\n")

        lines.append("| Term | Occurrences |")
        lines.append("| ---------- | ---------- |")

        for term, frequency in stats:
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

        return ("No recovered passwords were identified as containing date-related terminology such as days, months, or "
            "seasons. This reduces reliance on predictable and easily guessable password construction patterns.\n")

    lines = []

    lines.append(f"A total of {num_to_word(count)} recovered password{'s were' if count != 1 else ' was'} identified as "
        "containing references to days, months, seasons, or other date-related terms. Such references are commonly used "
        "to improve memorability but result in predictable password construction patterns.\n")

    lines.append("| Username | Password |")
    lines.append("| ---------- | ---------- |")

    for account in accounts[:5]:
        lines.append(f"| {account['username']} | {mask_password(account['password'])} |")

    if stats:

        lines.append("")
        if len(stats) == 1:
            lines.append("The following date-related term was identified within recovered passwords:\n")
        else:
            lines.append("The following date-related terms were identified most frequently within recovered passwords:\n")

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

        return ("No recovered passwords were identified as containing keyboard walking patterns. Such patterns are "
            "commonly included within password-cracking rule sets and their absence represents a positive indicator of password quality.\n")

    lines = []

    lines.append(f"{num_to_word(count).capitalize()} recovered password{'s were' if count != 1 else ' was'} "
        "identified as containing keyboard walking patterns. Keyboard sequences are widely represented within password "
        "auditing wordlists and cracking rule sets due to their predictable structure.\n")

    lines.append("| Username | Password |")
    lines.append("| ---------- | ---------- |")

    for account in accounts[:5]:
        lines.append(f"| {account['username']} | {mask_password(account['password'])} |")

    if stats:
        lines.append("")

        total_patterns = sum(frequency for _, frequency in stats)

        if total_patterns == 1:
            lines.append("The following keyboard walk pattern was identified:\n")
        else:
            lines.append("The following keyboard walk patterns were identified:\n")

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

        return ("No recovered passwords were identified as containing commonly used password terms or well-known weak "
            "password variants. This suggests that users are generally avoiding predictable password selections "
            "that are commonly represented within attacker wordlists.\n")

    lines = []

    lines.append(f"A total of {num_to_word(count)} recovered password{'s were' if count != 1 else ' was'} "
        "identified as containing commonly used password terms or variants thereof. Common password terms remain prevalent "
        "within publicly available breach corpora and are routinely prioritised during password attacks.\n")

    lines.append("| Username | Password |")
    lines.append("| ---------- | ---------- |")

    for account in accounts[:5]:
        lines.append(f"| {account['username']} | {mask_password(account['password'])} |")

    if stats:

        lines.append("")
        if len(stats) == 1:
            lines.append("The following common password term was identified:\n")
        else:
            lines.append("The following common password terms were identified most frequently:\n")

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

    lines = []

    lines.append("Recovered passwords were analysed to determine the adoption of common character classes. Whilst the "
        "presence of uppercase characters, numbers, and special characters may increase password complexity, "
        "their use alone does not guarantee resistance to password guessing or password-cracking attacks.\n")

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

def technical_commentary(results):
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

    total = results["total_passwords"]
    enabled_users = results["enabled_users"]
    crack_rate = results["crack_rate"]

    lines.append("A password audit was performed against extracted Active Directory password hashes to assess the "
        "effectiveness of password selection practices and identify weaknesses that could increase the likelihood "
        f"of credential compromise.\n\nThrough password-cracking techniques, it was possible to recover {num_to_word(total)} "
        f"plaintext passwords from {num_to_word(enabled_users)} enabled user accounts, representing approximately {crack_rate}% "
        "of the assessed population. This demonstrates that a measurable proportion of user credentials remain susceptible to "
        "password-cracking attacks following credential exposure. The recovered passwords were subsequently analysed to identify "
        "common password selection patterns, policy non-compliance, and other indicators of weak password hygiene.\n" )

    lines.append("To maintain report readability, example findings have been included throughout this section. Unless otherwise "
            "stated, tables are intended to provide representative samples and may not contain all affected accounts identified during "
            "the assessment.\n")

    # Privileged accounts
    lines.append(commentary_admins(results))

    # Presence of LM hashes
    lines.append(commentary_lm_hashes(results))

    # Recovered LM passwords
    lines.append(commentary_lm_passwords(results))

    # Domain policy compliance
    lines.append(commentary_password_lengths(results))

    # Password management practices
    lines.append(commentary_password_reuse(results))
    lines.append(commentary_similar_account_reuse(results))

    # Predictable patterns
    lines.append(commentary_username_passwords(results))
    lines.append(commentary_company_words(results))
    lines.append(commentary_common_passwords(results))
    lines.append(commentary_date_passwords(results))
    lines.append(commentary_keyboard_walks(results))

    # Password complexity
    lines.append(commentary_character_classes(results))

    return "\n".join(lines)