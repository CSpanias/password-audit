"""
Password analysis functions.

This module contains the core analysis logic used to identify
password weaknesses, policy non-compliance, password reuse,
and other characteristics within recovered credential datasets.

Functions in this module should focus on analysing data and
returning results. Report generation and presentation logic
should be handled elsewhere.
"""

from collections import Counter
from collections import defaultdict

from analysis.constants import (
    COMMON_PASSWORDS,
    KEYBOARD_PATTERNS,
    MONTHS,
    DAYS,
    SEASONS,
)

from common.utils import (
    normalise_password,
    normalise_text,
    username_base,
)


# TODO:
# Consolidate repeated *_stats() functions into a generic
# statistics helper once the monorepo refactor is complete.

# ---------------------------------------------------------------------------
# Privileged Accounts
# ---------------------------------------------------------------------------

def compromised_admins(passwords, domain_admins):
    """
    Identify recovered passwords belonging to Domain Administrators.

    Usernames are normalised by removing the domain component and
    converting values to lowercase before comparison.

    Returns:
        list: Recovered Domain Administrator accounts and
    associated passwords.
    """

    admins = []
    admin_set = {user.lower().split("\\")[-1] for user in domain_admins}

    for record in passwords:
        username = (record["username"].lower().split("\\")[-1])

        if username in admin_set:
            admins.append(record)

    return admins


# ---------------------------------------------------------------------------
# Password Statistics
# ---------------------------------------------------------------------------

# def top_passwords(passwords, limit=5):
    

#     counts = Counter(record["password"] for record in passwords)
#     results = []
#     total = len(passwords)

#     for password, count in counts.most_common(limit):
#         results.append({"password": password, "count": count, "percentage": round(count / total * 100, 1)})

#     return results

def top_passwords(passwords, limit=5):
    """
    Identify the most frequently recovered passwords.

    For each password, the total number of occurrences and
    percentage of the recovered password population are
    calculated.

    Returns:
        list: The most commonly observed passwords,
    their occurrence counts, and percentages.
    """

    frequency = password_frequency(passwords)

    total = len(passwords)

    results = []

    for password, count in frequency[:limit]:

        results.append({
            "password": password,
            "count": count,
            "percentage": round(
                count / total * 100,
                1
            ),
        })

    return results


def password_reuse(passwords):
    """
    Identify passwords that are reused across multiple accounts.

    Returns:
        list: Passwords observed more than once and
    their occurrence counts.
    """

    reuse = []
    counter = Counter(record["password"] for record in passwords)

    for password, count in counter.items():
        if count > 1:
            reuse.append({"password": password, "count": count})

    return reuse


def password_frequency(passwords):
    """
    Calculate the frequency of all recovered passwords.
    
    Results are returned in descending order of occurrence.

    This function provides the raw password frequency dataset
    consumed by reporting and summary functions.
    
    Returns:
        list: Passwords and their associated occurrence counts.
    """

    counts = Counter(
        record["password"]
        for record in passwords
    )

    return counts.most_common()


# ---------------------------------------------------------------------------
# Password Length Analysis
# ---------------------------------------------------------------------------

def password_lengths(passwords):
    """
    Calculate the distribution of recovered password lengths.

    Returns:
        Counter: Password lengths and their associated
    occurrence counts.
    """

    return Counter(len(record["password"]) for record in passwords)


def password_length_failures(passwords,minimum_length):
    """
    Identify passwords that do not comply with the configured
    minimum password length requirement.

    Returns:
        list: Accounts with passwords shorter than the
    specified minimum length.
    """

    failures = []

    for record in passwords:
        password = record["password"]

        if len(password) < minimum_length:
            failures.append({"username": record["username"], "password": password, "length": len(password)})

    return failures


def password_length_distribution(passwords):
    """
    Calculate the frequency of each recovered password length.

    Returns:
        list: Password lengths and their associated
        occurrence counts.
    """

    return password_lengths(passwords).most_common()

# ---------------------------------------------------------------------------
# Organisation-Related Terms
# ---------------------------------------------------------------------------

def company_name_passwords(passwords, company_words):
    """
    Identify passwords containing organisation-related terminology.

    Company terms are normalised and evaluated in descending order
    of length to ensure the most specific match is recorded.

    Returns:
        list: Accounts containing organisation-related terms and
    the associated matches.
    """

    findings = []
    company_words = sorted(company_words, key=len, reverse=True)

    for record in passwords:

        password_normalised = normalise_text(record["password"])

        for word in company_words:

            if normalise_text(word) in password_normalised:

                findings.append({
                    "username": record["username"],
                    "password": record["password"],
                    "matches": [word]
                })

                break

    return findings


def company_word_stats(company_findings):
    """
    Calculate the frequency of organisation-related terms identified
    within recovered passwords.

    Results are returned in descending order of occurrence.

    Returns:
        list: Organisation-related terms and their associated
    occurrence counts.
    """

    counts = Counter()

    for finding in company_findings:
        for match in finding["matches"]:
            counts[match] += 1

    return counts.most_common()


# ---------------------------------------------------------------------------
# Keyboard Walking Patterns
# ---------------------------------------------------------------------------

def keyboard_walk_passwords(passwords):
    """
    Identify passwords containing keyboard walking patterns.

    Keyboard patterns are evaluated in descending order of length
    to ensure the longest and most representative sequence is
    recorded for each password.

    Returns:
        list: Accounts containing keyboard walking patterns and
    the associated matches.
    """

    findings = []
    patterns = sorted(KEYBOARD_PATTERNS, key=len, reverse=True)

    for record in passwords:

        password = record["password"].lower()

        for pattern in patterns:

            if pattern in password:

                findings.append({
                    "username": record["username"],
                    "password": record["password"],
                    "matches": [pattern]
                })

                break

    return findings


def keyboard_walk_stats(findings):
    """
    Calculate the frequency of keyboard walking patterns identified
    within recovered passwords.

    Results are returned in descending order of occurrence.

    Returns:
        list: Keyboard walking patterns and their associated
    occurrence counts.
    """

    counts = Counter()

    for finding in findings:
        for match in finding["matches"]:
            counts[match] += 1

    return counts.most_common()


# ---------------------------------------------------------------------------
# Username-Derived Passwords
# ---------------------------------------------------------------------------

def username_variants(username):
    """
    Generate common username variants for password analysis.

    Usernames are normalised by removing any domain component and
    converting the value to lowercase. Common naming conventions
    are then derived to identify passwords containing all or part
    of a username.

    Example:

        john.smith

    Produces:

        john.smith
        john
        smith
        johnsmith
        jsmith

    Returns:
        set: Username variants suitable for comparison against
    recovered passwords.
    """

    user = username.lower()

    # Remove domain component
    if "\\" in user:
        user = user.split("\\")[-1]

    variants = {user}

    # Generate additional variants from names in the format: firstname.lastname.
    if "." in user:

        first, last = user.split(".", 1)

        variants.add(first)
        variants.add(last)
        variants.add(first + last)

        if first:
            variants.add(first[0] + last)

    return {
        variant
        for variant in variants
        if len(variant) >= 3
    }


def username_passwords(passwords):
    """
    Identify passwords containing a username or a variation thereof.

    Passwords and username variants are normalised to account for
    common character substitutions before comparison.

    Returns:
        list: Accounts whose passwords contain username-derived
    content and the associated matches.
    """

    findings = []

    for record in passwords:
        password_normalised = normalise_text(record["password"])
        matches = []

        for variant in username_variants(record["username"]):
            if normalise_text(variant) in password_normalised:
                matches.append(variant)

        if matches:
            findings.append({"username": record["username"], "password": record["password"],"matches": matches})

    return findings


# ---------------------------------------------------------------------------
# Similar Account Analysis
# ---------------------------------------------------------------------------

def similar_account_reuse(passwords):
    """
    Identify password reuse between similarly named accounts.

    Usernames are reduced to their base form to identify related
    accounts, such as standard and privileged account pairings.
    The total number of comparable account pairs is also tracked
    to support reporting where no related accounts exist.

    Returns:
        tuple:
            - list: Related account pairs sharing the same password.
            - int: Total number of similarly named account pairs
            identified during analysis.
    """

    findings = []
    similar_pairs = 0

    for i in range(len(passwords)):
        for j in range(i + 1, len(passwords)):

            left = passwords[i]
            right = passwords[j]

            if username_base(left["username"]) == username_base(right["username"]):

                similar_pairs += 1

                if left["password"] == right["password"]:

                    findings.append({
                        "password": left["password"],
                        "username": left["username"],
                        "shared_with": right["username"]
                    })

    return findings, similar_pairs


# ---------------------------------------------------------------------------
# Common Password Analysis
# ---------------------------------------------------------------------------

def common_passwords(passwords):
    """
    Identify passwords containing commonly used password terms.

    Passwords are normalised to account for common character
    substitutions before comparison against a predefined list
    of frequently observed password terms.

    Returns:
        list: Accounts containing common password terms and
    the associated matches.
    """

    findings = []

    for record in passwords:
        password = normalise_password(record["password"])
        matches = []

        for common in COMMON_PASSWORDS:
            if common in password:
                matches.append(common)

        if matches:
            findings.append({"username": record["username"], "password": record["password"], "matches": matches})

    return findings

def common_password_stats(findings):
    """
    Calculate the frequency of common password terms identified
    within recovered passwords.

    Results are returned in descending order of occurrence.

    Returns:
        list: Common password terms and their associated
    occurrence counts.
    """

    counter = Counter()

    for finding in findings:
        for match in finding["matches"]:
            counter[match] += 1

    return counter.most_common()


# ---------------------------------------------------------------------------
# Date-Related Terms
# ---------------------------------------------------------------------------

def date_passwords(passwords):
    """
    Identify passwords containing date-related terminology.

    Passwords are analysed for the presence of day names,
    month names, and seasonal references that may indicate
    predictable password construction patterns.

    Returns:
        list: Accounts containing date-related terms and
    the associated matches.
    """

    findings = []

    for record in passwords:
        password = record["password"].lower()
        matches = []

        for day in DAYS:
            if day in password:
                matches.append(day)

        for month in MONTHS:
            if month in password:
                matches.append(month)

        for season in SEASONS:
            if season in password:
                matches.append(season)

        if matches:
            findings.append({"username": record["username"], "password": record["password"], "matches": matches})

    return findings


def date_stats(findings):
    """
    Calculate the frequency of date-related terms identified
    within recovered passwords.

    Results are returned in descending order of occurrence.

    Returns:
        list: Date-related terms and their associated
    occurrence counts.
    """

    counts = Counter()

    for finding in findings:
        for match in finding["matches"]:
            counts[match] += 1

    return counts.most_common()


# ---------------------------------------------------------------------------
# Password Complexity
# ---------------------------------------------------------------------------

def character_class_adoption(passwords):
    """
    Calculate character class adoption across recovered passwords.

    The percentage of passwords containing lowercase letters,
    uppercase letters, numeric characters, and special
    characters is calculated independently.

    Returns:
        dict: Character class adoption percentages for
    lowercase, uppercase, numeric, and special characters.
    """

    total = len(passwords)

    lower = 0
    upper = 0
    numeric = 0
    special = 0

    for record in passwords:
        password = record["password"]

        if any(c.islower() for c in password):
            lower += 1

        if any(c.isupper() for c in password):
            upper += 1

        if any(c.isdigit() for c in password):
            numeric += 1

        if any(not c.isalnum() for c in password):
            special += 1

    return {
        "lower": round(lower / total * 100, 1),
        "upper": round(upper / total * 100, 1),
        "numeric": round(numeric / total * 100, 1),
        "special": round(special / total * 100, 1),
    }


# ---------------------------------------------------------------------------
# LM Users
# ---------------------------------------------------------------------------

def lm_hashes(accounts):
    """
    Analyse accounts storing LM password hashes.

    LM hashes are a legacy password storage mechanism that
    provides significantly weaker protection than modern NTLM
    hashes. This function summarises the affected account
    population for use within reporting and remediation
    workflows.

    Args:
        accounts (list):
            Accounts identified as storing LM password hashes.

    Returns:
        dict:
            LM hash analysis results containing:

            - count:
                Number of affected accounts.

            - accounts:
                Account details associated with identified
                LM hashes.
    """

    return {
        "count": len(accounts),
        "accounts": accounts,
    }