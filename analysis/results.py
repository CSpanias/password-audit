"""
Password analysis result generation.

This module coordinates password analysis functions and
constructs the standardised results structure consumed by
reporting components.
"""

from analyse.analysis import (
    compromised_admins,
    password_length_failures,
    top_passwords,
    company_name_passwords,
    company_word_stats,
    keyboard_walk_passwords,
    keyboard_walk_stats,
    username_passwords,
    similar_account_reuse,
    common_passwords,
    common_password_stats,
    date_passwords,
    date_stats,
    password_frequency,
    character_class_adoption,
    password_length_distribution,
)


# TODO:
# Consider replacing the nested results dictionary with
# dataclasses once the wider framework refactor is complete.


def build_results(
    passwords,
    domain_admins,
    company_words,
    minimum_length,
    enabled_users,
):
    """
    Build the complete password analysis results dataset.

    Returns:
        dict: Standardised analysis results.
    """

    admins = compromised_admins(passwords, domain_admins)

    length_failures = password_length_failures(
        passwords,
        minimum_length,
    )

    top_passes = top_passwords(passwords)

    company_findings = company_name_passwords(
        passwords,
        company_words,
    )

    keyboard_findings = keyboard_walk_passwords(passwords)

    username_findings = username_passwords(passwords)

    reuse_accounts, similar_pairs = (
        similar_account_reuse(passwords)
    )

    common_password_findings = common_passwords(passwords)

    date_findings = date_passwords(passwords)

    password_frequencies = password_frequency(passwords)

    char_classes = character_class_adoption(passwords)

    length_distribution = (
        password_length_distribution(passwords)
    )

    results = {}

    results["admins"] = {
        "accounts": admins,
        "count": len(admins)
    }

    results["password_length"] = {
        "minimum_length": minimum_length,
        "failures": length_failures,
        "count": len(length_failures),
        "percentage": (
            round(len(length_failures) / len(passwords) * 100, 1)
            if passwords else 0
        )
    }

    results["top_passwords"] = {
        "passwords": top_passes,
        "count": len(top_passes)
    }

    results["company_words"] = {
        "count": len(company_findings),
        "accounts": company_findings,
        "stats": company_word_stats(company_findings),
        "company_words": company_words,
    }

    results["keyboard_walks"] = {
        "count": len(keyboard_findings),
        "accounts": keyboard_findings,
        "stats": keyboard_walk_stats(keyboard_findings),
    }

    results["username_passwords"] = {
        "count": len(username_findings),
        "accounts": username_findings,
    }

    results["password_reuse"] = {
        "accounts": reuse_accounts,
        "count": len(reuse_accounts),
        "similarPairs": similar_pairs,
    }

    results["common_passwords"] = {
        "count": len(common_password_findings),
        "accounts": common_password_findings,
        "stats": common_password_stats(
            common_password_findings
        ),
    }

    results["date_passwords"] = {
        "count": len(date_findings),
        "accounts": date_findings,
        "stats": date_stats(date_findings),
    }

    results["password_frequency"] = {
        "passwords": password_frequencies
    }

    results["character_classes"] = char_classes

    results["password_lengths"] = {
        "lengths": length_distribution
    }

    results["total_passwords"] = len(passwords)

    results["unique_passwords"] = len(
        set(p["password"] for p in passwords)
    )

    results["enabled_users"] = len(enabled_users)

    results["crack_rate"] = (
        round(
            len(passwords) / len(enabled_users) * 100,
            1
        )
        if enabled_users
        else 0
    )

    return results