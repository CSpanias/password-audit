"""
Password analysis result generation.

This module coordinates password analysis functions and
constructs the standardised results structure consumed by
reporting components.
"""

from analysis.analysis import (
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
    lm_hashes
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
    lm_users,
):
    """
    Build the complete password analysis results dataset.

    Individual password analysis functions are executed and
    their findings aggregated into a standardised results
    structure consumed by the executive summary, technical
    commentary, remediation guidance, and other reporting
    components.

    Args:
        passwords (list):
            Recovered plaintext password mappings.

        domain_admins (list):
            Domain Administrator usernames.

        company_words (list):
            Organisation-specific terms used during
            password pattern analysis.

        minimum_length (int):
            Configured minimum password length obtained
            from the domain password policy.

        enabled_users (list):
            Enabled user accounts within the assessed
            Active Directory environment.

        lm_users (list):
            Accounts identified as storing LM password
            hashes.

    Returns:
        dict:
            Standardised analysis results containing
            password statistics, policy compliance
            findings, password pattern analysis,
            privileged account exposure, LM hash
            exposure, and supporting reporting data.
    """

    # Privileged accounts
    admins = compromised_admins(
        passwords, 
        domain_admins
    )

    # Password compliance
    length_distribution = password_length_distribution(passwords)
    length_failures = password_length_failures(
        passwords, 
        minimum_length
    )
    
    # Predictable patterns
    company_findings = company_name_passwords(
        passwords, 
        company_words
    )
    keyboard_findings = keyboard_walk_passwords(passwords)
    username_findings = username_passwords(passwords)
    common_password_findings = common_passwords(passwords)
    date_findings = date_passwords(passwords)

    # Password reuse
    password_frequencies = password_frequency(passwords)
    top_passes = top_passwords(passwords)
    reused_passwords = [
            (password, count)
            for password, count in password_frequencies
            if count > 1
        ]
    reuse_accounts, similar_pairs = similar_account_reuse(passwords)
    
    # Password complexity
    char_classes = character_class_adoption(passwords)

    # Presence of LM hashes
    lm_findings = lm_hashes(lm_users)

    # Duplicate LM hashes
    unique_hashes = len({
        account["lm_hash"]
        for account in lm_findings["accounts"]
    })

    results = {}

    # Privileged accounts
    results["admins"] = {
        "accounts": admins,
        "count": len(admins)
    }

    # Password compliance
    results["password_length"] = {
        "minimum_length": minimum_length,
        "failures": length_failures,
        "count": len(length_failures),
        "percentage": (
            round(len(length_failures) / len(passwords) * 100, 1)
            if passwords else 0
        )
    }

    results["password_lengths"] = {"lengths": length_distribution}

    # Password reuse
    results["top_passwords"] = {
        "passwords": top_passes,
        "count": len(top_passes)
    }

    results["similar_account_reuse"] = {
        "accounts": reuse_accounts,
        "count": len(reuse_accounts),
        "similarPairs": similar_pairs,
    }

    results["password_frequency"] = {"passwords": password_frequencies}

    # Predictable patterns
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

    results["username_passwords"] = {
        "count": len(username_findings),
        "accounts": username_findings,
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

    # Password complexity
    results["character_classes"] = char_classes

    # Crack rate
    results["total_passwords"] = len(passwords)
    results["enabled_users"] = len(enabled_users)
    results["unique_passwords"] = len(
        set(
            p["password"] for p in passwords
        )
    )

    results["crack_rate"] = (
        round(
            len(passwords) / len(enabled_users) * 100,
            1
        )
        if enabled_users
        else 0
    )

    # Password reuse
    results["password_reuse_general"] = {
        "sharedPasswords": len(reused_passwords),
        "sharedAccounts": sum(
            count
            for _, count in reused_passwords
        ),
        "percentage": (
            round(
                sum(entry[1] for entry in reused_passwords)
                / len(passwords) * 100,
                1
            )
            if passwords
            else 0
        ),
        "passwords": reused_passwords,
    }

    # Presence of LM hashes
    results["lm_hashes"] = {
        "count": lm_findings["count"],
        "accounts": lm_findings["accounts"],
        "uniqueHashes": unique_hashes,
        "duplicateHashes": (
            lm_findings["count"] - unique_hashes
        ),
    }

    return results