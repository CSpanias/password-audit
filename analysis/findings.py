"""
Analysis findings.

This module converts analysis results into a structured
finding format suitable for export.
"""

from common.utils import num_to_word


def build_findings(results):
    """
    Build findings from analysis results.

    Args:
        results:
            Analysis results.

    Returns:
        list:
            Findings.
    """

    #----------------------------------------
    # Generic analysis
    #----------------------------------------

    findings = [

        {
            "id": "password-audit",
            "title": "Password Audit",
            "description": (
                f"A total of {num_to_word(results['total_passwords'])} plaintext passwords were "
                f"recovered from {num_to_word(results['enabled_users'])} enabled accounts."
            )
        },
        {
            "id": "password-statistics",
            "title": "Password Statistics",
            "description": (
                "Password frequency and character usage statistics were analysed."
            )
        }
    ]

    #----------------------------------------
    # Privileged accounts
    #----------------------------------------

    domain_admins_ntlm = results["admins"]["count"]

    if domain_admins_ntlm:

        findings.append({
            "id": "domain-admin-passwords",
            "title": "Recovered Domain Administrator Passwords",
            "description": (
                f"A total of {num_to_word(domain_admins_ntlm)} Domain Administrator "
                f"password{'s' if domain_admins_ntlm != 1 else ''} "
                f"{'were' if domain_admins_ntlm != 1 else 'was'} recovered."
            )
        })

    #----------------------------------------
    # LM presence
    #----------------------------------------

    lm_hashes = results["lm_hashes"]["count"]

    if lm_hashes:

        findings.append({
            "id": "lm-hashes-present",
            "title": "LM Hashes Present",
            "description": (
                f"A total of {num_to_word(lm_hashes)} account{'s' if lm_hashes != 1 else ''} were "
                "found storing LM password hashes."
            )
        })

    #----------------------------------------
    # Privileged accounts with LM hashes
    #----------------------------------------

    domain_admins_lm = results["lm_admins"]["count"]

    if domain_admins_lm:

        findings.append({
            "id": "domain-admin-lm-hashes",
            "title": "Domain Administrator LM Hashes",
            "description": (
                f"A total of {num_to_word(domain_admins_lm)} Domain Administrator "
                f"account{'s' if domain_admins_lm != 1 else ''} "
                f"{'were' if domain_admins_lm != 1 else 'was'} found storing LM password hashes."
            )
        })


    #----------------------------------------
    # Password length compliance
    #----------------------------------------
    
    non_compliant_passwords = results["password_length"]["count"]

    if non_compliant_passwords:

        findings.append({
            "id": "non-compliant-passwords",
            "title": "Non-Compliant Passwords",
            "description": (
                f"A total of {num_to_word(non_compliant_passwords)} "
                f"password{'s' if non_compliant_passwords != 1 else ''} did not comply with the "
                "configured minimum password length requirement."
            )
        })

    #----------------------------------------
    # Password reuse
    #----------------------------------------
    
    # Generic password reuse
    reused_passwords = sum(
        1
        for _, count in results["password_frequency"]["passwords"]
        if count > 1
    )

    if reused_passwords:

        findings.append({
            "id": "password-reuse",
            "title": "Password Reuse",
           "description": (
                f"A total of {num_to_word(reused_passwords)} "
                f"password{'s' if reused_passwords != 1 else ''} "
                f"{'were' if reused_passwords != 1 else 'was'} reused across multiple unrelated "
                "accounts."
            )
        })

    # Password reuse between similarly-named accounts
    similar_name_reuse = results["similar_account_reuse"]["count"]

    if similar_name_reuse:

        findings.append({
            "id": "shared-account-passwords",
            "title": "Shared Passwords",
            "description": (
                f"A total of {num_to_word(similar_name_reuse)} same "
                f"password{'s' if similar_name_reuse != 1 else ''} across similarly named "
                "accounts. "
            )
        })
    
    #----------------------------------------
    # Predictable patterns
    #----------------------------------------

    username_passwords = results["username_passwords"]["count"]

    if username_passwords:

        findings.append({
            "id": "username-derived-passwords",
            "title": "Username-Derived Passwords",
            "description": (
                f"A total of {num_to_word(username_passwords)} "
                f"password{'s' if username_passwords != 1 else ''} contained username-derived "
                "content."
            )
        })

    company_words = results["company_words"]["count"]

    if company_words:

        findings.append({
            "id": "organisation-related-passwords",
            "title": "Organisation-Related Passwords",
            "description": (
                f"A total of {num_to_word(company_words)} "
                f"password{'s' if company_words != 1 else ''} contained organisation-related "
                "terminology."
            )
        })

    common_passwords = results["common_passwords"]["count"]

    if common_passwords:

        findings.append({
            "id": "common-passwords",
            "title": "Common Passwords",
            "description": (
                f"A total of {num_to_word(common_passwords)} "
                f"password{'s' if common_passwords != 1 else ''} contained common dictionary words."
            )
        })

    date_passwords = results["date_passwords"]["count"]

    if date_passwords:

        findings.append({
            "id": "date-based-passwords",
            "title": "Date-Based Passwords",
            "description": (
                f"A total of {num_to_word(date_passwords)} "
                f"password{'s' if date_passwords != 1 else ''} contained date-related content."
            )
        })

    keyboard_walks = results["keyboard_walks"]["count"]

    if keyboard_walks:

        findings.append({
            "id": "keyboard-patterns",
            "title": "Keyboard Patterns",
            "description": (
                f"A total of {num_to_word(keyboard_walks)} "
                f"password{'s' if keyboard_walks != 1 else ''} contained keyboard walking patterns."
            )
        })

    return findings