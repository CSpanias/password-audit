"""
Analysis findings.

This module converts analysis results into a structured
finding format suitable for export.
"""


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
                f"{results['total_passwords']:,} plaintext passwords "
                f"were recovered from {results['enabled_users']:,} "
                f"enabled accounts ({results['crack_rate']}%)."
            )
        },
        {
            "id": "password-statistics",
            "title": "Password Statistics",
            "description": (
                "Password frequency and character usage "
                "statistics were analysed."
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
                f"{domain_admins_ntlm:,} Domain Administrator "
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
                f"{lm_hashes:,} accounts were found "
                "storing LM password hashes."
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
                f"{domain_admins_lm:,} Domain Administrator "
                "accounts were found storing LM password hashes."
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
                f"{non_compliant_passwords:,} "
                " passwords did not comply "
                "with the configured minimum password "
                "length requirement."
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
                f"{reused_passwords:,} passwords were reused across "
                "multiple unrelated accounts."
            )
        })

    # Password reuse between similarly-named accounts
    similar_name_reuse = results["similar_account_reuse"]["count"]

    if similar_name_reuse:

        findings.append({
            "id": "shared-account-passwords",
            "title": "Shared Passwords",
            "description": (
                f"{similar_name_reuse:,} "
                "Same password across similarly named accounts "
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
                f"{username_passwords:,} passwords contained "
                "username-derived content."
            )
        })

    company_words = results["company_words"]["count"]

    if company_words:

        findings.append({
            "id": "organisation-related-passwords",
            "title": "Organisation-Related Passwords",
            "description": (
                f"{company_words:,} passwords contained "
                "organisation-related terminology."
            )
        })

    common_passwords = results["common_passwords"]["count"]

    if common_passwords:

        findings.append({
            "id": "common-passwords",
            "title": "Common Passwords",
            "description": (
                f"{common_passwords:,} passwords contained common "
                "dictionary words."
            )
        })

    date_passwords = results["date_passwords"]["count"]

    if date_passwords:

        findings.append({
            "id": "date-based-passwords",
            "title": "Date-Based Passwords",
            "description": (
                f"{date_passwords:,} passwords contained "
                "date-related content."
            )
        })

    keyboard_walks = results["keyboard_walks"]["count"]

    if keyboard_walks:

        findings.append({
            "id": "keyboard-patterns",
            "title": "Keyboard Patterns",
            "description": (
                f"{keyboard_walks:,} passwords contained keyboard "
                "walking patterns."
            )
        })

    return findings