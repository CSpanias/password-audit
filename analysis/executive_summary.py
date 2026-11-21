"""
Generate an executive-summary narrative from password-audit findings.

The summary brings together high-impact findings, systemic weaknesses,
positive observations, and a concluding assessment.
"""

from common.utils import natural_join


def executive_summary(results):
    """Build an executive summary from aggregated password-audit results.

    Args:
        results (dict): Results produced by analysis.results.build_results.

    Returns:
        str: Summary paragraphs separated by blank lines.
    """
    summary = []

    has_positive_findings = (
        (
            results["total_passwords"]
            and (
                (
                    not results["admins"]["count"]
                    and results["privileged_users"]["status"] == "available"
                )
                or (
                    not results["password_reuse_general"]["sharedPasswords"]
                    and not results["ntlm_hash_reuse"]["groups"]
                )
                or not results["password_length"]["count"]
            )
        )
        or (
            results["similar_account_reuse"]["similarPairs"]
            and not results["similar_account_reuse"]["count"]
        )
    )

    #---------------------------------------------------------------------------
    # Introduction
    #---------------------------------------------------------------------------
    
    # Extract domain name from the domain password policy file
    domain_name = results["domain_name"].lower() or "assessed"

    # Crack rate calculation
    crack_rate = results["crack_rate"]
        
    if crack_rate < 5:
        size = "a small subset"
        impact = "a limited number of passwords"

    elif crack_rate < 15:
        size = "a subset"
        impact = "some passwords"

    elif crack_rate < 30:
        size = "a substantial subset"
        impact = "a notable proportion of passwords"

    else:
        size = "a significant subset"
        impact = "a significant proportion of passwords"

    introduction = (
        f"A password audit was performed against the {domain_name} domain to "
        "evaluate the effectiveness of password management practices and "
        "identify weaknesses that could increase the organisation's exposure "
        "to credential-based attacks. The assessment simulated the activities "
        "available to an attacker in possession of password hash material and "
        "provides insight into the strength of user credentials, the "
        "effectiveness of password controls, and the resilience of privileged "
        "accounts. "
    )
    if has_positive_findings:
        introduction += (
            "Some results suggest that existing password security controls and "
            "user practices may be reducing exposure to credential compromise. "
        )
    if results["total_passwords"]:
        introduction += (
            f"{'However, the' if has_positive_findings else 'The'} audit "
            f"demonstrated that {size} of user credentials could be "
            "recovered through offline password-cracking techniques, indicating "
            f"that {impact} remain susceptible to compromise following credential "
            "exposure."
        )
    else:
        introduction += (
            "No plaintext passwords were recovered during the campaign. "
            "This does not establish that unrecovered passwords are strong."
        )
    summary.append(introduction)

    #---------------------------------------------------------------------------
    # FINDINGS AND IMPACTS
    #---------------------------------------------------------------------------
    
    # Privileged Accounts
    admin_count = results["admins"]["count"]
    privileged_count = results["privileged_users"]["count"]
    has_privileged = bool(admin_count or privileged_count)

    # Presence of LM hashes
    lm_count = results["lm_hashes"]["count"]

    # Recovered LM passwords
    lm_recovered = results["lm_passwords"]["count"]

    # Domain Admins with LM hashes
    lm_admin_count = results["lm_admins"]["count"]

    # Compliance with password policy
    failure_count = results["password_length"]["count"]

    weaknesses = any(
        results[key]["count"]
        for key in (
            "company_words", "username_passwords", "common_passwords",
            "date_passwords", "keyboard_walks",
        )
    )

    # Password reuse
    general_reuse_passwords = (
        results["password_reuse_general"]["sharedPasswords"]
    )
    hash_reuse = results["ntlm_hash_reuse"]["groups"]

    # count counts pairs that actually share a password.
    similar_account_reuse_count = (
        results["similar_account_reuse"]["count"]
    )

    findings = []
    if has_privileged:
        findings.append(
            "Privileged account credentials were recovered, potentially "
            "providing access to critical systems and sensitive information."
        )

    if lm_count or lm_recovered:
        findings.append(
            "Legacy LanMan (LM) password hashes were present, making credentials "
            "more susceptible to offline password cracking."
        )
        if lm_recovered:
            findings.append("Passwords were recovered from accounts storing LM hashes.")
        if lm_admin_count:
            findings.append(
                "LM passwords were recovered for Domain Administrator accounts, "
                "increasing the potential impact of a compromise."
            )

    if general_reuse_passwords or hash_reuse:
        findings.append(
            "Password reuse could allow a compromised credential to affect "
            "multiple accounts or systems."
        )
        if similar_account_reuse_count:
            findings.append(
                "Reuse between related accounts may also undermine account "
                "separation and increase the risk of privilege escalation."
            )

    if results.get("hibp", {}).get("count"):
        findings.append(
            "Some account password hashes matched known breach data, suggesting "
            "their passwords may be easier to guess."
        )

    if failure_count:
        findings.append(
            "Some recovered passwords were shorter than the configured domain "
            "minimum, potentially making them easier to crack."
        )

    if weaknesses:
        findings.append(
            "Recovered passwords contained predictable patterns, potentially "
            "reducing the effort required to compromise accounts."
        )

    if findings:
        summary.append(" ".join(findings))

    #---------------------------------------------------------------------------
    # CONCLUSION
    #---------------------------------------------------------------------------
    conclusion_findings = []

    if has_privileged:
        conclusion_findings.append("privileged accounts")

    if weaknesses:
        conclusion_findings.append("credential resilience")

    if general_reuse_passwords or hash_reuse:
        conclusion_findings.append("credential separation")

    if results.get("hibp", {}).get("count"):
        conclusion_findings.append("passwords found in known breach data")

    # if weaknesses:
    #     conclusion_findings.append("predictable password selection practices")

    if failure_count:
        conclusion_findings.append("password length")

    if lm_count or lm_recovered:
        conclusion_findings.append("legacy authentication mechanisms")

    if conclusion_findings:
        if results["total_passwords"]:
            summary.append(
                "Overall, the assessment highlighted opportunities to strengthen "
                "password security across the environment. Issues relating to "
                f"{natural_join(conclusion_findings)} increase the potential "
                "impact of credential compromise. Addressing these issues can "
                "reduce the likelihood of unauthorised access and strengthen "
                "protection across the environment."
            )
        else:
            summary.append(
                "Overall, the assessment identified weaknesses affecting "
                f"{natural_join(conclusion_findings)}. No plaintext passwords "
                "were recovered, which does not establish that unrecovered "
                "passwords are strong."
            )

    elif not results["total_passwords"]:
        summary.append(
            "No plaintext passwords were recovered, so password composition "
            "could not be assessed. This does not establish that unrecovered "
            "passwords are strong or that other weaknesses are absent."
        )
    else:
        summary.append(
            "Overall, the assessment did not identify any significant "
            "password-related weaknesses during the assessement dataset. The "
            "findings indicate a generally mature approach to password "
            "management, with no evidence of systemic issues that would "
            "substantially increase the likelihood of successful "
            "credential-based attacks. Continued adherence to existing "
            "password standards, together with periodic reassessment, will "
            "help maintain and further strengthen this security posture over "
            "time."
        )

    return "\n\n".join(summary)