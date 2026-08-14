"""
Executive summary generation.

This module produces a high-level narrative overview of the
password audit findings, highlighting key strengths, weaknesses,
and overall organisational exposure to password-related risks.
"""

from common.utils import natural_join, num_to_word

def executive_summary(results):

    # Crack rate
    total = results["total_passwords"]
    enabled_users = results["enabled_users"]
    crack_rate = results["crack_rate"]

    # Privileged accounts
    admin_count = results["admins"]["count"]

    # Passwords non-compliant with domain policy
    minimum_length = results["password_length"]["minimum_length"]
    failure_count = results["password_length"]["count"]
    percentage = results["password_length"]["percentage"]

    # Predictable patterns
    company_count = results["company_words"]["count"]
    username_count = results["username_passwords"]["count"]
    common_count = results["common_passwords"]["count"]
    date_count = results["date_passwords"]["count"]
    keyboard_count = results["keyboard_walks"]["count"]

    # General password reuse
    general_reuse_passwords = (results["password_reuse_general"]["sharedPasswords"])
    general_reuse_accounts = (results["password_reuse_general"]["sharedAccounts"])
    general_reuse_percentage = (results["password_reuse_general"]["percentage"])

    # Password reuse between similarly-named accounts
    similar_account_reuse_pairs = results["similar_account_reuse"]["similarPairs"]
    similar_account_reuse_count = results["similar_account_reuse"]["count"]

    # Presence of LM hashes
    lm_count = results["lm_hashes"]["count"]

    # Presence of duplicate hashes
    unique_hashes = results["lm_hashes"]["uniqueHashes"]

    # Recovered LM passwords
    lm_recovered = results["lm_passwords"]["count"]

    # Domain Admins with LM hashes
    lm_admin_count = results["lm_admins"]["count"]

    # Collect predictable patterns findings
    weaknesses = []

    if similar_account_reuse_count:
        weaknesses.append("password reuse between related accounts")

    if username_count:
        weaknesses.append("username-derived passwords")

    if company_count:
        weaknesses.append("organisation-related terminology")

    if common_count:
        weaknesses.append("common password phrases")

    if date_count:
        weaknesses.append("date-based passwords")

    if keyboard_count:
        weaknesses.append("keyboard sequences")

    summary = []
    positive_findings = []

    # Introductory paragraph
    summary.append(
        "A password audit was performed against extracted Active Directory "
        "password hashes to assess the effectiveness of password selection "
        "practices and identify weaknesses that could increase the likelihood "
        "of credential compromise. The assessment simulated the techniques "
        "available to an attacker with access to password hash material and "
        "provides insight into the effectiveness of password policies, user "
        "behaviour, and privileged account security controls."
    )

    # Crack-rate
    summary.append(
        f"Through password-cracking techniques, it was possible to recover "
        f"{num_to_word(total)} plaintext passwords from "
        f"{num_to_word(enabled_users)} enabled user accounts, representing "
        f"approximately {crack_rate}% of the assessed population. "
        "This demonstrates that a measurable proportion of user credentials "
        "remain susceptible to offline password-cracking attacks following "
        "credential exposure."
    )

    # Privileged accounts
    if admin_count:

        summary.append(
            f"Password weaknesses were identified within privileged identities, "
            f"resulting in the successful recovery of "
            f"{num_to_word(admin_count)} Domain Administrator password"
            f"{'s' if admin_count > 1 else ''}. "
            "Domain Administrator accounts represent some of the most sensitive "
            "identities within an Active Directory environment and typically "
            "provide unrestricted access to directory services, authentication "
            "infrastructure, and domain-joined systems. The successful recovery "
            "of any privileged credential substantially increases the potential "
            "impact of credential exposure and may facilitate rapid privilege "
            "escalation and wider compromise of the environment."
        )

    else:

        positive_findings.append(
            "no Domain Administrator passwords were recovered"
        )

    # Presence of LM hashes
    if lm_count:

        summary.append(
            "Legacy LM password hashes were identified for "
            f"{num_to_word(lm_count)} account{'s' if lm_count != 1 else ''}. "
            f"Analysis identified only {num_to_word(unique_hashes)} unique LM hash "
            f"value{'s' if unique_hashes != 1 else ''}, indicating that multiple "
            "accounts share identical LM hashes. The presence of LM hashes represents "
            "a legacy security weakness and may increase susceptibility to "
            "offline password-cracking attacks."
        )

    # Recovered LM passwords
    if lm_recovered:

        message = (
            f"Passwords were recovered from {num_to_word(lm_recovered)} account"
            f"{'s' if lm_recovered != 1 else ''} storing LM hashes, demonstrating "
            "the practical weakness of legacy LM password storage and the "
            "ease with which credentials may be recovered through offline attacks."
        )

        # Domain Admins with LM hashes
        if lm_admin_count:

            message += (
                f" Recovered passwords included {num_to_word(lm_admin_count)} Domain "
                f"Administrator account{'s' if lm_admin_count != 1 else ''}, "
                "significantly increasing the potential impact of credential compromise "
                "and the likelihood of privilege escalation."
            )

        summary.append(message)

    # Compliance with password policy
    if failure_count:

        summary.append(
            "The domain enforced a minimum password length requirement of "
            f"{num_to_word(minimum_length)} characters. However, analysis "
            f"of the recovered credentials identified {num_to_word(failure_count)} "
            f"passwords ({percentage}% of recovered passwords) that did not "
            "comply with this requirement. The presence of non-compliant "
            "credentials suggests that some accounts may not be subject to "
            "current password standards or that legacy passwords remain in use. "
            "Such credentials generally provide less resistance to password-"
            "cracking techniques and may disproportionately contribute to the "
            "overall credential exposure identified during the assessment."
        )

    else:

        positive_findings.append(
            "all recovered passwords complied with the domain's minimum "
            f"password length requirement of {num_to_word(minimum_length)} "
            "characters"
        )

    # Password reuse
    if general_reuse_passwords:

        summary.append(
            "Password reuse was identified across the recovered credential "
            f"dataset, with {num_to_word(general_reuse_passwords)} shared "
            f"password{'s' if general_reuse_passwords != 1 else ''} affecting "
            f"{num_to_word(general_reuse_accounts)} user account"
            f"{'s' if general_reuse_accounts != 1 else ''}. "
            "The reuse of passwords across multiple users reduces password "
            "diversity and increases the potential impact of credential "
            "compromise, as a single recovered password may provide access "
            "to multiple accounts. This can also increase susceptibility "
            "to password spraying and other credential-based attacks."
        )

    else:

        positive_findings.append(
            "no evidence of password reuse was identified across the "
            "recovered credential dataset"
        )

    # Password reuse between similarly named accounts
    if similar_account_reuse_count:
    
        summary.append(
            "Password reuse was identified between "
            f"{num_to_word(similar_account_reuse_count)} similarly named "
            f"account pair{'s' if similar_account_reuse_count != 1 else ''}. "
            "The reuse of credentials across related accounts may undermine "
            "administrative account separation and increase the risk of "
            "privilege escalation. Where users maintain separate standard "
            "and privileged accounts, unique passwords should be used to "
            "ensure that the compromise of one account does not immediately "
            "provide access to another."
        )
    
    elif similar_account_reuse_pairs:

        positive_findings.append(
            "no password reuse was identified between similarly named accounts"
        )

    # Predictable patterns
    if weaknesses:

        summary.append(
            "The assessment also identified recurring password selection "
            f"weaknesses including {natural_join(weaknesses)}. "
            "These patterns reduce password entropy and increase exposure "
            "to password guessing, password spraying, and offline password-"
            "cracking attacks. Their presence indicates that users frequently "
            "rely on memorable and predictable password constructions, "
            "increasing the effectiveness of commonly used attack techniques "
            "and publicly available password dictionaries."
        )

    has_findings = (
        admin_count
        or failure_count
        or general_reuse_passwords
        or weaknesses
    )

    # Positive security findings
    if positive_findings:

        summary.append(
            "Several positive security outcomes were also observed, "
            f"including {natural_join(positive_findings)}. "
            "These findings suggest that several password security controls "
            "and user practices are operating effectively and help reduce the "
            "likelihood and impact of credential compromise. While they do not "
            "eliminate risk entirely, they provide a strong foundation for "
            "continued improvement."
        )

    # Conclusion
    conclusion_findings = []

    if admin_count:
        conclusion_findings.append(
            "the compromise of a privileged account"
        )

    if general_reuse_passwords:
        conclusion_findings.append(
            "password reuse across multiple user accounts"
        )

    if weaknesses:
        conclusion_findings.append(
            "predictable password selection patterns"
        )

    if failure_count:
        conclusion_findings.append(
            "non-compliance with password policy requirements"
        )

    if lm_count:
        conclusion_findings.append(
            "legacy LM password storage"
        )

    if lm_recovered:
        conclusion_findings.append(
            "successful recovery of passwords from LM hashes"
        )

    key_findings = natural_join(conclusion_findings)

    if conclusion_findings:

        summary.append(
            "Overall, the assessment identified opportunities to further "
            "strengthen password security across the environment. While "
            "baseline password controls appear to be functioning "
            "effectively in several areas, "
            f"{key_findings} demonstrate"
            f"{'s' if len(conclusion_findings) == 1 else ''} "
            "that password-related risks remain present. Addressing these "
            "issues will improve resilience against credential-based attacks "
            "and strengthen the organisation's overall security posture."
        )

    else:
        summary.append(
            "Overall, the assessment did not identify any significant "
            "password-related weaknesses within the recovered credential "
            "dataset. The findings indicate a generally mature approach "
            "to password management, with no evidence of systemic issues "
            "that would substantially increase the likelihood of successful "
            "credential-based attacks. Continued adherence to existing "
            "password standards, together with periodic reassessment, will "
            "help maintain and further strengthen this security posture "
            "over time."
        )

    return "\n\n".join(summary)