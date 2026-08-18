"""
Executive summary generation.

This module produces a high-level narrative overview of the
password audit findings, highlighting key strengths, weaknesses,
and overall organisational exposure to password-related risks.
"""

from common.utils import natural_join


def executive_summary(results):

    summary = []
    positive_findings = []

    # Introductory paragraph
    domain_name = results["domain_name"].lower() or "assessed"

    summary.append(
        f"A password audit was performed against the {domain_name} domain in order to assess the "
        "effectiveness of password selection practices and identify weaknesses that could increase "
        "the likelihood of credential compromise. The assessment simulated the techniques "
        "available to an attacker with access to password hash material and provides insight into "
        "the effectiveness of password policies, user behaviour, and privileged account security "
        "controls."
    )

    #---------------------------------------------------------------------------
    # Crack-rate
    #---------------------------------------------------------------------------
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

    summary.append(
        f"The assessment demonstrated that {size} of user credentials could be recovered through "
        f"offline password-cracking techniques, indicating that {impact} remain susceptible to "
        "compromise following credential exposure."
    )

    #---------------------------------------------------------------------------
    # Privileged accounts
    #---------------------------------------------------------------------------
    admin_count = results["admins"]["count"]

    if admin_count:

        if admin_count == 1:
            credential_text = "a Domain Administrator credential"
        else:
            credential_text = "multiple Domain Administrator credentials"

        summary.append(
            "Password weaknesses were observed within privileged identities, resulting in the "
            f"successful recovery of {credential_text}. Domain Administrator accounts represent "
            "some of the most sensitive identities within an Active Directory environment and "
            "typically provide unrestricted access to directory services, authentication "
            "infrastructure, and domain-joined systems. The compromise of privileged credentials "
            "substantially increases the potential impact of credential exposure and may "
            "facilitate rapid privilege escalation and wider compromise of the environment."
        )

    else:

        positive_findings.append("no Domain Administrator passwords were recovered")

    #---------------------------------------------------------------------------
    # LM-related findings
    #---------------------------------------------------------------------------
    
    # Presence of LM hashes
    lm_count = results["lm_hashes"]["count"]

    # Recovered LM passwords
    lm_recovered = results["lm_passwords"]["count"]

    # Domain Admins with LM hashes
    lm_admin_count = results["lm_admins"]["count"]

    # LM hashes present and cracked 
    if lm_recovered:

        message = (
            "Legacy LanMan (LM) password hashes were identified within the assessed environment, "
            "and passwords were successfully recovered from affected accounts. This demonstrates "
            "the practical weakness of LM password storage and highlights the increased exposure "
            "to credential compromise associated with legacy password technologies."
        )

        if lm_admin_count:

            message += (
                " Recovered credentials included privileged accounts, significantly increasing the "
                "potential impact of credential compromise and the likelihood of privilege "
                "escalation."
            )

        summary.append(message)

    # LM hashes present and not cracked
    elif lm_count:

        message = (
            "Legacy LanMan (LM) password hashes were identified within the assessed environment. "
            "LM hashing represents an obsolete password storage mechanism that is significantly "
            "weaker than modern alternatives and may increase susceptibility to offline "
            "password-cracking attacks."
        )

        if lm_admin_count:

            message += (
                " The presence of this weakness on privileged accounts increases the potential "
                "impact of credential compromise and should be prioritised for remediation."
            )

        else:

            message += (
                " The presence of LM hashes indicates an opportunity to further strengthen "
                "password security and reduce exposure to credential compromise."
            )

        summary.append(message)

    #---------------------------------------------------------------------------
    # Compliance with password policy
    #---------------------------------------------------------------------------
    failure_count = results["password_length"]["count"]
    percentage = results["password_length"]["percentage"]
    
    if failure_count:

        if percentage < 10:
            severity = "a small number of"
        elif percentage < 25:
            severity = "a number of"
        else:
            severity = "a substantial number of"

        summary.append(
            f"The assessment highlighted {severity} passwords that did not comply with the "
            "configured minimum password length requirement. The presence of non-compliant "
            "credentials suggests that some accounts may not be subject to current password "
            "standards or that legacy passwords remain in use. Such credentials generally provide "
            "less resistance to password-cracking techniques and may increase overall exposure to "
            "credential-based attacks."
        )

    else:

        positive_findings.append(
            "all recovered passwords complied with the configured minimum password length policy"
        )

    #---------------------------------------------------------------------------
    # Password reuse
    #---------------------------------------------------------------------------
    general_reuse_passwords = (results["password_reuse_general"]["sharedPasswords"])
    general_reuse_accounts = (results["password_reuse_general"]["sharedAccounts"])
    similar_account_reuse_pairs = results["similar_account_reuse"]["similarPairs"]
    similar_account_reuse_count = results["similar_account_reuse"]["count"]
    
    if general_reuse_passwords:

        if general_reuse_accounts < 10:
            scope = "limited"
        elif general_reuse_accounts < 50:
            scope = "moderate"
        else:
            scope = "widespread"

        message = (
            f"{scope.capitalize()} password reuse was identified across the recovered credential "
            "dataset. The reuse of passwords across multiple users reduces password diversity and "
            "increases the potential impact of credential compromise, as a single recovered "
            "password may provide access to multiple accounts. This can also increase "
            "susceptibility to password spraying and other credential-based attacks."
        )

        if similar_account_reuse_count:

            message += (
            " Password reuse was also identified between similarly named accounts. The reuse of "
            "credentials across related accounts may undermine administrative account separation "
            "and increase the risk of privilege escalation."
            )

        summary.append(message)

    elif similar_account_reuse_count:

        summary.append(
            "Password reuse was identified between similarly named accounts. The reuse of "
            "credentials across related accounts may undermine administrative account separation "
            "and increase the risk of privilege escalation. Where users maintain separate standard "
            "and privileged accounts, unique passwords should be used to ensure that the "
            "compromise of one account does not immediately provide access to another."
        )

    else:

        positive_findings.append(
            "no evidence of password reuse was identified across the recovered credential dataset"
        )

        if similar_account_reuse_pairs:

            positive_findings.append(
                "no password reuse was identified between similarly named accounts"
            )

    #---------------------------------------------------------------------------
    # Predictable patterns
    #---------------------------------------------------------------------------
    company_count = results["company_words"]["count"]
    username_count = results["username_passwords"]["count"]
    common_count = results["common_passwords"]["count"]
    date_count = results["date_passwords"]["count"]
    keyboard_count = results["keyboard_walks"]["count"]

    # Collect predictable patterns findings
    weaknesses = []
    
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
    
    if weaknesses:

        if len(weaknesses) == 1:
            intro = "The assessment also revealed a recurring password selection weakness,"
        else:
            intro = "The assessment also revealed multiple recurring password selection weaknesses,"

        summary.append(
            f"{intro} including {natural_join(weaknesses)}. These patterns reduce "
            "password entropy and increase exposure to password guessing, password spraying, and "
            "offline password-cracking attacks. Their presence indicates that users frequently "
            "rely on memorable and predictable password constructions, increasing the "
            "effectiveness of commonly used attack techniques and publicly available password "
            "dictionaries."
        )

    #---------------------------------------------------------------------------
    # Positive security findings
    #---------------------------------------------------------------------------
    if positive_findings:

        summary.append(
            "Several positive security outcomes were also observed, including "
            f"{natural_join(positive_findings)}. These findings suggest that several password "
            "security controls and user practices are operating effectively and help reduce the "
            "likelihood and impact of credential compromise. While they do not eliminate risk "
            "entirely, they provide a strong foundation for continued improvement."
        )

    #---------------------------------------------------------------------------
    # Conclusion
    #---------------------------------------------------------------------------
    conclusion_findings = []

    if admin_count:
        conclusion_findings.append("exposure of privileged credentials")

    if general_reuse_passwords:
        conclusion_findings.append("password reuse")

    if weaknesses:
        conclusion_findings.append("predictable password selection practices")

    if failure_count:
        conclusion_findings.append("password policy non-compliance")

    if lm_count:
        conclusion_findings.append("legacy authentication weaknesses")

    key_findings = natural_join(conclusion_findings)

    if conclusion_findings:

        summary.append(
            "Overall, the assessment highlighted opportunities to further strengthen password "
            "security across the environment. While baseline password controls appear effective "
            f"in several areas, {natural_join(conclusion_findings)} indicate that password-related "
            "risks remain present. Addressing these issues will improve resilience against "
            "credential-based attacks and further strengthen the organisation's security posture."
        )

    else:
        summary.append(
            "Overall, the assessment did not identify any significant password-related weaknesses "
            "during the assessement dataset. The findings indicate a generally mature approach to "
            "password management, with no evidence of systemic issues that would substantially "
            "increase the likelihood of successful credential-based attacks. Continued adherence "
            "to existing password standards, together with periodic reassessment, will help "
            "maintain and further strengthen this security posture over time."
        )

    return "\n\n".join(summary)