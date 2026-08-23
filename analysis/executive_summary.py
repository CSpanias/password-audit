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

    summary.append(
        f"A password audit was performed against the {domain_name} domain to "
        "evaluate the effectiveness of password management practices and "
        "identify weaknesses that could increase the organisation's exposure "
        "to credential-based attacks. The assessment simulated the activities "
        "available to an attacker in possession of password hash material and "
        "provides insight into the strength of user credentials, the "
        "effectiveness of password controls, and the resilience of privileged "
        "accounts. "

        f"The assessment demonstrated that {size} of user credentials could be "
        "recovered through offline password-cracking techniques, indicating "
        f"that {impact} remain susceptible to compromise following credential "
        "exposure."
    )


    #---------------------------------------------------------------------------
    # High-Impact Findings
    #---------------------------------------------------------------------------
    
    # Privileged Accounts
    admin_count = results["admins"]["count"]

    # Presence of LM hashes
    lm_count = results["lm_hashes"]["count"]

    # Recovered LM passwords
    lm_recovered = results["lm_passwords"]["count"]

    # Domain Admins with LM hashes
    lm_admin_count = results["lm_admins"]["count"]

    if not admin_count:
        
        positive_findings.append("no recovered Domain Administrator passwords")

    if admin_count and lm_count:

        message = (
            "Of particular concern, the assessment identified weaknesses "
            "that could significantly increase the impact of a successful "
            "credential compromise. These included the recovery of "
            "privileged credentials and the continued use of legacy "
            "LanMan (LM) password hashes. "
        )

    elif admin_count:

        message = (
            "Of particular concern, the assessment resulted in the "
            "recovery of one or more privileged credentials. "
        )

    elif lm_count:

        message = (
            "Of particular concern, the assessment identified the continued "
            "use of legacy LanMan (LM) password hashes. "
        )

    else:
        message = None

    if message and admin_count:

        message += (
            "Privileged accounts provide elevated access to directory "
            "services, business systems, and sensitive information. The "
            "compromise of such credentials could enable unauthorised "
            "access to critical systems and data, undermine security "
            "controls, and increase the risk of operational disruption. "
        )

    if message and lm_recovered:

        message += (
            "The risk associated with credential compromise is further "
            "increased by the continued use of LM password hashes. "
            "Passwords were successfully recovered from accounts that "
            "stored LM hashes, demonstrating that this legacy "
            "authentication technology continues to increase both the "
            "likelihood and impact of credential compromise. "
        )

    elif message and lm_count:

        message += (
            "LM hashing represents an obsolete password storage mechanism "
            "that is significantly weaker than modern alternatives and "
            "increases exposure to offline password-cracking attacks. "
        )

    if message and lm_admin_count:

        message += (
            "The presence of LM-related weaknesses on privileged accounts "
            "further increases the potential impact of a successful "
            "compromise and should be prioritised for remediation."
        )

    if message:
        summary.append(message)


    #---------------------------------------------------------------------------
    # Systemic Password Weaknesses
    #---------------------------------------------------------------------------

    # Compliance with password policy
    failure_count = results["password_length"]["count"]

    # Predictable patterns
    weaknesses = []

    company_count = results["company_words"]["count"]
    username_count = results["username_passwords"]["count"]
    common_count = results["common_passwords"]["count"]
    date_count = results["date_passwords"]["count"]
    keyboard_count = results["keyboard_walks"]["count"]

    # Password reuse
    general_reuse_passwords = (results["password_reuse_general"]["sharedPasswords"])
    similar_account_reuse_pairs = results["similar_account_reuse"]["similarPairs"]
    similar_account_reuse_count = results["similar_account_reuse"]["count"]

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

    systemic_weaknesses = []

    if general_reuse_passwords:
        systemic_weaknesses.append("password reuse")

    if failure_count:
        systemic_weaknesses.append(
            "credentials that did not comply with password standards"
        )

    if weaknesses:
        systemic_weaknesses.append("predictable password selection practices")

    if systemic_weaknesses:

        message = (
            "The assessment also identified a number of broader "
            "password-management weaknesses, including "
            f"{natural_join(systemic_weaknesses)}. Collectively, these "
            "weaknesses increase the likelihood of credential compromise and "
            "reduce the overall effectiveness of password-based security "
            "controls. "
        )

        if (general_reuse_passwords or failure_count or weaknesses):

            message += (
                "Password reuse increases the potential impact of a compromised "
                "credential by potentially providing access to multiple accounts "
                "or systems, whilst weak and predictable password choices reduce "
                "the effort required to successfully compromise user accounts. "
                "Together, these conditions increase organisational exposure to "
                "unauthorised access and credential-based attacks. "
            )

            if similar_account_reuse_count:

                message += (
                    "Password reuse between related accounts may also undermine "
                    "administrative account separation and increase the risk of "
                    "privilege escalation. "
                )

    if not general_reuse_passwords:
        positive_findings.append(
            "no evidence of password reuse was identified across the "
            "recovered credential dataset"
        )

    if not failure_count:
        positive_findings.append(
            "full compliance with the configured minimum password length "
            "policy among recovered passwords"
        )

    if similar_account_reuse_pairs and not similar_account_reuse_count:
        positive_findings.append(
            "the absence of password reuse between similarly named accounts"
        )

    summary.append(message)


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
        conclusion_findings.append("privileged accounts")

    if weaknesses:
        conclusion_findings.append("credential resilience")

    # if weaknesses:
    #     conclusion_findings.append("predictable password selection practices")

    # if failure_count:
    #     conclusion_findings.append("password policy non-compliance")

    if lm_count:
        conclusion_findings.append("legacy authentication mechanisms")

    if conclusion_findings:

        summary.append(
            "Overall, the assessment identified opportunities to further "
            "strengthen password security across the environment. While many "
            "baseline controls appear effective, weaknesses affecting "
            f"{natural_join(conclusion_findings)} increase the potential "
            "impact of credential compromise. Addressing these issues will reduce the "
            "likelihood of unauthorised access, improve protection of "
            "sensitive information, and strengthen the organisation's "
            "overall resilience against credential-based attacks."
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