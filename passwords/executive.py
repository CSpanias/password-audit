"""
Executive summary generation.

This module produces a high-level narrative overview of the
password audit findings, highlighting key strengths, weaknesses,
and overall organisational exposure to password-related risks.
"""

from common.utils import (
    natural_join,
    num_to_word,
)

def executive_summary(results):

    total = results["total_passwords"]
    enabled_users = results["enabled_users"]
    admin_count = results["admins"]["count"]
    failure_count = results["password_length"]["count"]
    percentage = results["password_length"]["percentage"]
    minimum_length = results["password_length"]["minimum_length"]
    company_count = results["company_words"]["count"]
    username_count = results["username_passwords"]["count"]
    similar_pairs = results["password_reuse"]["similarPairs"]
    reuse_count = results["password_reuse"]["count"]
    common_count = results["common_passwords"]["count"]
    date_count = results["date_passwords"]["count"]
    keyboard_count = results["keyboard_walks"]["count"]
    crack_rate = results["crack_rate"]

    summary = []
    weaknesses = []

    if reuse_count:
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

    summary.append("A password audit was performed against extracted Active Directory password hashes to assess the "
        "effectiveness of password selection practices and identify weaknesses that could increase the likelihood "
        f"of credential compromise. Through password-cracking techniques, it was possible to recover {num_to_word(total)} plaintext passwords "
        f"from {num_to_word(enabled_users)} enabled user accounts, representing approximately {crack_rate}% of the assessed population. "
        "This demonstrates that a measurable proportion of user credentials remain susceptible to password-cracking "
        "attacks following credential exposure.")

    if admin_count:
            summary.append(f"Password weaknesses were identified within privileged identities, resulting in the "
                f"successful recovery of {num_to_word(admin_count)} Domain Administrator password{'s' if admin_count > 1 else ''}. "
                "Such identities represent high-value targets due to the elevated level of access they provide "
                "across the environment. Their compromise would substantially increase the potential impact of a successful attack.")

    else:
        summary.append("No Domain Administrator passwords were recovered during the assessment. This is a positive outcome as privileged "
            "identities represent high-value targets and their compromise would significantly increase the potential impact of a successful attack.")

    if similar_pairs == 0:
    
        summary.append("No similarly named account pairs were identified during the assessment. As a result, password reuse"
            " between related standard and privileged accounts could not be assessed.")
    
    elif reuse_count == 0:

        summary.append("No password reuse was identified between similarly named accounts, indicating that administrative "
            "account separation does not appear to be undermined through credential reuse.")

    if failure_count:
    
            summary.append(f"The domain enforced a minimum password length requirement of {num_to_word(minimum_length)} characters. "
                f"However, analysis of the recovered credentials identified {num_to_word(failure_count)} passwords "
                f"({percentage}% of recovered passwords) that did not comply with this requirement, "
                "indicating that weak, legacy, or otherwise non-compliant credentials remain present within the environment.")

    else:
        summary.append("All recovered passwords complied with the domain's minimum password length requirement.")

    if weaknesses:
        summary.append(
            f"The assessment also identified recurring password selection weaknesses including {natural_join(weaknesses)}. "
            "These patterns reduce password entropy and increase susceptibility to password guessing, password spraying, "
            "and offline password-cracking attacks.")

    has_findings = (admin_count or failure_count or weaknesses)

    if has_findings:
        summary.append("Overall, the results indicate that password complexity and selection practices could be further improved. "
                "Strengthening password policy enforcement, reducing the use of predictable password patterns, and ensuring "
                "privileged accounts utilise unique, high-entropy passwords will reduce the likelihood of successful "
                "credential-based attacks and improve the overall resilience of the organisation's identity infrastructure.")

    else:
        summary.append("Overall, the assessment did not identify any significant password-related weaknesses within the recovered credential dataset.")

    return "\n\n".join(summary)