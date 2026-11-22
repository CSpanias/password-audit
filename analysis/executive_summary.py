"""
Generate an executive-summary narrative from password-audit findings.

The summary brings together high-impact findings, systemic weaknesses,
positive observations, and a concluding assessment.
"""

from analysis.findings import build_findings_dict, finding_priority
from common.utils import proportion_wording


def executive_summary(results, findings_data=None):
    """Build an executive summary from aggregated password-audit results.

    Args:
        results (dict): Results produced by analysis.results.build_results.

    Returns:
        str: Summary paragraphs separated by blank lines.
    """
    summary = []
    if findings_data is None:
        findings_data = build_findings_dict(results)

    has_reuse = bool(
        results["password_reuse_general"]["sharedPasswords"]
        or results["ntlm_hash_reuse"]["groups"]
    )
    # Absence of general reuse already covers similarly named accounts.
    positive_observations = sum((
        bool(
            results["total_passwords"]
            and not results["admins"]["count"]
            and not results["privileged_users"]["count"]
            and not results["privileged_users"]["lm_recovered_count"]
            and not results["lm_admins"]["count"]
            and results["privileged_users"]["status"] == "available"
        ),
        bool(
            results["total_passwords"] and not has_reuse
            and results["ntlm_hash_reuse"]["status"] == "available"
        ),
        bool(
            results["total_passwords"]
            and results["password_length"]["minimum_length"] is not None
            and not results["password_length"]["count"]
        ),
        bool(
            results["total_passwords"] and has_reuse
            and results["ntlm_hash_reuse"]["status"] == "available"
            and results["similar_account_reuse"]["similarPairs"]
            and not results["similar_account_reuse"]["count"]
        ),
    ))

    #---------------------------------------------------------------------------
    # Introduction
    #---------------------------------------------------------------------------
    
    # Extract domain name from the domain password policy file
    domain_name = (results["domain_name"] or "assessed").lower()

    introduction = (
        f"A password audit was performed against the {domain_name} domain to "
        "evaluate the effectiveness of password management practices and "
        "identify weaknesses that could increase the organisation's exposure "
        "to credential-based attacks."
    )
    if results["total_passwords"]:
        if results["enabled_users"]:
            size, impact = proportion_wording(results["crack_rate"])
            recovery = (
                f"{size} of user credentials could be recovered through offline "
                f"password cracking, indicating that {impact} passwords remain susceptible "
                "to compromise if credential data is exposed"
            )
        else:
            recovery = (
                "passwords could be recovered through offline password cracking, "
                "demonstrating their susceptibility to compromise if credential "
                "data is exposed"
            )
        if positive_observations:
            positive = (
                "some positive observations" if positive_observations <= 2
                else "many positive observations"
            )
            introduction += (
                f" While the assessment yielded {positive} about password "
                f"security, {recovery}."
            )
        else:
            introduction += f" The assessment demonstrated that {recovery}."
    else:
        introduction += (
            " No plaintext passwords were recovered during the campaign. "
            "This does not establish that unrecovered passwords are strong."
        )
    if results["password_length"]["minimum_length"] is None:
        introduction += (
            " Password length compliance could not be assessed because the "
            "domain minimum password length was unavailable."
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

    # Count unique pairs with matching recovered passwords or NTLM hashes.
    similar_account_reuse_count = (
        results["similar_account_reuse"]["count"]
    )

    findings = []
    if has_privileged:
        findings.append((("DOMAIN-ADMIN-001", "PRIV-ACCOUNT-001"),
            "Privileged account credentials were recovered, which could expose "
            "critical systems and sensitive information to unauthorised access."
        ))

    if lm_count or lm_recovered:
        finding = (
            "Legacy LanMan (LM) password hashes were present"
            + (", including for Domain Administrator accounts" if lm_admin_count else "")
            + ", making credentials more susceptible to offline password cracking"
        )
        if lm_recovered:
            finding += (
                ", as demonstrated by passwords recovered from accounts storing "
                "them"
            )
        finding += "."
        findings.append((("LM-AUTH-001", "DOMAIN-ADMIN-002"), finding))

    if general_reuse_passwords or hash_reuse:
        finding = (
            "Password reuse could allow a compromised credential to affect "
            "multiple accounts or systems"
        )
        if similar_account_reuse_count:
            finding += (
                " and may undermine separation between accounts "
                "with different roles"
            )
        findings.append((("PWD-REUSE-001", "PWD-REUSE-002", "PWD-REUSE-003"), finding + "."))

    breached = bool(results.get("hibp", {}).get("count"))
    if breached and weaknesses:
        findings.append((("PWD-BREACH-001", "PWD-PATTERN-001", "PWD-PATTERN-002",
                          "PWD-PATTERN-003", "PWD-PATTERN-004", "PWD-PATTERN-005"),
            "Passwords matching known breach data and passwords with "
            "predictable patterns were identified, placing affected accounts at "
            "greater risk of compromise."
        ))
    elif breached:
        findings.append((("PWD-BREACH-001",),
            "Some passwords matched known breach data, placing affected accounts "
            "at greater risk of compromise."
        ))
    elif weaknesses:
        findings.append((("PWD-PATTERN-001", "PWD-PATTERN-002", "PWD-PATTERN-003",
                          "PWD-PATTERN-004", "PWD-PATTERN-005"),
            "Some recovered passwords followed predictable patterns, placing "
            "affected accounts at greater risk of compromise."
        ))

    if failure_count:
        findings.append((("PWD-POLICY-001",),
            "Some recovered passwords fell below the domain's configured "
            "minimum length and may be easier to guess or crack."
        ))

    if findings:
        findings.sort(key=lambda item: finding_priority(findings_data, item[0]))
        sentences = []
        for index, (_, text) in enumerate(findings):
            if index == 1:
                text = "In addition, " + text[0].lower() + text[1:]
            elif index > 1 and index == len(findings) - 1:
                text = "Finally, " + text[0].lower() + text[1:]
            sentences.append(text)
        summary.append(
            "The assessment also highlighted weaknesses that could increase "
            "the risk of credential compromise. "
            + " ".join(sentences)
        )

    #---------------------------------------------------------------------------
    # CONCLUSION
    #---------------------------------------------------------------------------
    if findings:
        conclusion = (
            "Overall, the assessment highlighted opportunities to strengthen "
            "password security across the environment. Prioritising remediation "
            "according to severity and business context can reduce the likelihood "
            "of unauthorised access and strengthen protection across the environment."
        )
        if has_privileged or lm_admin_count:
            conclusion += (
                " Affected privileged passwords should be reset promptly."
            )
        conclusion += (
            " Tracking remediation and reassessing affected controls will help "
            "confirm that weaknesses have been addressed."
        )
        summary.append(conclusion)

    elif not results["total_passwords"]:
        summary.append(
            "Overall, password composition could not be assessed, and other "
            "weaknesses may remain undetected."
        )
    else:
        summary.append(
            "Overall, no significant password-related weaknesses were observed "
            "in the assessed data. Continue to review password practices and "
            "reassess periodically, as unrecovered credentials may still contain "
            "weaknesses."
        )

    return "\n\n".join(summary)