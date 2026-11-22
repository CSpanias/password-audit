"""
Generate an executive-summary narrative from password-audit findings.

The summary brings together high-impact findings, systemic weaknesses,
positive observations, and a concluding assessment.
"""

from analysis.findings import build_findings_dict, finding_priority
from common.utils import natural_join


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
            and results["privileged_users"]["status"] == "available"
        ),
        bool(results["total_passwords"] and not has_reuse),
        bool(results["total_passwords"] and not results["password_length"]["count"]),
        bool(
            results["total_passwords"] and has_reuse
            and results["similar_account_reuse"]["similarPairs"]
            and not results["similar_account_reuse"]["count"]
        ),
    ))

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
        "to credential-based attacks."
    )
    if results["total_passwords"]:
        if results["enabled_users"]:
            recovery = (
                f"{size} of user credentials could be recovered through offline "
                f"password cracking, indicating that {impact} remain susceptible "
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
                "a positive observation" if positive_observations == 1
                else "some positive observations" if positive_observations == 2
                else "several positive observations"
            )
            introduction += (
                f" While the assessment noted {positive} relating to password "
                f"security, {recovery}."
            )
        else:
            introduction += f" The assessment demonstrated that {recovery}."
    else:
        introduction += (
            " No plaintext passwords were recovered during the campaign. "
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

    # Count unique pairs with matching recovered passwords or NTLM hashes.
    similar_account_reuse_count = (
        results["similar_account_reuse"]["count"]
    )

    findings = []
    if has_privileged:
        findings.append((("DOMAIN-ADMIN-001", "PRIV-ACCOUNT-001"),
            "Privileged account credentials were recovered, potentially "
            "providing access to critical systems and sensitive information."
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
                ", potentially undermining separation between accounts "
                "with different roles"
            )
        findings.append((("PWD-REUSE-001", "PWD-REUSE-002", "PWD-REUSE-003"), finding + "."))

    breached = bool(results.get("hibp", {}).get("count"))
    if breached and weaknesses:
        findings.append((("PWD-BREACH-001", "PWD-PATTERN-001", "PWD-PATTERN-002",
                          "PWD-PATTERN-003", "PWD-PATTERN-004", "PWD-PATTERN-005"),
            "The assessment found passwords matching known breach data and "
            "passwords with predictable patterns, potentially making affected "
            "accounts easier to compromise."
        ))
    elif breached:
        findings.append((("PWD-BREACH-001",),
            "Some passwords matched known breach data, potentially making "
            "affected accounts easier to compromise."
        ))
    elif weaknesses:
        findings.append((("PWD-PATTERN-001", "PWD-PATTERN-002", "PWD-PATTERN-003",
                          "PWD-PATTERN-004", "PWD-PATTERN-005"),
            "Some recovered passwords followed predictable patterns, potentially "
            "making affected accounts easier to compromise."
        ))

    if failure_count:
        findings.append((("PWD-POLICY-001",),
            "Some recovered passwords fell below the domain's configured "
            "minimum length, potentially making them easier to guess or crack."
        ))

    if findings:
        findings.sort(key=lambda item: finding_priority(findings_data, item[0]))
        summary.append(
            "The assessment also highlighted weaknesses that could increase "
            "the risk of credential compromise. "
            + " ".join(text for _, text in findings)
        )

    #---------------------------------------------------------------------------
    # CONCLUSION
    #---------------------------------------------------------------------------
    severities = [
        severity for severity in ("critical", "high", "medium", "low")
        if any(finding["severity"] == severity for finding in findings_data)
    ]
    if severities:
        conclusion = (
            f"Overall, prioritise the {severities[0]}-severity findings"
        )
        if len(severities) > 1:
            remaining = natural_join([f"{severity}-severity" for severity in severities[1:]])
            conclusion += f", followed by {remaining} findings"
        conclusion += ", taking account of affected accounts and business context."
        if has_privileged or lm_admin_count:
            conclusion += (
                " Reset affected privileged passwords promptly and verify that "
                "remediation is effective."
            )
        else:
            conclusion += (
                " Track remediation and reassess affected controls to confirm "
                "that weaknesses have been addressed."
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