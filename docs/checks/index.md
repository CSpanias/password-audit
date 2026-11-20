# Checks

Password Audit analyses organised Active Directory password hashes and
recovered credentials. These pages explain what each check looks for, how it
works, why it matters, and how to interpret its results.

Checks run as part of [`audit`](../audit.md) or [`analyse`](../analyse.md);
they are not separate commands. Which results are available depends on the
input datasets.

| Area | Checks |
| --- | --- |
| Privileged and legacy credentials | [Privileged accounts](privileged-accounts.md), [LM hashes](lm-hashes.md) |
| Password policy | [Password length](password-length.md) |
| Reuse | [Recovered passwords](password-reuse.md), [NTLM hashes](ntlm-hash-reuse.md), [similarly named accounts](similar-accounts.md) |
| Predictable patterns | [Username-derived](username-passwords.md), [organisation-related](organisation-passwords.md), [common terms](common-passwords.md), [date-related](date-passwords.md), [keyboard patterns](keyboard-patterns.md) |
| Statistics | [Password statistics](password-statistics.md) |

## Understanding the scope

Most checks use **recovered plaintext passwords**. Their results describe
the recovered subset, not every account or password in the environment.
Passwords not recovered during a campaign are not necessarily strong.
Recovery depends on the campaign, wordlists, rules, hardware, and time
available.

NTLM hash reuse and LM hash presence can be assessed without recovering
passwords. The organiser normally limits these datasets to enabled user
accounts after exclusions; standalone analysis depends on the files supplied.
Machine accounts and disabled accounts are not included in the organiser's
enabled-user datasets.

Privileged-account results also depend on BloodHound coverage and reliable
matching to NTDS accounts. Missing or incomplete membership data can leave
affected accounts unidentified. Read each check's limitations before drawing
conclusions from an absence of findings.

Use the [Analyse guide](../analyse.md) for inputs and report generation, or
the [Audit guide](../audit.md) for the end-to-end workflow.
