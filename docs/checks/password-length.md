# Password Length Compliance

Compares recovered passwords with the configured minimum password length.

## What it checks

Password Audit counts recovered passwords shorter than the minimum length in
the supplied domain policy and summarises the lengths observed. Passwords
equal to or longer than the configured minimum pass this specific check.

## How it works

Analysis reads `Minimum Password Length` from the policy input and compares
it with the length of each recovered plaintext password. In the audit workflow,
the organiser obtains the domain policy from BloodHound data. The report
includes up to five example accounts and their masked passwords.

## Why it matters

Short passwords generally offer a smaller search space for offline guessing.
Passwords below the applicable minimum may indicate older credentials,
policy changes, or an account subject to different policy settings.

## Interpreting results

This checks **length only** among recovered passwords. It does not evaluate
password history, age, complexity enforcement, lockout settings, or whether
every account complied with its effective policy. Fine-grained password
policies may apply different requirements to individual accounts, and an
existing password may predate a policy change. Review those factors before
classifying an account as actually violating its effective policy.

If the minimum length cannot be determined, the audit workflow asks before
continuing without this check and identifies it as unavailable in the report.
Non-interactive audits stop instead. Standalone `analyse` requires a usable
policy and stops when the minimum length is unavailable.

## Findings

| Finding ID | Title |
| --- | --- |
| PWD-POLICY-001 | Passwords Below Domain Minimum |

## References

- [Microsoft: password policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy)
- [NCSC: password policy guidance](https://www.ncsc.gov.uk/collection/passwords/updating-your-approach)
- [NIST SP 800-63B: password length](https://pages.nist.gov/800-63-4/sp800-63b.html#length)
