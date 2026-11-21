# Password Length Compliance

Compares recovered passwords with the configured minimum password length.

## What it checks

Password Audit counts recovered passwords shorter than the minimum length in
the supplied domain policy and summarises the lengths observed. Passwords
equal to or longer than the configured minimum pass this specific check.

## How it works

Analysis reads `Minimum Password Length` from the policy input and compares
it with the length of each recovered plaintext password. In the audit workflow,
the organiser obtains the domain policy from BloodHound data.

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

If the minimum length cannot be determined from the policy input, analysis
stops rather than treating the check as passed.

## Findings

| Finding ID | Title |
| --- | --- |
| PWD-POLICY-001 | Non-Compliant Passwords |

## References

- [Microsoft: password policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy)
- [NCSC: password policy guidance](https://www.ncsc.gov.uk/collection/passwords/updating-your-approach)
