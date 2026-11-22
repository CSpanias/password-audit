# Similarly Named Account Reuse

Identifies shared credentials used by similarly named accounts.

## What it checks

Password Audit looks for pairs of similarly named accounts sharing a
recovered password or matching NTLM hash. For example, an account and a
similarly named administrative account may use the same credentials.

## How it works

The check derives a base name from each username by ignoring the domain
prefix, removing common administrative markers such as `_adm` and `_da`,
and removing trailing digits. It compares accounts with the same base name
and reports pairs whose recovered passwords match exactly or whose NTLM
hashes match. A pair found by both methods is counted once.

## Why it matters

If a standard and privileged account share a password, compromise of the
standard account may also expose the privileged credential and undermine the
intended separation between them.

## Interpreting results

Similar names are a heuristic: they do not prove that accounts belong to the
same person or that either account is privileged. Unrelated accounts,
including accounts in different domains, can have the same derived base name.
Review the identities and their roles before drawing conclusions.

Hash-based comparisons require organised NTDS user records and include enabled,
unfiltered accounts, even when their passwords were not recovered. If these
records are unavailable, only recovered passwords are compared. Matching
hashes are strong evidence of reuse, although distinct passwords can
theoretically produce the same hash. These pairs can also appear in the
[general password reuse](password-reuse.md) and
[NTLM hash reuse](ntlm-hash-reuse.md) results; do not add their counts.

## Findings

| Finding ID | Title |
| --- | --- |
| PWD-REUSE-002 | Shared Passwords |

## References

- [Microsoft: privileged access model](https://learn.microsoft.com/security/privileged-access-workstations/privileged-access-access-model)
- [NCSC: password policy guidance](https://www.ncsc.gov.uk/collection/passwords/updating-your-approach)
