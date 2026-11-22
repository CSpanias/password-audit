# Recovered Password Reuse

Identifies identical passwords recovered for multiple accounts.

## What it checks

Password Audit counts recovered plaintext passwords that appear more than
once and summarises the affected accounts and most frequently seen values.

## How it works

The check compares recovered password strings exactly and groups repeated
values. Passwords are case-sensitive for this comparison. The report masks up
to five example passwords and shows up to five associated accounts for each,
with the number of additional accounts.

## Why it matters

When multiple accounts share a password, compromise of one credential can
increase exposure across the other accounts. Shared credentials can also
weaken separation between different roles.

## Interpreting results

This check is limited to recovered passwords and does not establish reuse
outside the supplied dataset or across external services. It can overlap with
[NTLM hash reuse](ntlm-hash-reuse.md) and
[similarly named account reuse](similar-accounts.md); their counts should not
be added together. The general reuse finding can include similarly named
accounts as well as unrelated accounts.

## Findings

| Finding ID | Title |
| --- | --- |
| PWD-REUSE-001 | Password Reuse |

## References

- [NCSC: password policy guidance](https://www.ncsc.gov.uk/collection/passwords/updating-your-approach)
- [NIST SP 800-63B: authentication and password guidance](https://pages.nist.gov/800-63-4/sp800-63b.html)
