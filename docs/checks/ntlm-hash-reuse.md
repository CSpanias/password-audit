# NTLM Hash Reuse

Identifies matching NTLM hashes across enabled user accounts, including
passwords that have not been recovered.

## What it checks

Password Audit groups accounts that have the same NTLM hash and highlights
known members of selected privileged groups. It uses the organiser's
`ntds-users-clean.txt` dataset, which contains enabled users after exclusions.

## How it works

NTLM hashing is deterministic: the same password produces the same NTLM
hash. The check compares hash values and groups those shared by more than
one account. It does not need the plaintext passwords. Hashes in report
examples are masked, while the finding lists affected account groups without
full hashes or passwords. Examples involving selected privileged accounts
identify their groups separately from other accounts sharing the hash.

## Why it matters

Matching hashes can identify shared credentials even when cracking did not
recover the passwords. Reuse involving privileged accounts deserves particular
attention because it can weaken the separation of privileged access.

## Interpreting results

Matching hashes are strong evidence of reuse, although distinct passwords can
theoretically produce the same hash. They do not reveal the password itself
or show reuse outside the supplied NTDS dataset.

Privileged context depends on the collected group data and reliable account
matching. Accounts not identified as members of the selected groups are not
necessarily unprivileged. Results can overlap with
[recovered-password reuse](password-reuse.md); do not add their counts.
If the organised NTDS user records are not supplied, the report marks this
check as unavailable.

## Findings

| Finding ID | Title |
| --- | --- |
| PWD-REUSE-003 | Password Reuse Identified from NTLM Hashes |

## References

- [Microsoft: NTLM overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview)
- [NCSC: password policy guidance](https://www.ncsc.gov.uk/collection/passwords/updating-your-approach)
