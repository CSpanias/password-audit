# Privileged Account Passwords

Identifies recovered passwords associated with Domain Admins (DAs) and members
of selected privileged groups.

## What it checks

Password Audit reports recovered DA credentials separately from recovered
credentials belonging to the selected privileged groups:

- DAs
- Enterprise Admins
- Schema Admins
- Administrators
- DNSAdmins
- Account Operators
- Backup Operators
- Server Operators
- Cert Publishers
- Exchange Windows Permissions

## How it works

The organiser reads group and user objects from BloodHound, traverses nested
memberships, and includes primary-group membership. It matches identified users
to enabled, unfiltered NTDS accounts using account names and RIDs within the
source domain SID, regardless of NTDS prefix. Analysis compares those
identities with recovered passwords.

The separate DA check uses the BloodHound-derived DA list and compares account
names without domain prefixes. See [Organise](../organise.md) for the
domain-matching and confirmation process.

## Why it matters

Privileged accounts can provide extensive access to directory services and
systems. Recovery of a password associated with such an account can therefore
have a greater impact than recovery of an ordinary user's password.

## Interpreting results

The broader privileged finding includes DAs, so the two findings overlap. An
account in multiple selected groups is counted once in that finding. The groups
represent a defined subset of privileged access, not all administrative rights
or attack paths.

Missing group objects, unresolved members, or ambiguous account matches can
make coverage incomplete. DA name matching also ignores domain prefixes, so
verify individual identities where names are shared across domains. An
unrecovered password does not establish that the account is safe.

## Findings

| Finding ID | Title |
| --- | --- |
| DOMAIN-ADMIN-001 | Recovered Domain Administrator Passwords |
| PRIV-ACCOUNT-001 | Recovered Privileged Account Passwords |

## References

- [Microsoft: privileged access model](https://learn.microsoft.com/security/privileged-access-workstations/privileged-access-access-model)
- [Microsoft: Active Directory security groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)
