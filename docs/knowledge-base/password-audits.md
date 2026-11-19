# Password audits

A password audit assesses the strength and reuse of passwords in an
environment by analysing authorised password-hash datasets and recovered
credentials. The results can help prioritise improvements to password
policies, account practices, and privileged-account protection.

## Prerequisites

Agree the scope and obtain explicit authorisation before collecting or
analysing credentials. An internal Active Directory assessment typically
requires access to a domain controller and a Domain Administrator account
for collection. The exact permissions and access depend on the collection
method and environment; use appropriately authorised access.

The Password Audit workflow also requires an NTDS export, a BloodHound ZIP
export, Hashcat, a campaign configuration, and the wordlists and rules
referenced by that configuration. See the [audit guide](../audit.md) for
the tool's prerequisites.

## Workflow

1. **Extract** NTDS hashes and collect domain data. See
   [Password Audits Part 1](https://mollysec.com/posts/password-audits-part-1/).
2. **Organise** the extracted datasets for recovery and analysis. See
   [Password Audits Part 2](https://mollysec.com/posts/password-audits-part-2/)
   and [Organise datasets](../organise.md).
3. **Recover** passwords from the available hashes using an appropriate
   campaign. See
   [Password Audits Part 3](https://mollysec.com/posts/password-audits-part-3/),
   [Crack campaigns](../crack.md), and
   [Wordlists and rules](wordlists-and-rules.md).
4. **Analyse** the recovered credentials and report the results. See
   [Password Audits Part 4](https://mollysec.com/posts/password-audits-part-4/)
   and [Analyse](../analyse.md).

The recommended [`audit`](../audit.md) command orchestrates organisation,
recovery, mapping, and analysis after the data has been collected. The
[tools reference](tools.md) covers the tools used throughout the process.

## Handling sensitive data

NTDS exports, password hashes, potfiles, recovered passwords, and reports are
sensitive assessment data. Restrict access, protect them in transit and at
rest, and follow the engagement's retention and disposal requirements.
