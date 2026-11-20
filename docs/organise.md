# Organise datasets

The `organise` command parses a SecretsDump NTDS export and a BloodHound ZIP
export, then writes the supporting datasets used by the cracking and analysis
workflows. It can also use an existing Hashcat potfile to map recovered NTLM
passwords to accounts.

## Basic usage

```bash
password-audit organise \
    --ntds company.ntds \
    --bloodhound bloodhound.zip
```

By default, output files are written to `password-audit/`; use `--output` to
choose another directory.

## Options

| Option | Purpose | Default |
| --- | --- | --- |
| `-N`, `--ntds` | SecretsDump NTDS export | Required |
| `-B`, `--bloodhound` | BloodHound ZIP export | Required |
| `-F`, `--filter` | Comma-separated usernames to exclude | None |
| `-O`, `--output` | Output directory | `password-audit` |
| `-P`, `--potfile` | Hashcat potfile for NTLM password mapping | None |

Use `password-audit organise --help` for the installed version's full help.

## Generated files

| File | Contents |
| --- | --- |
| `enabled-users.txt` | Enabled user accounts used by analysis. |
| `ntlm-hashes.txt` | NTLM hashes extracted from the NTDS dataset. |
| `ntds-users-clean.txt` | Enabled user records after exclusions, used for NTLM hash reuse analysis. |
| `domain-admins.txt` | Domain Administrator accounts identified from BloodHound data, when available. |
| `privileged-users.json` | Enabled NTDS accounts in selected privileged groups, their group memberships, and coverage warnings. |
| `domain-policy.txt` | Password policy values extracted from BloodHound data, when available. |
| `company-words.txt` | Basic terms derived from domain/account data; not a realistic company vocabulary. |
| `lm-hashes.txt`, `lm-users.txt` | LM hashes and associated accounts, when present. |
| `mapped-ntlm-passwords.txt` | Recovered NTLM passwords mapped to accounts; written when a potfile is supplied and matches are found. |
| `.ntds-enabled.txt`, `.ntds-disabled.txt`, `.ntds-machines.txt` | Intermediate records used by the workflow. |
| `.testing-accounts.txt` | Accounts excluded by `--filter`, when any match. |

The output includes password hashes and may include recovered plaintext
passwords. Store it securely and restrict access to the assessment team.

Privileged membership includes nested groups and primary-group membership.
Accounts are matched to NTDS using the account name and RID, with domain
checks when a domain prefix is present. Ambiguous identities are omitted and
reported as incomplete coverage. The prefix must match the BloodHound DNS
domain or the suffix of that account's exported `userprincipalname`. Not all
collectors export the UPN. If those checks cannot resolve accounts and the
BloodHound data identifies a single domain, an interactive run asks whether
the NTDS dump belongs to that domain. Confirm only when you know this is true:
matching then uses the account name and RID within the confirmed domain SID.
The confirmation is recorded in `privileged-users.json` and the audit report.
Declining, non-interactive runs, ambiguous identities, and multi-domain or
unclear exports retain incomplete coverage where matches cannot be verified.
The JSON file contains account names and group memberships, but no passwords.

The generated `company-words.txt` is a basic seed and is regenerated when
organising data. For more realistic company-specific password analysis, keep a
separate curated `./company-words.txt` file with roughly 10–20 relevant terms;
the `audit` workflow adds it to the generated terms when present.

## Map recovered NTLM passwords

After a Hashcat campaign, supply its potfile to map recovered passwords back to
the NTDS accounts:

```bash
password-audit organise \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --potfile /path/to/hashcat.potfile
```

The mapped dataset can then be analysed with [`analyse`](analyse.md#usage).