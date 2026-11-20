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
Password Audit assumes the NTDS dump comes from one domain. When BloodHound
identifies one source domain, its SID is used automatically to match account
names and RIDs; different NTDS prefixes do not prevent a match. BloodHound
objects from other domains are not treated as NTDS accounts from the source
domain.

If the export contains multiple domains, an interactive run asks which one
the NTDS dump belongs to. Confirm only the domain you know is the source.
Without a confirmed source, including in non-interactive runs, privileged
account matches are omitted and coverage is incomplete. Missing or inconsistent
domain data likewise prevents source-domain matching.

The selected source is recorded in `privileged-users.json`; a user-confirmed
source is also noted in the report. Ambiguous account matches, missing group
members, and missing membership data are reported as incomplete.
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