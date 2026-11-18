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

By default, output files are written to `ntds-organiser/`. Use `--output` to
choose another directory.

## Options

| Option | Purpose | Default |
| --- | --- | --- |
| `-N`, `--ntds` | SecretsDump NTDS export | Required |
| `-B`, `--bloodhound` | BloodHound ZIP export | Required |
| `-F`, `--filter` | Comma-separated usernames to exclude | None |
| `-O`, `--output` | Output directory | `ntds-organiser` |
| `-P`, `--potfile` | Hashcat potfile for NTLM password mapping | None |

Use `password-audit organise --help` for the installed version's full help.

## Generated files

| File | Contents |
| --- | --- |
| `enabled-users.txt` | Enabled user accounts used by analysis. |
| `ntlm-hashes.txt` | NTLM hashes extracted from the NTDS dataset. |
| `ntds-users-clean.txt` | Normalized enabled-user records. |
| `domain-admins.txt` | Domain Administrator accounts identified from BloodHound data, when available. |
| `domain-policy.txt` | Password policy values extracted from BloodHound data, when available. |
| `company-words.txt` | Organisation-related terms derived from the available domain and account data. |
| `lm-hashes.txt`, `lm-users.txt` | LM hashes and associated accounts, when present. |
| `mapped-ntlm-passwords.txt` | Recovered NTLM passwords mapped to accounts; written when a potfile is supplied and matches are found. |
| `.ntds-enabled.txt`, `.ntds-disabled.txt`, `.ntds-machines.txt` | Intermediate records used by the workflow. |
| `.testing-accounts.txt` | Accounts excluded by `--filter`, when any match. |

The output includes password hashes and may include recovered plaintext
passwords. Store it securely and restrict access to the assessment team.

## Map recovered NTLM passwords

After a Hashcat campaign, supply its potfile to map recovered passwords back to
the NTDS accounts:

```bash
password-audit organise \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --potfile /path/to/hashcat.potfile
```

The mapped dataset can then be analysed with
[`analyse`](analyse.md#usage). The end-to-end [`audit`](audit.md) command
performs organisation and mapping automatically.
