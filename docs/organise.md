# Organise

The `organise` module processes Active Directory datasets (NTDS dumps and BloodHound exports) and generates the artefacts required for password auditing and analysis. Recovered NTLM passwords can also be mapped to user accounts using a Hashcat potfile.

It performs two primary functions:

1. Parses NTDS and BloodHound data and generate audit artefacts
2. Maps recovered NTLM passwords back to user accounts using a Hashcat potfile

```bash
$ password-audit organise -h
usage: main.py organise [-h] -N NTDS -B BLOODHOUND [-F FILTER] [-O OUTPUT] [-P POTFILE]

Parse NTDS, BloodHound, and Hashcat datasets and generate analysis artefacts.

options:
  -h, --help            show this help message and exit

required arguments:
  -N, --ntds NTDS       Secretsdump NTDS file
  -B, --bloodhound BLOODHOUND
                        BloodHound ZIP export

optional arguments:
  -F, --filter FILTER   Comma-separated usernames to exclude (default: None)
  -O, --output OUTPUT   Output directory (default: ntds-organiser)
  -P, --potfile POTFILE
                        Hashcat potfile containing recovered passwords (default: None)

Example:

    password-audit organise \
        -N company.ntds \
        -B bloodhound.zip
```

## Domain Data Parsing

After collecting the NTDS dump and BloodHound data, the first step is to parse both datasets and extract the information required for password auditing:

```bash
# Process NTDS and BloodHound data
$ password-audit organise \
    --ntds company.ntds \
    --bloodhound bloodhound.zip

[*] NTDS Organiser

    Enabled Accounts    : 481
    Disabled Accounts   : 42
    User Accounts       : 273
    Machine Accounts    : 208
    NTLM Hashes         : 164
    LM Hashes           : 88
    Company Words       : 3
    Domain Admins       : 23

    Output Directory    : ntds-organiser 
```

The following artefacts are generated:

- `company-words.txt` containing organisation-specific words extracted from account names and group names
- `domain-admins.txt` containing Domain Administrator accounts identified from BloodHound data
- `domain-policy.txt` containing the domain password policy
- `enabled-users.txt` containing enabled user accounts in `domain\username` format
- `ntlm-hashes.txt` containing extracted NTLM hashes for password auditing
- `ntds-users-clean.txt` containing enabled user accounts in SecretsDump format (`domain\username:rid:lm:nt:::`)

Hidden datasets are also generated for internal processing and troubleshooting:

- `.ntds-enabled.txt` containing all enabled accounts
- `.ntds-disabled.txt` containing all disabled accounts
- `.ntds-machines.txt` containing machine accounts

The following datasets are generated only when applicable:

- `lm-hashes.txt` containing extracted LM hashes (only if LM hashes exist)
- `lm-users.txt` containing accounts associated with LM hashes (only if LM hashes exist)
- `mapped-ntlm-passwords.txt` containing recovered NTLM passwords mapped to user accounts (only when `-P` / `--potfile` is supplied)
- `.testing-accounts.txt` containing accounts matching the supplied filter (only when `-F` / `--filter` is used)

```bash
$ tree -a ntds-organiser
ntds-organiser
├── company-words.txt
├── domain-admins.txt
├── domain-policy.txt
├── enabled-users.txt
├── lm-hashes.txt
├── lm-users.txt
├── .ntds-disabled.txt
├── .ntds-enabled.txt
├── .ntds-machines.txt
├── ntds-users-clean.txt
└── ntlm-hashes.txt
```

## Password Mapping

Providing a Hashcat potfile allows `organise` to map recovered NTLM passwords back to user accounts:

```bash
$ password-audit organise \
    --ntds company.ntds \
    --potfile hashcat.potfile \
    --bloodhound bloodhound.zip

[*] NTDS Organiser

    Enabled Accounts    : 481
    Disabled Accounts   : 42
    User Accounts       : 273
    Machine Accounts    : 208
    NTLM Hashes         : 164
    LM Hashes           : 88
    Domain Admins       : 23
    Company Words       : 3
    Mapped Passwords    : 134

    Output Directory    : ntds-organiser
```

This generates an additional dataset containing recovered NTLM passwords mapped to their corresponding user accounts:

```bash
$ ls ntds-organiser/mapped-ntlm-passwords.txt
ntds-organiser/mapped-ntlm-passwords.txt

$ head -1 ntds-organiser/mapped-ntlm-passwords.txt
domain.local\mike:Welcome123!
```