# Organise

The `password-audit organise` module processes Active Directory (AD) datasets (NTDS dump, BloodHound ZIP) and generates artefacts used during password audits.

## Usage

The `organise` module is used for two things:

1. Parsing the NTDS and BloodHound files
2. Map recovered passwords back to user accounts after password recovery

```bash
$ password-audit organise -h
usage: password-audit organise [-h] -N NTDS [-O OUTPUT] [-F FILTER] [-B BLOODHOUND] [-P POTFILE]

options:
  -h, --help            show this help message and exit
  -N, --ntds NTDS       Secretsdump NTDS file
  -O, --output OUTPUT   Output directory (default: ntds-organiser)
  -F, --filter FILTER   Comma-separated testing account filters (default: None)
  -B, --bloodhound BLOODHOUND
                        BloodHound ZIP export (default: None)
  -P, --potfile POTFILE
                        Hashcat potfile containing recovered passwords (default: None)
```

### NTDS and BloodHound Parsing

After extracting the NTDS database and collecting BloodHound data, the first step of the process is to parse them and extract the required information:

> The `--filter` option can be used to exclude known testing, administrative, or service accounts from analysis.

```bash
# Process NTDS and BloodHound data
password-audit organise \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --filter testing_acc1,testing_acc2
```

This will produce the following artefacts:

```bash
$ tree -a ntds-organiser
ntds-organiser
├── company-words.txt # Organisation-specific wordlist
├── domain-admins.txt # Domain Administrator accounts
├── domain-policy.txt # Domain password policy
├── enabled-users.txt # Enabled user accounts (domain\username)
├── .ntds-disabled.txt # All disabled accounts
├── .ntds-enabled.txt # All enabled accounts
├── .ntds-machines.txt # Machine accounts
├── ntds-users-clean.txt # Enabled user accounts (domain\username:rid:lm:nt:::)
├── ntlm-hashes.txt # Extracted NTLM hashes
└── .testing-accounts.txt # Testing accounts (-f)
```

### Recovered Passwords Mapping

```bash
password-audit organise \
    --ntds company.ntds \
    --potfile hashcat.potfile
```

This will generate the final recovered password dataset by matching NTLM hashes in the NTDS file against entries found in the supplied Hashcat potfile:

```bash
$ ls ntds-organiser/mapped-ntlm-passwords.txt
ntds-organiser/mapped-ntlm-passwords.txt # Recovered passwords mapped to user accounts (domain\username:password)
```