# Password-Audit

A Python-based framework designed to streamline Active Directory password audits.

`password-audit` combines NTDS processing, password recovery analysis, and future cracking workflows into a single modular toolkit.

The framework currently includes:

* **NTDS Organiser**: Parses and enriches Active Directory hash datasets.
* **Password Analyser**: Analyses recovered passwords and generates assessment reports.

## Installation

### UV (Recommended)

> Recommended for most users who simply want to use the framework.

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install password-audit
uv tool install git+https://github.com/CSpanias/password-audit

# Verify installation
password-audit -h

# Update
uv tool upgrade password-audit
```

### Development Installation

> Recommended for contributors and anyone modifying the source code.
>
> The editable installation (`-e`) links the installed package directly to the working directory, allowing code changes to take effect immediately without reinstalling the package.

```bash
# Clone repository
git clone https://github.com/CSpanias/password-audit /opt/password-audit

# Move into the directory
cd /opt/password-audit

# Create virtual environment
uv venv

# Install editable package
uv pip install -e .

# Verify installation
password-audit -h
```

## Components

### NTDS Organiser

Automates post-processing of `secretsdump.py` output and combines NTDS data with BloodHound and Hashcat artefacts.

#### Features

* Parse NTDS dumps
* Separate enabled and disabled accounts
* Identify machine accounts
* Extract NTLM hashes
* Detect LM hashes
* Parse BloodHound ZIP exports
* Extract Domain Administrators
* Extract domain password policy
* Generate organisation-specific wordlists
* Map recovered passwords from Hashcat potfiles
* Generate LM candidate datasets

#### Typical Workflow

A password audit using password-audit typically follows four stages:

```text
NTDS Dump
    |
    v
password-audit organise
    |
    +--> ntlm-hashes.txt
    +--> domain-admins.txt
    +--> company-words.txt
    +--> domain-policy.txt
    +--> enabled-users.txt
    |
    v
Hashcat
    |
    v
hashcat.potfile
    |
    v
password-audit organise --potfile
    |
    v
mapped-ntlm-passwords.txt
    |
    v
password-audit analyse
    |
    v
report.md
```
### End-to-End Example

1. Extract NTDS.dit using [`secretsdump.py`](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py):

```bash
secretsdump.py <domain>/<da-account>:<da-password>@<dc-ip> -user-status -just-dc-ntlm -outputfile <domain>
```

2. Extract BloodHound data (e.g. using [`rusthound-ce`](https://github.com/g0h4n/RustHound-CE)):

```bash
rusthound-ce -u <user> -p <pass> -d <domain> -i <dc-ip> -z
```

3. Process the NTDS dump and enrich the results with BloodHound data:

```bash
password-audit organise -n company.ntds -b bloodhound.zip
```

This generates datasets including:

```bash
ntlm-hashes.txt
domain-admins.txt
domain-policy.txt
company-words.txt
enabled-users.txt
```

4. Use [`hashcat`](https://github.com/hashcat/hashcat) to recover passwords from the exported NTLM hashes:

```bash
hashcat -m1000 ntds-organiser/ntlm-hashes.txt wordlist.txt -r rule.rule -O -d 1
```

Recovered passwords are stored automatically in:

```bash
hashcat.potfile
```

3. Map Recovered Passwords

Map recovered passwords back to user accounts.

```bash
password-audit organise -n company.ntds -b bloodhound.zip -p hashcat.potfile
```

This generates:

```bash
mapped-ntlm-passwords.txt
```

containing:

```bash
user1:Password123
user2:Summer2025!
user3:Welcome1
```

4. Analyse the dataset and generate the audit report:

```bash
password-audit analyse -M ntds-organiser/mapped-ntlm-passwords.txt
```

The required datasets are loaded automatically from the `./ntds-organiser` directory:

```bash
domain-admins.txt
domain-policy.txt
company-words.txt
enabled-users.txt
```

---

### Password Analyser

Analyses recovered passwords and generates Markdown reporting content suitable for Active Directory password assessments.

#### Features

* Password recovery statistics
* Crack-rate analysis
* Privileged account identification
* Password reuse detection
* Username-derived passwords
* Organisation-related passwords
* Common password analysis
* Date-based password analysis
* Keyboard-walk analysis
* Password length analysis
* Character-class analysis
* Executive summary generation
* Technical commentary generation
* Remediation guidance generation

#### Usage

```bash
password-audit analysis \
    -M ntds-organiser/mapped-ntlm-passwords.txt
```

Example output:

```bash
[+] Markdown report written to: report.md
```

## Workflow

```text
NTDS Dump
    |
    v
NTDS Organiser
    |
    +--> NTLM Hashes
    +--> Domain Admins
    +--> Domain Policy
    +--> Company Words
    +--> Mapped Passwords
    |
    v
Password Analyser
    |
    v
Markdown Report
```

## Command Reference

### Show Help

```bash
password-audit -h
```

### NTDS Organiser Help

```bash
password-audit organise -h
```

### Password Analyser Help

```bash
password-audit analysis -h
```

## Requirements

### Core

* Python 3.10+

### Optional

* BloodHound ZIP exports
* Hashcat potfiles
* NTDS data obtained during authorised security assessments

## Roadmap

* Hashcat Scheduler integration
* Additional privileged group analysis
* Additional report formats
* Supporting audit utilities
