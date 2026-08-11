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

### NTDS Organiser (`organiser`)

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

### Password Analyser (`analysis`)

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

## Typical Workflow

A password audit using `password-audit` typically follows four stages:

```markdown
NTDS Dump (secretsdump.py)
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
    +--> hashcat.potfile
    |
    v
password-audit organise -n ntds -p potfile
    |
    +--> mapped-ntlm-passwords.txt
    |
    v
password-audit analyse -M mapped-ntlm-passwords.txt
    |
    v
    +--> report.md
```

### End-to-End Example

1. Extract NTDS.dit using [`secretsdump.py`](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py):

```bash
secretsdump.py <domain>/<username>:<password>@<dc-ip> -user-status -just-dc-ntlm -outputfile <domain>
```

2. Extract BloodHound data (e.g. using [`rusthound-ce`](https://github.com/g0h4n/RustHound-CE)):

```bash
rusthound-ce -u <username> -p <password> -d <domain> -i <dc-ip> -z
```

3. Process the NTDS dump and BloodHound data:

```bash
password-audit organise -n company.ntds -b bloodhound.zip
```

4. Use [`hashcat`](https://github.com/hashcat/hashcat) to recover passwords from the exported NTLM hashes:

```bash
hashcat -m1000 ntds-organiser/ntlm-hashes.txt wordlist.txt -r rule.rule
```

5. Map recovered passwords back to user accounts:

```bash
password-audit organise -n company.ntds -p hashcat.potfile
```

6. Analyse the dataset and generate the audit report:

```bash
password-audit analyse -M ntds-organiser/mapped-ntlm-passwords.txt
```

---

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
