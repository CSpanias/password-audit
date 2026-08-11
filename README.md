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

#### Usage

```bash
password-audit organise -n company.ntds

password-audit organise \
    -n company.ntds \
    -b bloodhound.zip \
    -p hashcat.potfile
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
