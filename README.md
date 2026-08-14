# Password-Audit

## Overview

`password-audit` is a modular Python-based framework designed to streamline Active Directory password audits by combining dataset organisation, password recovery campaigns, and password analysis into a single toolkit.

The core components include:

* **NTDS Organiser**: Parses and enriches Active Directory hash datasets.
* **Password Cracker**: Executes and tracks Hashcat recovery campaigns.
* **Password Analyser**: Analyses recovered passwords and generates assessment reports.

📖 **Documentation:** https://cspanias.github.io/password-audit/

💡 **Future Ideas:** https://cspanias.github.io/password-audit/ideas/

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
> The editable installation (`-e`) allows local code changes to take effect immediately without reinstalling the package.

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

## Typical Workflow

A password audit using `password-audit` typically follows the following stages:

```markdown
Extract NTDS (secretsdump) and Collect BloodHound Data (rusthound-ce)
    |
    +--> domain.ntds
    +--> bloodhound.zip
    | 
    v
Parse NTDS and BloodHound data (password-audit organise)
    |
    +--> domain-admins.txt
    +--> company-words.txt
    +--> domain-policy.txt
    +--> enabled-users.txt
    +--> .ntds-disabled.txt
    +--> .ntds-enabled.txt
    +--> .ntds-machines.txt
    +--> ntds-users-clean.txt
    +--> ntlm-hashes.txt
    |
    v
Crack hashes (password-audit crack run)
    |
    +--> hashcat.potfile
    +--> campaign-results.json
    +--> loopback.txt
    |
    v
Map recovered passwords back to users (password-audit organise)
    |
    +--> mapped-ntlm-passwords.txt
    |
    v
Analyse the results & generate the report (password-audit analyse)
    |
    v
    +--> report.md
```

For a more detailed end-to-end example, see [End-to-End Example](https://cspanias.github.io/password-audit/#end-to-end-example).