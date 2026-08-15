# Password-Audit

## Overview

`password-audit` is a modular Active Directory password auditing framework that combines dataset organisation, password recovery campaigns, and password analysis into a single toolkit.

It combines and extends the functionality of the following standalone projects:

* [`ntds-organiser`](https://github.com/CSpanias/ntds-organiser): Parses and enriches Active Directory hash datasets.
* [`hashcat-scheduler`](https://github.com/CSpanias/hashcat-scheduler): Executes and tracks Hashcat recovery campaigns.
* [`password-analyser`](https://github.com/CSpanias/password-analyser): Analyses recovered passwords and generates assessment reports.

📖 **Documentation:** https://cspanias.github.io/password-audit/

## Key Features

* End-to-end password auditing workflow (`audit`)
* NTDS and BloodHound dataset processing (`organise`)
* Hashcat campaign execution and tracking (`crack`)
* LM password recovery support and candidate generation (`lm`)
* Password analysis and report generation (`analyse`)
* Campaign statistics and duration estimation (`crack`)

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

## Quick Start

The recommended workflow is the `audit` module, which automatically orchestrates dataset organisation, password recovery, password mapping, and report generation:

```bash
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign config.json \
    --campaign-name internal-audit
```

## Typical Workflow

A password audit using `password-audit` consists of the following stages:

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
Map recovered NTLM passwords back to user accounts (password-audit organise)
    |
    +--> mapped-ntlm-passwords.txt
    |
    v
Analyse the results & generate the report (password-audit analyse)
    |
    v
    +--> report.md
```

For detailed examples and module-specific documentation, see:

📖 https://cspanias.github.io/password-audit/