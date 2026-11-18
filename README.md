# Password-Audit

## Overview

`password-audit` is a modular Active Directory password auditing framework that combines dataset organisation, password recovery campaigns, and password analysis into a single toolkit.

It combines and extends the functionality of the following, now deprecated and deleted, standalone projects:

* `ntds-organiser`: Parses and enriches Active Directory hash datasets.
* `hashcat-scheduler`: Executes and tracks Hashcat recovery campaigns.
* `password-analyser`: Analyses recovered passwords and generates assessment reports.

📖 **Documentation:** https://cspanias.github.io/password-audit/

## Key Features

* End-to-end password auditing workflow (`audit`)
* NTDS and BloodHound dataset processing (`organise`)
* Advanced standalone Hashcat campaign execution (`crack`)
* LM password recovery support and candidate generation (`lm`)
* Rich-formatted CLI help, analysis progress, summary tables, and an offline HTML dashboard
* Markdown, JSON, YAML, SARIF, and HTML report exports
* Experimental campaign statistics and duration estimation (`crack`)

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

The recommended workflow is `audit`, which automatically orchestrates dataset
organisation, password recovery, password mapping, and report generation:

```bash
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign config.json \
    --campaign-name internal-audit
```

Company-specific password analysis is stronger with a curated wordlist. You
can optionally create `./company-words.txt` with around 10–20 terms tailored
to the company; `audit` adds it to the generated domain/account terms and
reminds you if it appears unchanged since the previous run.

The standalone commands below remain available for advanced or partial runs.
For ordinary assessments, prefer `audit`.

## Advanced partial workflow

The end-to-end command runs these stages automatically. Run modules
independently only when you need to repeat or troubleshoot part of the process:

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
    +--> password-audit/company-words.txt (basic generated terms)
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
    +--> password-audit-report.md
    +--> password-audit-findings.json
```

For detailed examples and module-specific documentation, see:

📖 https://cspanias.github.io/password-audit/