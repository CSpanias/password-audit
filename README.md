# Password-Audit

A Python-based framework designed to streamline Active Directory (AD) password audits.

`password-audit` is a modular AD password auditing framework that combines dataset organisation, password recovery campaigns, and password analysis into a single toolkit.

The framework currently includes:

* **NTDS Organiser**: Parses and enriches Active Directory hash datasets.
* **Password Cracker**: Executes and tracks Hashcat recovery campaigns.
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

Automates post-processing of the NTDS dump, BloodHound data, and Hashcat artefacts.

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

### Password Cracker

Executes Hashcat recovery campaigns using configurable campaign definitions and tracks historical attack effectiveness.

* Multi-phase password recovery campaigns
* Loopback dictionary generation
* Campaign validation
* Campaign result tracking
* Historical campaign statistics
* Attack ROI analysis
* Campaign duration estimation
* Hashcat integration
* JSON-based campaign definitions

### Password Analyser

Analyses recovered passwords and generates Markdown report suitable for AD password audits.

* Statistics
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
* Report generation
    * Executive summary
    * Technical commentary
    * Remediation guidance

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

### End-to-End Example

1. Extract NTDS ([`secretsdump.py`](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)) and BloodHound data ([`rusthound-ce`](https://github.com/g0h4n/RustHound-CE)):

```bash
# NTDS dump
secretsdump.py \
    <domain>/<username>:<password>@<dc-ip> \
    -user-status \
    -just-dc-ntlm \
    -outputfile <domain>

# BloodHound data
rusthound-ce \
    -u <username> \
    -p <password> \
    -d <domain> \
    -i <dc-ip> -z
```

2. Process the generated `.ntds` and `.zip` files:

```bash
password-audit organise \
    -n company.ntds \
    -b bloodhound.zip
```

3. Recover passwords using the defined configuration:

```bash
password-audit crack run \
    -C campaign.json \
    -H ntds-organiser/ntlm-hashes.txt \
    -N internal-audit
```

4. Map recovered passwords back to user accounts:

```bash
password-audit organise \
    -n company.ntds \
    -p hashcat.potfile
```

5. Analyse the dataset and generate the audit report:

```bash
password-audit analyse \
    -M ntds-organiser/mapped-ntlm-passwords.txt
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

* Workflow automation 
* Historical campaign comparison reports 
* Advanced campaign effectiveness analytics 
* Additional privileged group analysis 
* Additional report formats 
* Supporting audit utilities
