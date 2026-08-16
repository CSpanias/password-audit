# Documentation

[Password-Audit](https://github.com/CSpanias/password-audit) is a modular Active Directory password auditing framework that combines dataset organisation, password recovery campaigns, and password analysis into a single toolkit.

It combines and extends the functionality of the following standalone projects:

* [`ntds-organiser`](https://github.com/CSpanias/ntds-organiser) parses and enriches AD hash datasets.
* [`hashcat-scheduler`](https://github.com/CSpanias/hashcat-scheduler) executes and tracks Hashcat recovery campaigns.
* [`password-analyser`](https://github.com/CSpanias/password-analyser) analyses recovered passwords and generates assessment reports.

The core ideas behind each script are discussed in the following articles:

* [Password Audits Part 2: Hash Organisation](https://mollysec.com/posts/password-audits-part-2/)
* [Password Audits Part 3: Cracking Hashes](https://mollysec.com/posts/password-audits-part-3/)
* [Password Audits Part 4: Analysing Results](https://mollysec.com/posts/password-audits-part-4/)

## Getting Started

* [Installation](installation.md) → Install Password Audit
* [Audit](audit.md) → End-to-end password auditing workflow
* [Organise](organise.md) → Parse NTDS and BloodHound datasets
* [Crack](crack.md) → Execute password recovery campaigns
* [LM](lm.md) → Process recovered LM passwords
* [Analyse](analyse.md) → Generate audit reports
* [Development](development.md) → Project structure and contribution guide

## Quick Start

The most efficient way to execute a complete password audit is via the use of the (aptly named!) [`audit`](audit.md) module:

!!! tip
    Example configuration files for both [NTLM](https://github.com/CSpanias/password-audit/blob/main/example-ntlm-config.json) and [LM](https://github.com/CSpanias/password-audit/blob/main/example-lm-config.json) can be found on the GitHub root directory.

```bash
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign config.json \
    --campaign-name internal-audit
```

## Workflow Diagram

The high-level process of what's happening behind the scenes looks like this:

!!! info
    `password-audit` can also process, analyse, and include LM-related findings in the report (see [LM](lm.md)).

```markdown
Extract NTDS (secretsdump) and collect BloodHound data (rusthound-ce)
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
Analyse the results (password-audit analyse)
    |
    v
    +--> report.md
```

## Manual Workflow

!!! note
    This demonstrates the underlying workflow used by the standalone modules. In most cases, the `audit` module should be preferred as it performs all of the steps below automatically.

Extract NTDS ([`secretsdump.py`](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)) and BloodHound data ([`rusthound-ce`](https://github.com/g0h4n/RustHound-CE)):

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
    -i <dc-ip> \
    -z
```

Process the generated `.ntds` and `.zip` files:

```bash
password-audit organise \
    --ntds company.ntds \
    --bloodhound bloodhound.zip
```

Recover passwords using the predefined configuration:

```bash
password-audit crack run \
    --campaign config.json \
    --hashes ntds-organiser/ntlm-hashes.txt \
    --campaign-name internal-audit
```

Map recovered passwords back to user accounts:

```bash
password-audit organise \
    --ntds company.ntds \
    --potfile hashcat.potfile \
    --bloodhound bloodhound.zip
```

Analyse the dataset and generate the audit report:

```bash
password-audit analyse \
    --mapped-passwords ntds-organiser/mapped-ntlm-passwords.txt
```