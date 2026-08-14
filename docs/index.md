# Documentation

!!! tip
    The `audit` module performs the end-to-end process without the invidual use of the `crack` and `analyse` modules.

[Password-Audit](https://github.com/CSpanias/password-audit) is a modular Active Directory (AD) password auditing framework that combines dataset organisation, password recovery campaigns, and password analysis into a single toolkit.

It is a merge and subsequent improvement of the following standalone Proof of Concept (PoC) scripts:

* [`ntds-organiser`](https://github.com/CSpanias/ntds-organiser) &rarr; Parses and enriches AD hash datasets.
* [`hashcat-scheduler`](https://github.com/CSpanias/hashcat-scheduler) &rarr; Executes and tracks Hashcat recovery campaigns.
* [`password-analyser`](https://github.com/CSpanias/password-analyser) &rarr; Analyses recovered passwords and generates assessment reports.

The core ideas behind each PoC can be found out on the associated articles:

* [Password Audits Part 2: Hash Organisation](https://mollysec.com/posts/password-audits-part-2/)
* [Password Audits Part 3: Cracking Hashes](https://mollysec.com/posts/password-audits-part-3/)
* [Password Audits Part 4: Analysing Results](https://mollysec.com/posts/password-audits-part-4/)

The implementation was done with the help of Microsoft Copilot (Basic) (19.2608.34011.0).

## Getting Started

* [Installation](installation.md) &rarr; How to install `password-audit`.
* [Organise](organise.md) &rarr; How to parse NTDS, [BloodHound](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart), and [`hashcat`](https://github.com/hashcat/hashcat) artefacts.
* [Crack](crack.md) &rarr; How to execute password recovery campaigns.
* [Analyse](analyse.md) &rarr; How to analyse the final dataset and generate the report.
* [Development](development.md) &rarr; How to contribute and project structure information.

## Workflow

### Overview

The high-level process of a password audit with `password-audit` (!) looks like this:

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
Map recovered passwords back to users (password-audit organise)
    |
    +--> mapped-ntlm-passwords.txt
    |
    v
Analyse the results (password-audit analyse)
    |
    v
    +--> report.md
```

### Quick Start

The fastest way to execute a complete password audit:

```bash
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign config.json \
    --campaign-name internal-audit
```

### End-to-End Example

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

Recover passwords using the defined configuration:

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
    --potfile hashcat.potfile
```

Analyse the dataset and generate the audit report:

```bash
password-audit analyse \
    --mapped-passwords ntds-organiser/mapped-ntlm-passwords.txt
```