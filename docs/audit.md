# Audit

## Overview

The `audit` module automates the [end-to-end process](index.md#end-to-end-example) process by orchestrating the `organise`, `crack`, and `analyse` modules.

It is intended as the primary workflow for most engagements and automates the full password auditing process from data parsing through to report generation.

```bash
$ password-audit audit -h
usage: password-audit audit [-h] -N NTDS -B BLOODHOUND -C CAMPAIGN -G CAMPAIGN_NAME [-F FILTER]
                     [-M MAPPED_PASSWORDS] [-A DOMAIN_ADMINS] [-P PASS_POLICY] [-W COMPANY_WORDS]
                     [-E ENABLED_USERS]

options:
  -h, --help            show this help message and exit

required arguments:
  -N, --ntds NTDS       Secretsdump NTDS file
  -B, --bloodhound BLOODHOUND
                        BloodHound ZIP export
  -C, --campaign CAMPAIGN
                        Campaign configuration file
  -G, --campaign-name CAMPAIGN_NAME
                        Campaign identifier

optional arguments:
  -F, --filter FILTER   Comma-separated usernames to exclude (default: None)
  -M, --mapped-passwords MAPPED_PASSWORDS
                        Recovered password dataset (default: ./ntds-organiser/mapped-ntlm-
                        passwords.txt)
  -A, --domain-admins DOMAIN_ADMINS
                        Domain Admin account list (default: ./ntds-organiser/domain-admins.txt)
  -P, --pass-policy PASS_POLICY
                        Domain password policy (default: ./ntds-organiser/domain-policy.txt)
  -W, --company-words COMPANY_WORDS
                        Organisation-related strings (default: ./ntds-organiser/company-words.txt)
  -E, --enabled-users ENABLED_USERS
                        Enabled user accounts list (default: ./ntds-organiser/enabled-users.txt)
```

## Usage

For the `audit` module, the following inputs are required:

* An NTDS dataset exported with SecretsDump
* Domain data exported from a BloodHound collector
* A campaign configuration file describing the cracking strategy

The campaign name identifies the assessment and is used when writing campaign history and output files. Meaningful names make it easier to distinguish between multiple engagements.

!!! note

    The audit workflow identifies and reports the presence of LM hashes. However, LM password recovery requires an additional `hashcat --show` step before recovered passwords can be mapped back to user accounts. See the [LM](lm.md) module for details.

```bash
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign config.json \
    --campaign-name internal-password-audit
```

This will sequentially run the `organise`, `crack`, and `analyse` modules and produce a Markdown-based report when completed:

1. Organising Data: Parses the NTDS dataset and extracts supporting artefacts.
2. Recovering Passwords: Executes the configured cracking campaign.
3. Mapping Passwords: Maps recovered hashes back to user accounts.
4. Analysing Passwords: Performs the dataset analysis and generates the report.

```bash
[*] Stage 1/4 - Organising Data
[*] Stage 2/4 - Recovering Passwords
[*] Stage 3/4 - Mapping Passwords
[*] Stage 4/4 - Analysing Passwords

[*] Audit Complete

    Report              : report.md
    Mapped Passwords    : ntds-organiser/mapped-ntlm-passwords.txt
    Recovered Passwords : 238
```

The workflow also generates the intermediate artefacts produced by the underlying modules, including:

* `ntds-organiser/mapped-ntlm-passwords.txt`
* `ntds-organiser/domain-admins.txt`
* `ntds-organiser/company-words.txt`
* `ntds-organiser/domain-policy.txt`
* `ntds-organiser/enabled-users.txt`
* `report.md`

If LM hashes are present and processed, additional LM-related artefacts may also be generated. See the [LM](lm.md) module for details.

By default, the audit workflow automatically uses artefacts generated during execution. The following inputs can be overridden when custom datasets are required:

* `--mapped-passwords`
* `--domain-admins`
* `--pass-policy`
* `--company-words`
* `--enabled-users`

For example, the default password policy can be overridden as follows:

```bash
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign config.json \
    --campaign-name internal-password-audit \
    --pass-policy custom-domain-policy.txt
```