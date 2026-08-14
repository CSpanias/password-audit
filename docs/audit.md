# Audit

## Overview

The `audit` module performs automatically the [end-to-end process](index.md#end-to-end-example) by orchestrating all the other three modules (`organise`, `crack`, and `analyse`).

It is intended as the primary workflow for most engagements and automates the full password auditing process from data parsing through to report generation.

```bash
$ password-audit audit -h
usage: password-audit audit [-h] -N NTDS -B BLOODHOUND -C CAMPAIGN -G CAMPAIGN_NAME [-M MAPPED_PASSWORDS] [-A DOMAIN_ADMINS] [-P PASS_POLICY] [-W COMPANY_WORDS] [-E ENABLED_USERS]

options:
  -h, --help            show this help message and exit
  -N, --ntds NTDS       Secretsdump NTDS file
  -B, --bloodhound BLOODHOUND
                        BloodHound ZIP export
  -C, --campaign CAMPAIGN
                        Campaign configuration file
  -G, --campaign-name CAMPAIGN_NAME
                        Campaign identifier
  -M, --mapped-passwords MAPPED_PASSWORDS
                        Recovered username:password dataset (default: ./ntds-organiser/mapped-ntlm-passwords.txt)
  -A, --domain-admins DOMAIN_ADMINS
                        Domain Admin account list (default: ./ntds-organiser/domain-admins.txt)
  -P, --pass-policy PASS_POLICY
                        Domain password policy (default: ./ntds-organiser/domain-policy.txt)
  -W, --company-words COMPANY_WORDS
                        Organisation-specific password analysis terms (default: ./ntds-organiser/company-words.txt)
  -E, --enabled-users ENABLED_USERS
                        Enabled user accounts list (default: ./ntds-organiser/enabled-users.txt)
```

## Usage

For the `audit` module three files are required:

- The NTDS dump
- The domain data
- A configuration file

The campaign name flag is for

```bash
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign config.json \
    --campaign-name internal-password-audit
```

This will sequentially run the `organise`, `crack`, and `analyse` modules and produce a Markdown-based report when completed:

```bash
[*] Stage 1/4 - Organising Data # parsing data
[*] Stage 2/4 - Recovering Passwords # cracking hashes
[*] Stage 3/4 - Mapping Passwords # generating final dataset
[*] Stage 4/4 - Analysing Passwords # analysing results and creating the report

[*] Audit Complete

    Report              : report.md
    Mapped Passwords    : ntds-organiser/mapped-ntlm-passwords.txt
    Recovered Passwords : 238
```

By default, the audit workflow automatically uses artefacts generated during execution. However, the following inputs can be overridden when required (e.g. incomplete BloodHound datasets):

* `--mapped-passwords`
* `--domain-admins`
* `--pass-policy`
* `--company-words`
* `--enabled-users`

For instance, the password policy could be overridden as follows:

```bash
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign config.json \
    --campaign-name internal-password-audit \
    --pass-policy custom-domain-policy.txt
```