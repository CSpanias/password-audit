# Audit

## Overview

The `password-audit audit` module performs automatically the [end-to-end process](index.md#end-to-end-example) by orchestrating all the other three modules (`organise`, `crack`, and `analyse`).

It is intended as the primary workflow for most engagements and automates the full password auditing process from NTDS parsing through to report generation.

```bash
$ password-audit audit -h
usage: password-audit audit [-h] -N NTDS [-B BLOODHOUND] -C CAMPAIGN -G CAMPAIGN_NAME [-M MAPPED_PASSWORDS] [-A DOMAIN_ADMINS] [-P PASS_POLICY] [-W COMPANY_WORDS] [-E ENABLED_USERS]

options:
  -h, --help            show this help message and exit
  -N, --ntds NTDS       Secretsdump NTDS file
  -B, --bloodhound BLOODHOUND
                        BloodHound ZIP export (default: None)
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

Example:

```bash
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign config.json \
    --campaign-name internal-password-audit
```

Example output:

```text
[*] Stage 1/4 - Organising Data
[*] Stage 2/4 - Recovering Passwords
[*] Stage 3/4 - Mapping Passwords
[*] Stage 4/4 - Analysing Passwords

[*] Audit Complete

    Report              : report.md
    Mapped Passwords    : ntds-organiser/mapped-ntlm-passwords.txt
    Recovered Passwords : 238
```

## Custom Analysis Inputs

By default, the audit workflow automatically uses artefacts generated during execution. However, analysis inputs can be overridden when required (e.g. incomplete BloodHound datasets).

Available overrides:

* `--mapped-passwords`
* `--domain-admins`
* `--pass-policy`
* `--company-words`
* `--enabled-users`

Example overriding the password policy:

```bash
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign config.json \
    --campaign-name internal-password-audit \
    --pass-policy custom-domain-policy.txt
```