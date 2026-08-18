# Audit

The `audit` module automates the [end-to-end](index.md#manual-workflow) workflow by orchestrating 
the `organise`, `crack`, and `analyse` modules. It is intended as **the primary workflow** for most 
engagements and automates the full password auditing process from data collection through to report 
generation.

```bash
$ password-audit audit -h
usage: password-audit audit [-h] -N NTDS -B BLOODHOUND -C CAMPAIGN -G CAMPAIGN_NAME [-F FILTER] [-M MAPPED_PASSWORDS] [-D DOMAIN_ADMINS] [-P PASS_POLICY] [-W COMPANY_WORDS] [-E ENABLED_USERS]

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
  -M, --mapped-ntlm-passwords MAPPED_NTLM_PASSWORDS
                        Recovered NTLM passwords (default: ./ntds-organiser/mapped-ntlm-passwords.txt)
  -U, --lm-users LM_USERS
                        Accounts storing LM password hashes (default: ./ntds-organiser/lm-users.txt)
  -L, --mapped-lm-passwords MAPPED_LM_PASSWORDS
                        Recovered LM passwords (default: ./ntds-organiser/mapped-lm-passwords.txt)
  -D, --domain-admins DOMAIN_ADMINS
                        Domain Admin account list (default: ./ntds-organiser/domain-admins.txt)
  -P, --pass-policy PASS_POLICY
                        Domain password policy (default: ./ntds-organiser/domain-policy.txt)
  -W, --company-words COMPANY_WORDS
                        Organisation-related strings (default: ./ntds-organiser/company-words.txt)
  -E, --enabled-users ENABLED_USERS
                        Enabled user accounts list (default: ./ntds-organiser/enabled-users.txt)

Example:

    password-audit audit \
        -N company.ntds \
        -B bloodhound.zip \
        -C config.json \
        -G internal-password-audit
```

The following inputs are required:

* An NTDS dataset exported with SecretsDump
* Domain data exported from a BloodHound collector
* A campaign configuration file describing the cracking strategy

The campaign name identifies the assessment and is used when writing campaign history and output 
files. Meaningful names make it easier to distinguish between multiple engagements.

!!! note

    The audit workflow automatically performs LM password recovery and mapping,
    including the required `hashcat --show` step. See the [LM](lm.md) module
    for details.

```bash
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign config.json \
    --campaign-name internal-password-audit
```

This will sequentially run the `organise`, `crack`, and `analyse` modules and produce a 
Markdown-based report when completed:

1. **Organising Data**: Parses the NTDS dataset and extracts supporting artefacts.
2. **Recovering NTLM Passwords**: Executes the configured NTLM cracking campaign.
3. **Recovering LM Passwords**: Executes the configured LM cracking campaign.
4. **Mapping Passwords**: Maps recovered NTLM and LM passwords back to user accounts.
5. **Analysing Passwords**: Performs the dataset analysis and generates the report.

```bash
[*] Stage 1/5 - Organising Data

      NTDS Summary

| Object        | Count |
|---------------|-------|
| User Accounts |   273 |
| NTLM Hashes   |   164 |
| LM Hashes     |    88 |
| Domain Admins |    23 |

[*] Stage 2/5 - Recovering NTLM Passwords
...
                            Campaign Summary

| Phase         | Duration | New Passwords | Total Passwords | ROI (pwd/min) |
|---------------|----------|---------------|-----------------|---------------|
| rockyou       |       2s |             0 |              87 |          0.00 |
| loopback-rule |       2s |             0 |              87 |          0.00 |
| Total         |       4s |             0 |              87 |             - |

[*] Stage 3/5 - Recovering LM Passwords
...

[*] Stage 4/5 - Mapping Passwords

  Password Mapping Summary

| Object            | Count |
|-------------------|-------|
| Mapped Passwords  | 191   |

[*] Stage 5/5 - Analysing Passwords

[+] Audit Complete

[+] Report written to: report.md
[+] Findings written to: findings.json
```

The workflow also generates artefacts produced by the underlying modules, including:

* `ntds-organiser/mapped-ntlm-passwords.txt`
* `ntds-organiser/domain-admins.txt`
* `ntds-organiser/company-words.txt`
* `ntds-organiser/domain-policy.txt`
* `ntds-organiser/enabled-users.txt`
* `report.md`
* `findings.json`

Where LM hashes are present, additional artefacts may also be generated:

* `ntds-organiser/lm-users.txt`
* `ntds-organiser/mapped-lm-passwords.txt`

By default, the audit workflow automatically uses artefacts generated during earlier stages of the 
workflow, but they can be overridden:

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