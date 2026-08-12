# Password Analyser

## Overview 

The Password Analyser module identifies password security weaknesses and generates a Markdown-formatted report from recovered password datasets.

The only required argument is `--mapped-passwords` / `-M` which is the dataset in a `domain\username:password` format. All other information is loaded automatically from the default `./ntds-organiser` directory, but all options can be overridden manually:

```bash
$ password-audit analyse -h
usage: password-audit analyse [-h] -M MAPPED_PASSWORDS [-A DOMAIN_ADMINS] [-P PASS_POLICY] [-G COMPANY_WORDS] [-E ENABLED_USERS]

options:
  -h, --help            show this help message and exit
  -M, --mapped-passwords MAPPED_PASSWORDS
                        Recovered username:password dataset
  -A, --domain-admins DOMAIN_ADMINS
                        Domain Admin account list (default: ./ntds-organiser/domain-admins.txt)
  -P, --pass-policy PASS_POLICY
                        Domain password policy (default: ./ntds-organiser/domain-policy.txt)
  -G, --company-words COMPANY_WORDS
                        Organisation-specific password analysis terms (default: ./ntds-organiser/company-words.txt)
  -E, --enabled-users ENABLED_USERS
                        Enabled user accounts list (default: ./ntds-organiser/enabled-users.txt)
```

The `analyser` currently identifies:

* Password recovery rates
* Privileged account exposure (at the moment only Domain Admins)
* Password reuse
* Common passwords
* Username-derived passwords
* Organisation-related passwords
* Date-based passwords
* Keyboard-walk passwords
* Character-class usage

## Usage

Simply pass the final dataset (assuming everything else is within `./ntds-organiser`):

```bash
password-audit analyse \
    -M ntds-organiser/mapped-ntlm-passwords.txt
```

This will generate the `report.md` file which will contain the analysis separated in the following sections:

1. Executive Summary (high-level assessment and key findings)
2. Technical Commentary (detailed analysis of password weaknesses)
3. Remediation Guidance (recommendations for improving password security)