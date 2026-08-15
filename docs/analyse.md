# Analyse

The `analyse` module identifies password security weaknesses and generates a Markdown-formatted report from recovered password datasets.

The only required argument is `--mapped-passwords` / `-M`, which should reference a dataset in the `domain\username:password` format. All other datasets are loaded automatically from the default `./ntds-organiser` directory, but can be overridden manually if required.

!!! info
    If LM hashes are present in the NTDS, these can be included in the analysis via the `-L` / `--mapped-lm-passwords` flag. See [LM](lm.md) for more.

```bash
$ password-audit analyse -h
usage: password-audit analyse [-h] -M MAPPED_PASSWORDS [-D DOMAIN_ADMINS] [-P PASS_POLICY] [-G COMPANY_WORDS] [-E ENABLED_USERS] [-U LM_USERS] [-L MAPPED_LM_PASSWORDS]

Analyse recovered NTLM and LM passwords, identify common weaknesses, and generate a Markdown report with findings and remediation guidance.

options:
  -h, --help            show this help message and exit

required arguments:
  -M, --mapped-passwords MAPPED_PASSWORDS
                        Recovered NTLM passwords

optional arguments:
  -D, --domain-admins DOMAIN_ADMINS
                        Domain Admin account list (default: ./ntds-organiser/domain-admins.txt)
  -P, --pass-policy PASS_POLICY
                        Domain password policy (default: ./ntds-organiser/domain-policy.txt)
  -G, --company-words COMPANY_WORDS
                        Organisation-specific password analysis terms (default: ./ntds-organiser/company-words.txt)
  -E, --enabled-users ENABLED_USERS
                        Enabled user accounts list (default: ./ntds-organiser/enabled-users.txt)
  -U, --lm-users LM_USERS
                        Accounts storing LM password hashes (default: ./ntds-organiser/lm-users.txt)
  -L, --mapped-lm-passwords MAPPED_LM_PASSWORDS
                        Recovered LM passwords (default: ./ntds-organiser/mapped-lm-passwords.txt)

Example:

    password-audit analyse \
        -M ntds-organiser/mapped-ntlm-passwords.txt
```

The current analysis includes:

* Password recovery rates
* Privileged account exposure (currently Domain Administrators)
* Password reuse analysis
* Common password identification
* Username-derived passwords
* Organisation-related passwords
* Date-based passwords
* Keyboard-walk passwords
* Character-class analysis

## Usage

The `analyse` module combines recovered password datasets with supporting artefacts generated during the organise stage, such as Domain Administrator lists, password policy information, organisation-specific terminology, and enabled user accounts. The only required argument is the final dataset:

```bash
# NTLM hashes only
$ password-audit analyse \
    -M ntds-organiser/mapped-ntlm-passwords.txt

[+] Markdown report written to: report.md

# NTLM + LM hashes
$ password-audit analyse \
    -M ntds-organiser/mapped-ntlm-passwords.txt \
    -L ntds-organiser/mapped-lm-passwords.txt

[+] Markdown report written to: report.md
```

The generated report is divided into three sections:

1. Executive Summary (high-level assessment and key findings)
2. Technical Commentary (detailed analysis of identified weaknesses)
3. Remediation Guidance (recommendations for improving password security)

A simplified example report structure is shown below:

```markdown
# Executive Summary

A password audit was performed against extracted Active Directory password 
hashes to assess the effectiveness of password selection practices and identify 
weaknesses that could increase the likelihood of credential compromise. The 
assessment simulated the techniques available to an attacker with access to 
password hash material and provides insight into the effectiveness of password 
policies, user behaviour, and privileged account security controls.
...

# Technical Commentary

A password audit was performed against extracted Active Directory password 
hashes to assess the effectiveness of password selection practices and identify 
weaknesses that could increase the likelihood of credential compromise.

Through password-cracking techniques, it was possible to recover 79 plaintext 
passwords from 273 enabled user accounts, representing approximately 28.9% of 
the assessed population. This demonstrates that a measurable proportion of user 
credentials remain susceptible to password-cracking attacks following 
credential exposure. The recovered passwords were subsequently analysed to 
identify common password selection patterns, policy non-compliance, and other 
indicators of weak password hygiene.

To maintain report readability, example findings have been included throughout 
this section. Unless otherwise stated, tables are intended to provide
representative samples and may not contain all affected accounts identified 
during the assessment.
...

# Remediation Guidance

Remediation efforts should be prioritised according to business risk and 
aligned with the organisation's wider identity and access management strategy:

- The affected privileged accounts should have their passwords reset 
immediately and reviewed to ensure they are protected by strong, unique 
credentials. Consider applying enhanced controls to privileged identities, 
including dedicated password policies, privileged access management solutions, 
and multi-factor authentication.
- LM hash storage should be disabled and affected users should be required to 
change their passwords to ensure that previously stored LM hashes are removed. 
Any legacy systems requiring LM compatibility should be identified and 
remediated where possible.
...
```