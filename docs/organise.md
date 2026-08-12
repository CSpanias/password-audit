# NTDS Organiser

The NTDS Organiser module processes Active Directory datasets and generates artefacts used during password audits.

## Features

* NTDS parsing
* BloodHound ZIP processing
* Domain Administrator identification
* Domain policy extraction
* Organisation wordlist generation
* NTLM hash extraction
* LM candidate generation
* Password mapping

## Commands

### Process NTDS and BloodHound Data

```bash
password-audit organise \
    -n company.ntds \
    -b bloodhound.zip
```

### Map Recovered Passwords

```bash
password-audit organise \
    -n company.ntds \
    -p hashcat.potfile
```

## Inputs

| File | Description |
|------|-------------|
| `company.ntds` | NTDS dataset |
| `bloodhound.zip` | BloodHound export |
| `hashcat.potfile` | Hashcat recovered passwords |

## Outputs

| File | Description |
|------|-------------|
| `ntlm-hashes.txt` | Extracted NTLM hashes |
| `domain-admins.txt` | Domain Administrator accounts |
| `domain-policy.txt` | Domain password policy |
| `company-words.txt` | Organisation-specific wordlist |
| `mapped-ntlm-passwords.txt` | Recovered passwords mapped to user accounts |
| `lm-candidates.txt` | LM candidate dataset |

## Workflow Position

The organiser module is typically executed:

1. Before password recovery campaigns.
2. After password recovery campaigns to map recovered passwords.

## Example Workflow

```text
NTDS + BloodHound
       ↓
password-audit organise
       ↓
ntlm-hashes.txt
company-words.txt
domain-admins.txt
       ↓
password-audit crack run
       ↓
hashcat.potfile
       ↓
password-audit organise
       ↓
mapped-ntlm-passwords.txt
```