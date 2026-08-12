# Password Analyser

The Password Analyser module identifies password security weaknesses and generates assessment reports from recovered password datasets.

## Features

* Password recovery statistics
* Crack-rate analysis
* Privileged account identification
* Password reuse detection
* Username-derived password detection
* Organisation-related password detection
* Common password analysis
* Date-based password analysis
* Keyboard-walk analysis
* Password length analysis
* Character-class analysis
* Executive summary generation
* Technical commentary generation
* Remediation guidance generation

## Commands

### Generate a Report

```bash
password-audit analyse \
    -M ntds-organiser/mapped-ntlm-passwords.txt
```

## Inputs

| File | Description |
|------|-------------|
| `mapped-ntlm-passwords.txt` | Recovered passwords mapped to user accounts |

## Output

| File | Description |
|------|-------------|
| `report.md` | Markdown audit report |

## Analysis Areas

The analyser examines:

* Password recovery rates
* Privileged account exposure
* Password reuse
* Common passwords
* Username-derived passwords
* Organisation-related passwords
* Date-based passwords
* Keyboard-walk passwords
* Password complexity
* Character-class usage

## Workflow Position

The analyser is typically executed after:

1. NTDS processing
2. Password recovery
3. Password mapping

```text
password-audit organise
        ↓
password-audit crack run
        ↓
password-audit organise
        ↓
mapped-ntlm-passwords.txt
        ↓
password-audit analyse
        ↓
report.md
```

## Example Workflow

```bash
password-audit analyse \
    -M ntds-organiser/mapped-ntlm-passwords.txt
```

Generated report:

```text
report.md
```