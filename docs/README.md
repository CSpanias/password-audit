# Documentation

This directory contains the documentation for the Password-Audit framework.

## Getting Started

New users should read the documents in the following order:

1. [Root `README` (project overview)](https://github.com/CSpanias/password-audit/blob/main/README.md)
2. [organise](https://github.com/CSpanias/password-audit/blob/main/docs/organise.md): Process NTDS dumps, BloodHound exports, and Hashcat artefacts.
3. [campaigns](https://github.com/CSpanias/password-audit/blob/main/docs/campaigns.md): Define password recovery campaigns.
4. [crack](https://github.com/CSpanias/password-audit/blob/main/docs/crack.md) : Execute password recovery campaigns using Hashcat.
5. [analyse](https://github.com/CSpanias/password-audit/blob/main/docs/analyse.md): Generate password audit findings and reports.
6. [development](https://github.com/CSpanias/password-audit/blob/main/docs/development.md): Contributor and project structure information.

## Typical Workflow

```text
Extract NTDS and BloodHound Data
            ↓
password-audit organise
            ↓
password-audit crack run
            ↓
password-audit organise
            ↓
password-audit analyse
```