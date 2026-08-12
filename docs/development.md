# Development

This document provides an overview of the development workflow and project structure.

## Installation

### Clone Repository

```bash
git clone https://github.com/CSpanias/password-audit
cd password-audit
```

### Create Virtual Environment

```bash
uv venv
```

### Install Editable Package

```bash
uv pip install -e .
```

### Verify Installation

```bash
password-audit -h
```

## Project Structure

```text
password-audit/
├── analysis/
├── cli/
├── common/
├── cracking/
├── organiser/
├── docs/
├── pyproject.toml
└── README.md
```

### analysis

Password audit reporting and analysis functionality.

### cli

Command-line interface entry points.

### common

Shared utilities, constants, and console helpers.

### cracking

Password recovery campaigns, Hashcat integration, statistics, and estimation.

### organiser

NTDS, BloodHound, and Hashcat artefact processing.

### docs

Project documentation.

## Commands

Display available commands:

```bash
password-audit -h
```

Display cracking commands:

```bash
password-audit crack -h
```

## Testing

### Organise

```bash
password-audit organise \
    -n company.ntds \
    -b bloodhound.zip
```

### Crack

```bash
password-audit crack run \
    -C campaign.json \
    -H ntds-organiser/ntlm-hashes.txt \
    -N test
```

### Statistics

```bash
password-audit crack stats
```

### Estimation

```bash
password-audit crack estimate \
    -C campaign.json
```

### Analyse

```bash
password-audit analyse \
    -M ntds-organiser/mapped-ntlm-passwords.txt
```

## Design Principles

The project follows a modular design:

* One responsibility per module.
* Shared functionality belongs in `common`.
* CLI handlers belong in `cli`.
* Business logic belongs in feature packages.
* Documentation is maintained alongside the source code.

## Future Development

Planned areas of development include:

* End-to-end workflow automation
* Historical campaign comparisons
* Advanced campaign effectiveness analytics
* Additional report formats
* Additional password audit utilities