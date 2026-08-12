# Development

This document provides an overview of the project structure and development practices used by the framework.

## Installation

For the development installation, see [Installation](installation.md#development-installation).

## Design Principles

The project follows a modular design:

* One responsibility per module.
* Shared functionality belongs in `common`.
* CLI handlers belong in `cli`.
* Business logic belongs in feature packages.
* Documentation is maintained alongside the source code.

## Project Structure

* `analysis` &rarr; Password audit reporting and analysis functionality.
* `auditing` &rarr; End-to-end audit workflow orchestration.
* `cli` &rarr;  Command-line interface entry points.
* `common` &rarr; Shared utilities, constants, and console helpers.
* `cracking` &rarr;  Password recovery campaigns, Hashcat integration, statistics, and estimation.
* `docs`  &rarr; Project documentation.
* `ntds` &rarr; NTDS, BloodHound, and Hashcat artefact processing.

```text
password-audit/
├── analysis/
├── auditing/
├── cli/
├── common/
├── cracking/
├── docs/
└── ntds/
```

## Architecture 

Framework components are separated into: 

* CLI handlers
* Business logic
* Reporting and export helpers 

CLI handlers should remain thin wrappers around reusable workflow functions. Business logic should not be implemented directly within CLI modules.

Example `organise` workflow: 

```text
cli/organise.py 
↓ 
ntds/workflow.py 
↓ 
ntds/results.py 
↓ 
ntds/exports.py
```

Example `audit` workflow: 

```text
cli/audit.py
↓
auditing/workflow.py
├── ntds/workflow.py
├── cracking/scheduler.py
└── analysis/workflow.py
```

## Adding New Functionality 

New functionality should generally follow the pattern:

1. Implement business logic in the relevant module.
2. Expose functionality through a workflow. 
3. Add a CLI entry point. 
4. Update documentation.

Example: 

```text
analysis/ 
├── parsers.py 
├── results.py 
└── workflow.py 

cli/ 
└── analyse.py
```

## Future Development

Planned areas of development include:

* Add additional privileged groups (e.g. Account Operators) in the analysis (`analyse`)
* Campaign resume support (`crack run`)
* Wordlist and rule effectiveness metrics (`crack stats`)
* Historical campaign comparisons (`crack stats`)
* Advanced campaign effectiveness analytics (`crack stats`)
* Additional report formats (`crack analyse`)