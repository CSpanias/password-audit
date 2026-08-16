# Development

!!! info
    Portions of this project were implemented with the assistance of Microsoft Copilot (Basic) (19.2608.34011.0).

This document provides an overview of the project structure and development practices used by the framework.

## Installation

For the development installation, see [Installation](installation.md#development-installation).

## Project Structure

The framework is organised into a number of top-level packages:

| Package | Responsibility |
|----------|-------------|
| `analysis` | Password analysis and report generation |
| `auditing` | End-to-end workflow orchestration |
| `cli` | Command-line interface entry points |
| `common` | Shared utilities, constants, and helpers |
| `cracking` | Hashcat integration, campaign execution, estimation, and statistics |
| `docs` | Project documentation |
| `lm` | LM password mapping and candidate generation |
| `ntds` | NTDS, BloodHound, and password dataset processing |


```text
password-audit/
├── analysis/
├── auditing/
├── cli/
├── common/
├── cracking/
├── docs/
├── lm/
└── ntds/
```

Each package is intended to remain largely self-contained, with shared functionality placed in `common` where appropriate.

## Design Philosophy

The project is designed around a simple principle: command-line modules should remain thin wrappers around reusable workflow functions. In general:

* CLI modules are responsible for argument parsing and user interaction.
* Workflow modules coordinate the execution of features.
* Supporting modules implement the business logic.
* Export and reporting modules write results to disk.
* Shared functionality belongs in `common`.

This separation makes features easier to test, reuse, and maintain.

## Workflow Architecture

Most user-facing functionality follows the same pattern:

```text
CLI
 ↓
Workflow
 ↓
Business Logic
 ↓
Results / Exports
```

### Audit

Coordinates the full password auditing workflow:

```text
cli/audit.py
        ↓
auditing/workflow.py
        ├── ntds/workflow.py
        ├── cracking/scheduler.py
        └── analysis/workflow.py
```

### Organise

Processes NTDS, BloodHound, and Hashcat artefacts:

```text
cli/organise.py 
↓ 
ntds/workflow.py 
↓ 
ntds/results.py 
↓ 
ntds/exports.py
```

### Crack

Executes Hashcat campaigns and records statistics:

```text
cli/crack.py
        ↓
cracking/scheduler.py
        ├── cracking/phases.py
        ├── cracking/hashcat.py
        ├── cracking/history.py
        └── cracking/reporting.py
```

### Analyse

Performs password analysis and generates reports:

```text
cli/analyse.py
        ↓
analysis/workflow.py
        ├── analysis/parsers.py
        ├── analysis/patterns.py
        ├── analysis/results.py
        └── analysis/reports.py
```

### LM

Processes recovered LM passwords and generates candidate datasets:

```text
cli/lm.py
        ↓
lm/workflow.py
        ├── lm/mapping.py
        ├── lm/candidates.py
        └── ntds/exports.py
```

## Contributing New Features

When adding new functionality, try to follow the existing architecture:

* Implement the business logic in the appropriate package.
* Add or extend a workflow function.
* Expose the functionality through the CLI.
* Document the feature and update command examples.

For example, adding a new analysis feature might involve:

```text
analysis/ 
├── parsers.py 
├── results.py 
└── workflow.py 

cli/ 
└── analyse.py
```