# Installation

Password Audit is a Python command-line application. Install it with
[uv](https://docs.astral.sh/uv/) as an isolated command-line tool, or install an
editable copy when developing the project.

## Requirements

- Python 3.10 or later. `uv tool install` creates an isolated tool environment.
- Hashcat for password-recovery campaigns and the end-to-end `audit` workflow.
- For `audit` and `organise`, an NTDS export and a BloodHound ZIP export.

Analysis and report rendering do not require Hashcat. Configure the Hashcat
binary and data directories in the campaign file; see
[Campaign configuration](crack.md#campaign-configuration).

## Install for use

Install `uv` using its [official instructions](https://docs.astral.sh/uv/getting-started/installation/),
then install Password Audit:

```bash
uv tool install git+https://github.com/CSpanias/password-audit
password-audit --help
```

To update the installation:

```bash
uv tool upgrade password-audit
```

## Recommended workflow

Continue with the [end-to-end audit guide](audit.md) for the recommended
assessment workflow. The standalone modules are available for advanced or
partial workflows.