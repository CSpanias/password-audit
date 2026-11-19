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

Install [`uv`](https://docs.astral.sh/uv/getting-started/installation/) and 
then `password-audit`:

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install password-audit
uv tool install git+https://github.com/CSpanias/password-audit

# Check installation
password-audit --help
```

To update the installation:

```bash
uv tool upgrade password-audit
```