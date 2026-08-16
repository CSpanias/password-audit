# Installation

Password-Audit supports both user and development installations.

## UV (Recommended)

Recommended for most users who simply want to use the framework.

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install password-audit
uv tool install git+https://github.com/CSpanias/password-audit

# Verify installation
password-audit -h

# Update to the latest version
uv tool upgrade password-audit
```

## Development Installation

Recommended for contributors and anyone modifying the source code. 

The editable installation (`-e`) links the installed package directly to the working directory, allowing code changes to take effect immediately without reinstalling the package.

```bash
# Clone repository
git clone https://github.com/CSpanias/password-audit /opt/password-audit

# Move into the directory
cd /opt/password-audit

# Create virtual environment
uv venv

# Install editable package
uv pip install -e .

# Verify installation
password-audit -h
```

## Requirements

### Core Requirements

* Python 3.10+
* Hashcat (for password recovery campaigns)

### Inputs

* NTDS datasets
* BloodHound ZIP exports