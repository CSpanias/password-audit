# Roadmap

This page documents potential future enhancements. Features listed here are ideas under consideration and are not guaranteed to be implemented.

## Crack

### Campaign Resume

`crack run --resume` continues a recorded interrupted campaign, but the
original hash dataset, campaign file, and campaign name must be supplied again:

```bash
password-audit crack run \
    -H hashes.txt \
    -C config.json \
    -G internal-audit \
    --resume
```

Future versions may support selecting an interrupted campaign from its recorded
results without re-entering those arguments:

```bash
password-audit crack run --resume
```

## Analyse

### Additional Privileged Group Analysis

The current privileged account analysis focuses on Domain Administrators. Future versions may include dedicated analysis for additional privileged groups, such as:

* Account Operators
* Backup Operators
* Cert Publishers
* DNS Admins
* Enterprise Admins
* Exchange Windows
* Server Operators
* Schema Admins
* Custom privileged groups identified in BloodHound

### Additional Report Formats

Additional export formats may improve compatibility with existing reporting
workflows. The current report formats are Markdown, HTML, JSON, YAML, and
SARIF.

* PDF
* DOCX