# Roadmap

This page documents potential future enhancements. Features listed here are ideas under consideration and are not guaranteed to be implemented.

## Crack

### Campaign Resume

The current resume functionality requires the original campaign parameters to be supplied again:

```bash
password-audit crack run \
    -H hashes.txt \
    -C config.json \
    -G internal-audit \
    --resume
```

Future versions may support automatic campaign recovery by parsing the most recent interrupted campaign from the history directory:

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

Support generating reports in formats other than Markdown for easier distribution and integration with existing reporting workflows:

* HTML
* PDF
* DOCX