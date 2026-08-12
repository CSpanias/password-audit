# Password Cracker

The Password Cracker module executes password recovery campaigns using Hashcat and tracks historical campaign performance.

## Features

* Multi-phase recovery campaigns
* Loopback dictionary generation
* Campaign validation
* Campaign result tracking
* Historical attack statistics
* ROI tracking
* Campaign duration estimation
* Hashcat integration

## Commands

### Run a Campaign

Execute a password recovery campaign:

```bash
password-audit crack run \
    -C campaign.json \
    -H ntds-organiser/ntlm-hashes.txt \
    -N internal-audit
```

Parameters:

* `-C`: Campaign configuration file
* `-H`: Hash dataset
* `-N`: Campaign name
* `--debug`: Display verbose Hashcat output

## Statistics

Display historical attack statistics:

```bash
password-audit crack stats
```

Example:

```text
## Attack Statistics

rockyou-rule
------------

    Runs                : 12
    Average Duration    : 1m 41s
    Average Recovery    : 4.2
    Average ROI         : 2.5 passwords/min
```

## Estimation

Estimate campaign duration using historical execution data:

```bash
password-audit crack estimate \
    -C campaign.json
```

Example:

```text
## Campaign Estimate

rockyou             : 3s (12 runs)
rockyou-rule        : 1m 41s (12 runs)
loopback-rule       : 2s (12 runs)

Estimated Total     : 1m 46s
```

## Outputs

Campaign execution produces the following artefacts:

| File | Description |
|------|-------------|
| `campaign-results.json` | Campaign execution results |
| `loopback.txt` | Generated loopback dictionary |
| `hashcat.potfile` | Hashcat recovered password database |

## Historical Data

Campaign results are archived automatically and used to provide:

* Historical attack statistics
* Recovery metrics
* ROI calculations
* Campaign duration estimates