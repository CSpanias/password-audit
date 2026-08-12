# Crack

!!! tip
    Use `password-audit crack estimate` before executing large campaigns.

The `password-audit crack` module executes password recovery campaigns using Hashcat and tracks historical campaign performance. It has three submodules:

```bash
$ password-audit crack -h
usage: password-audit crack [-h] {run,stats,estimate} ...

positional arguments:
  {run,stats,estimate}
    run                 Execute a cracking campaign
    stats               Display historical cracking statistics
    estimate            Estimate campaign duration

options:
  -h, --help            show this help message and exit
```

## Campaign Structure

Campaigns define how password recovery attacks are executed. A campaign consists of:

* Global parameters
* One or more attack phases

Campaigns are written in JSON and supplied to the `crack run` subcommand using the `-C` / `--campaign` flag:

```bash
$ password-audit crack run -h
usage: password-audit crack run [-h] -C CAMPAIGN -H HASHES -G CAMPAIGN_NAME [--debug]

options:
  -h, --help            show this help message and exit
  -C, --campaign CAMPAIGN
                        Campaign configuration file
  -H, --hashes HASHES   File containing NTLM hashes to recover
  -G, --campaign-name CAMPAIGN_NAME
                        Campaign identifier
  --debug               Display verbose Hashcat output (default: False)
```

A campaign contains two top-level sections:

* `parameters`
    * `hashMode`: Specifies the Hashcat hash mode.
    * `hashcatDir`: Overrides the default Hashcat installation directory.
    * `hashcatBinary`: Overrides the Hashcat executable path.
    * `flags`: Additional Hashcat command-line arguments.
* `phases`
    * `id`: Unique identifier for the phase.
    * `enabled`: Enable or disable a phase.
    * `type`: Dictionary (`wordlist`) or loopback (`loopback`) attack.
    * `wordlist`: Wordlist file used by the phase. (required only if `"type": "wordlist"`)
    * `rule`: Rule file to be used by the phase.

Phases are executed sequentially in the order they are defined.

An example `config.json` file consisting of five phases is shown below:

```json
{
    "parameters": {
        "hashcatDir": "/mnt/c/tools/hashcat",
        "hashMode": "1000",
        "flags": [
            "-O",
            "-w", "3",
            "-d", "1",
            "--status",
            "--status-timer", "300"
        ]
    },

    "phases": [
        {
            "id": "rockyou-rule",
            "type": "wordlist",
            "wordlist": "rockyou.txt",
            "rule": "OneRuleToRuleThemStill.rule",
            "enabled": true
        },
        {
            "id": "hashmob-rule",
            "type": "wordlist",
            "wordlist": "hashmob.net_2026-06-07.combined.txt",
            "rule": "OneRuleToRuleThemStill.rule",
            "enabled": true
        },
        {
            "id": "weakpass-rule",
            "type": "wordlist",
            "wordlist": "weakpass_4a.txt",
            "rule": "OneRuleToRuleThemStill.rule",
            "enabled": true
        },
        {
            "id": "rockyou2024-rule",
            "type": "wordlist",
            "wordlist": "rockyou2024.txt",
            "rule": "OneRuleToRuleThemStill.rule",
            "enabled": true
        },
        {
            "id": "loopback-rule",
            "type": "loopback",
            "wordlist": "loopback.txt",
            "rule": "OneRuleToRuleThemStill.rule",
            "enabled": true
        }
    ]
}
```

Loopback phases generate a temporary dictionary from passwords recovered during previous phases. This allows recovered passwords to be transformed with Hashcat rules and reused in subsequent attack phases. If no passwords have been recovered, loopback phases are skipped automatically.

## Campaign Validation

Campaigns are validated before execution. Validation includes:

* Required parameter checks
* Required phase fields
* Valid phase types
* Duplicate phase detection
* Enabled phase validation

Invalid configurations will be rejected before Hashcat execution begins.

## Usage

### Campaign Duration Estimation

Once we have a configuration file ready, we can use the `crack estimate` option to produce a per phase and a total duration based on historical data:

```bash
$ password-audit crack estimate --campaign config.json

## Campaign Estimate

rockyou             : 3s (10 runs)
rockyou-rule        : 12s (10 runs)
hashmob-rule        : Unknown (0 runs)
weakpass-rule       : Unknown (0 runs)
rockyou2024-rule    : Unknown (0 runs)
loopback-rule       : 2s (10 runs)

Estimated Total   : 18s (partial estimate)
```

### Running the Campaign

We can adjust the JSON file accordingly (e.g. via the `enabled` flag) and then re-estimate the campaign's duration. When satisfied, we can `run` the campaign:

```bash
password-audit crack run \
    --campaign campaign.json \
    --hashes ntds-organiser/ntlm-hashes.txt \
    --campaign-name internal-password-audit
```

### Campaign Statistics

Campaign execution produces a results file containing recovery statistics for each phase (`./ntds-organiser/test-run-results.json`):

```json
{
    "campaign": "test-run",
    "hashMode": "1000",
    "hashDataset": "/home/test/ntds-organiser/ntlm-hashes.txt",
    "started": "2026-08-12T12:23:21.551835",
    "phases": [
        {
            "id": "rockyou",
            "wordlist": "rockyou.txt",
            "rule": "",
            "duration": 3.13,
            "durationHuman": "3s",
            "newRecovered": 0,
            "totalRecovered": 1,
            "returnCode": 1,
            "passwordsPerMinute": 0.0
        },
        {
            "id": "rockyou-rule",
            "wordlist": "rockyou.txt",
            "rule": "best66.rule",
            "duration": 2.73,
            "durationHuman": "2s",
            "newRecovered": 0,
            "totalRecovered": 1,
            "returnCode": 1,
            "passwordsPerMinute": 0.0
        },
        {
            "id": "loopback-rule",
            "wordlist": "loopback.txt",
            "rule": "OneRuleToRuleThemStill.rule",
            "duration": 2.7,
            "durationHuman": "2s",
            "newRecovered": 0,
            "totalRecovered": 1,
            "returnCode": 1,
            "passwordsPerMinute": 0.0
        }
    ],
    "completed": "2026-08-12T12:23:30.197514"
}
```

In addition, campaign results are archived automatically and used to provide:

* Historical attack statistics
* Recovery metrics
* Return on investment (ROI) calculations
* Campaign duration estimates

For example:

```bash
$ password-audit crack stats

## Attack Statistics

loopback-rule
-------------
    Runs                : 10
    Average Duration    : 2s
    Average Recovery    : 0.0
    Average ROI         : 0.0 passwords/min
    Best Recovery       : 0
    Best ROI            : 0 passwords/min

rockyou
-------
    Runs                : 10
    Average Duration    : 3s
    Average Recovery    : 0.1
    Average ROI         : 1.9 passwords/min
    Best Recovery       : 1
    Best ROI            : 18.97 passwords/min

rockyou-rule
------------
    Runs                : 10
    Average Duration    : 12s
    Average Recovery    : 0.0
    Average ROI         : 0.0 passwords/min
    Best Recovery       : 0
    Best ROI            : 0 passwords/min
```

## Output Files

Campaign execution generates the following artefacts:

| File | Description |
|--------|--------|
| `campaign-results.json` | Campaign execution results |
| `loopback.txt` | Generated loopback dictionary |
| `hashcat.potfile` | Hashcat recovered password database |