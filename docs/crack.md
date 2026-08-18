# Crack

!!! tip
    Use `password-audit crack estimate` before executing large campaigns.

The `crack` module is used to:

- Estimate campaign duration using historical statistics (`estimate`)
- Execute password recovery campaigns with Hashcat (`run`)
- Review historical attack performance and recovery metrics (`stats`)

```bash
$ password-audit crack -h
usage: main.py crack [-h] {estimate,run,stats} ...

Execute Hashcat password recovery campaigns, estimate campaign duration 
using historical statistics, and review past campaign performance.

positional arguments:
  {estimate,run,stats}
    estimate            Estimate campaign duration
    run                 Execute a cracking campaign
    stats               Display historical cracking statistics

options:
  -h, --help            show this help message and exit

    Examples:

        password-audit crack estimate \
            -C config.json

        password-audit crack run \
            -H ntds-organiser/ntlm-hashes.txt \
            -C config.json \
            -G internal-audit

        password-audit crack stats
```

## Campaigns

Campaigns define the sequence of password recovery attacks executed by Hashcat. They consist of global `parameters` (apply to all phases) and one or more attack `phases` executed sequentially. 

Campaigns are written in JSON and contain the following sections:

* `parameters`
    * `hashMode`: Specifies the Hashcat hash mode.
    * `hashcatDir`: Overrides the default Hashcat installation directory.
    * `hashcatBinary`: Overrides the Hashcat executable path.
    * `flags`: Additional Hashcat command-line arguments.
* `phases`
    * `id`: Unique identifier for the phase.
    * `enabled`: Enable or disable a phase.
    * `type`: Attack type (`wordlist` or `loopback`).
    * `wordlist`: Input wordlist used by the phase.
    * `rule`: Rule file to be used by the phase.

!!! tip
    Example configuration files for [NTLM](https://github.com/CSpanias/password-audit/blob/main/example-ntlm-config.json), [LM](https://github.com/CSpanias/password-audit/blob/main/example-lm-config.json), or [both](https://github.com/CSpanias/password-audit/blob/main/example-dual-config-small.json) can be found on the GitHub root directory.

An example JSON file consisting of three phases is shown below:

```json
{
    "ntlm": {
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
                "id": "loopback-rule",
                "type": "loopback",
                "wordlist": "loopback.txt",
                "rule": "OneRuleToRuleThemStill.rule",
                "enabled": true
            }
        ]
    }
}
```

!!! tip
    **Loopback phases** generate a temporary dictionary from passwords recovered during previous phases (`loopback.txt`). This allows recovered passwords to be transformed with Hashcat rules and reused in subsequent attack phases. If no passwords have been recovered, loopback phases are skipped automatically.

Campaigns are validated before execution. Validation includes:

* Required parameter checks
* Required phase fields
* Valid phase types
* Duplicate phase detection
* Enabled phase validation

Invalid configurations will be rejected before Hashcat execution begins.

## Estimate

The `estimate` command predicts the duration of each campaign phase and the overall campaign based on historical execution data. This helps operators estimate runtime and optimise cracking strategies before launching large campaigns.

```bash
$ password-audit crack estimate -h
usage: main.py crack estimate [-h] -C CAMPAIGN

Estimate the duration of a cracking campaign before execution using 
the supplied configuration file and historical data.

options:
  -h, --help            show this help message and exit

required arguments:
  -C, --campaign CAMPAIGN
                        Campaign configuration file

Example:

    password-audit crack estimate \
        -C config.json
```

Each `run` generates a JSON history file under `~/.password-audit/history` containing performance metrics used by the estimation engine:

```json
{
...
        {
            "id": "rockyou-rule",
            "session": "test-lm-rockyou-rule",
            "wordlist": "rockyou.txt",
            "rule": "OneRuleToRuleThemStill.rule",
            "duration": 817.54,
            "durationHuman": "13m 37s",
            "newRecovered": 43,
            "totalRecovered": 192,
            "returnCode": 1,
            "passwordsPerMinute": 0.0
        },
...
}                                     
```

The estimate is calculated by matching campaign phases against historical execution data:

```bash
$ password-audit crack estimate --campaign config.json

               Campaign Estimate

| Phase           | Duration | Historical Runs |
|-----------------|----------|-----------------|
| rockyou         |       3s |              62 |
| loopback-rule   |       3s |              58 |
|-----------------|----------|-----------------|
| Estimated Total |       6s |               - |
```

## Run

Running a campaign requires:

- A hash dataset
- A campaign configuration file
- A campaign identifier used for result tracking and statistics collection

```bash
$ password-audit crack run -h
usage: main.py crack run [-h] -H HASHES -C CAMPAIGN -G CAMPAIGN_NAME [--resume] [--debug]

Execute a Hashcat password recovery campaign using the supplied hash dataset and campaign configuration file.

options:
  -h, --help            show this help message and exit

required arguments:
  -H, --hashes HASHES   Hash file to crack
  -C, --campaign CAMPAIGN
                        Campaign configuration file
  -G, --campaign-name CAMPAIGN_NAME
                        Campaign identifier

optional arguments:
  --resume              Resume an interrupted campaign (default: False)
  --debug               Display verbose Hashcat output (default: False)

    Example:

        password-audit crack run \
            -H ntds-organiser/ntlm-hashes.txt \
            -C config.json \
            -G internal-audit
```

Once a campaign configuration has been validated and estimated, it can be executed using the `run` command:

```bash
password-audit crack run \
    --campaign campaign.json \
    --hashes ntds-organiser/ntlm-hashes.txt \
    --campaign-name internal-password-audit
```

Campaign execution generates a results file named after the campaign identifier (e.g. `internal-password-audit-results.json`) containing statistics for every executed phase.

## Stats

The `stats` command displays historical performance data gathered from previous campaigns.

```bash
$ password-audit crack stats -h
usage: main.py crack stats [-h]

Display statistics for previously executed cracking campaigns, 
including password recovery counts, attack performance, and campaign history.

options:
  -h, --help  show this help message and exit

Example:

    password-audit crack stats
```

Historical campaign data is archived automatically and used to provide:

* Historical attack statistics
* Recovery metrics
* Return on investment (ROI) calculations
* Campaign duration estimates

For example:

```bash
$ password-audit crack stats

                                           Attack Statistics

| Phase         | Runs | Avg Duration | Avg Recovery | Avg ROI (pwd/min) | Best Recovery | Best ROI (pwd/min) |
|---------------|------|--------------|--------------|-------------------|---------------|--------------------|
| hashmob-rule  |    2 |   26h 8m 52s |         13.0 |              0.01 |            24 |               0.02 |
| loopback-rule |   58 |           3s |         0.55 |              7.77 |            23 |             296.35 |
| rockyou       |   62 |           3s |         1.24 |             15.87 |            65 |             739.78 |
| rockyou-rule  |   20 |        1m 3s |          3.1 |             42.56 |            34 |             503.28 |
```

## Additional Flags

### Resume

The `--resume` flag resumes an interrupted campaign and skips phases that completed successfully during the previous execution.

!!! note 
    The resume workflow is currently being refined and may change in future releases.

```bash
$ password-audit crack run \
    -H ntds-organiser/ntlm-hashes.txt \
    -C config.json \
    -G test-resume

[*] Password Audit Crack

[*] Phase 1/3
    Wordlist : rockyou.txt

    ---------------------------------------------------------------------------
    Status    : Exhausted
    Recovered : 87/164 (53.05%) Digests (total), 0/164 (0.00%) Digests (new)
    Progress  : 14344384/14344384 (100.00%)
    Speed     : 22301.5 kH/s (0.62ms) @ Accel:320 Loops:1 Thr:256 Vec:1
    ETA       : Mon Aug 17 10:21:57 2026 (0 secs)
    ---------------------------------------------------------------------------


[*] Phase 2/3
    Wordlist : rockyou.txt
    Rule     : OneRuleToRuleThemStill.rule
^C
[!] Campaign interrupted

    Current Phase       : rockyou-rule
    Session             : test-rich-crack-run-rockyou-rule
```

The campaign can then be resumed:

```bash
$ password-audit crack run \
    -H ntds-organiser/ntlm-hashes.txt \
    -C config.json \
    -G test-resume \
    --resume

[*] Password Audit Crack

[+] Resuming interrupted campaign
    Skipping            : rockyou


[*] Phase 1/2
    Wordlist : rockyou.txt
    Rule     : OneRuleToRuleThemStill.rule
...
```

Previously completed phases are skipped automatically.

### Debug

The `--debug` flag displays the full Hashcat commands used during campaign execution. This can be useful for troubleshooting, validating file paths, and verifying Hashcat arguments:

```bash
$ password-audit crack run \
    -H ntds-organiser/ntlm-hashes.txt \
    -C config.json \
    -G test-debug \
    --debug

[*] Password Audit Crack

[*] Phase 1/3
    Wordlist : rockyou.txt

[+] Executing:
/mnt/c/tools/hashcat/hashcat.exe -m 1000 \
    C:\ntds-organiser\ntlm-hashes.txt \
    C:\tools\hashcat\wordlists\rockyou.txt \
    --potfile-path C:\tools\hashcat\hashcat.potfile \
    -O -w 3 -d 1 \
    --status --status-timer 300 \
    --session test-debug-rockyou
...
```