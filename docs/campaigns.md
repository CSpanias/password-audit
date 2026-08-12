# Campaigns

Campaigns define how password recovery attacks are executed.

A campaign consists of:

* Global parameters
* One or more attack phases

Campaigns are written in JSON and supplied to the cracking module using:

```bash
password-audit crack run -C campaign.json
```

## Campaign Structure

A campaign contains two top-level sections:

* parameters
    * `hashMode`: Specifies the Hashcat hash mode.
    * `hashcatDir`: Overrides the default Hashcat installation directory.
    * `hashcatBinary`: Overrides the Hashcat executable path.
    * `flags`: Additional Hashcat command-line arguments.
* phases
    * `id`: Unique identifier for the phase.
    * `enabled`: Enable or disable a phase.
    * `type`: Dictionary (`wordlist`) or loopback (`loopback`) attack.
    * `wordlist`: Wordlist file used by the phase. (required only if `"type": "wordlist"`)
    * `rule`: Rule file to be used by the phase.

Phases are executed sequentially in the order they are defined.

Example `config.json` file:

```json
{
    "parameters": {
        "hashMode": "1000"
    },
    "phases": [
        {
            "id": "rockyou",
            "type": "wordlist",
            "wordlist": "rockyou.txt"
        },
        {
            "id": "rockyou-rule",
            "type": "wordlist",
            "wordlist": "rockyou.txt",
            "rule": "best66.rule"
        },
        {
            "id": "loopback-rule",
            "type": "loopback",
            "rule": "OneRuleToRuleThemStill.rule"
        }
    ]
}
```

Loopback phases generate a temporary dictionary from passwords recovered during previous phases. If no passwords have been recovered, the loopback phase is skipped automatically.

## Campaign Validation

Campaigns are validated before execution. Validation includes:

* Required parameter checks
* Required phase fields
* Valid phase types
* Duplicate phase detection
* Enabled phase validation

Invalid configurations will be rejected before Hashcat execution begins.

## Historical Statistics

Campaign execution results are archived automatically. Historical data is used to provide:

* Attack statistics
* Recovery metrics
* ROI tracking
* Campaign duration estimates

Display attack statistics:

```bash
password-audit crack stats
```

Estimate campaign duration:

```bash
password-audit crack estimate -C campaign.json
```