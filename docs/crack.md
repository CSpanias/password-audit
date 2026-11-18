# Crack campaigns

The `crack` commands run Hashcat campaigns, provide an estimate command based
on prior runs, and summarise campaign history. Use them only for hashes you are
authorised to assess.

| Command | Purpose |
| --- | --- |
| `password-audit crack run` | Run an NTLM-only or LM-only campaign. |
| `password-audit crack estimate` | Experimental phase estimates (currently limited; see below). |
| `password-audit crack stats` | Experimental historical phase statistics. |

For combined NTLM and LM recovery, use the end-to-end
[`audit`](audit.md) workflow.

## Campaign configuration

Campaigns are JSON files with an `ntlm` section and, optionally, an `lm`
section. Each section contains parameters and an ordered list of phases.

```json
{
  "ntlm": {
    "parameters": {
      "hashMode": "1000",
      "hashcatDir": "/path/to/hashcat",
      "hashcatBinary": "/path/to/hashcat/hashcat",
      "flags": []
    },
    "phases": [
      {
        "id": "wordlist",
        "type": "wordlist",
        "wordlist": "rockyou.txt",
        "rule": "best64.rule",
        "enabled": true
      },
      {
        "id": "loopback",
        "type": "loopback",
        "wordlist": "loopback.txt",
        "rule": "best64.rule",
        "enabled": true
      }
    ]
  }
}
```

Set `hashcatDir` and `hashcatBinary` to match the local Hashcat installation.
The current default directory is `/mnt/c/pentest/tools/hashcat`; set both
values explicitly on systems where that path or the default `hashcat.exe`
name does not apply. Wordlists and rules are resolved relative to
`hashcatDir/wordlists/` and `hashcatDir/rules/`, respectively. Common hash
modes are `1000` for NTLM and `3000` for LM.

### Parameters and phases

| Field | Description |
| --- | --- |
| `hashMode` | Required Hashcat mode for the campaign. |
| `hashcatDir` | Hashcat data directory; defaults to `/mnt/c/pentest/tools/hashcat`. |
| `hashcatBinary` | Hashcat executable; defaults to `hashcat.exe` under `hashcatDir`. |
| `flags` | Additional Hashcat arguments as a JSON list of strings. |
| `id` | Required, unique phase identifier. |
| `type` | `wordlist` or `loopback`. |
| `enabled` | Whether to run the phase; defaults to `true`. |
| `wordlist` | Required for every phase. Used as input for `wordlist` phases and as a label for loopback phases. |
| `rule` | Optional for `wordlist` phases and required for `loopback` phases; path is relative to `hashcatDir/rules/`. |

A `loopback` phase builds a temporary wordlist from passwords already in the
Hashcat potfile. It is skipped when no passwords are available. Campaign
configuration is validated before execution; invalid or duplicate phase
definitions are rejected.

!!! tip "Example files"
    The repository includes [NTLM](https://github.com/CSpanias/password-audit/blob/main/example-ntlm-config.json),
    [LM](https://github.com/CSpanias/password-audit/blob/main/example-lm-config.json),
    and [dual NTLM/LM](https://github.com/CSpanias/password-audit/blob/main/example-dual-config-small.json)
    campaign examples.

## Run a campaign

```bash
password-audit crack run \
    --hashes password-audit/ntlm-hashes.txt \
    --campaign campaign.json \
    --campaign-name internal-audit
```

`crack run` requires a campaign file containing either `ntlm` or `lm`, but not
both. To run both campaign types as part of one workflow, use `audit`.

| Option | Purpose |
| --- | --- |
| `-H`, `--hashes` | Hash dataset to process. |
| `-C`, `--campaign` | Campaign JSON file. |
| `-G`, `--campaign-name` | Identifier for campaign sessions and results. |
| `--debug` | Show verbose Hashcat output. |

Results are written beside the hash dataset as
`<campaign-name>-results.json`. A timestamped copy is archived under
`~/.password-audit/history/`. Hashcat maintains its potfile in the configured
Hashcat directory. Campaigns cannot be resumed; use a new campaign name to
start an interrupted campaign again from its first phase.

## Estimate duration

The estimator is intended to use average phase durations from prior campaign
history. **Known limitation:** campaign statistics are keyed by both hash mode
and phase ID, while the estimator looks them up by phase ID alone. As a result,
phase durations currently appear as unknown. This command and `stats` are
experimental; use `stats` only for an exploratory view of recorded history.

```bash
password-audit crack estimate --campaign campaign.json
```

Estimates are most useful after representative runs have been recorded for the
campaign's phase identifiers.

## Review statistics

The statistics command summarises recorded campaign phases, including run
counts, average duration and recovery, return on investment, and best results.

```bash
password-audit crack stats
```

Use `password-audit crack --help` or a subcommand's `--help` option for the
installed version's complete argument list.
