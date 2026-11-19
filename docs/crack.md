# Crack campaigns

The `crack` commands run Hashcat campaigns, provide an estimate command based
on prior runs, and summarise campaign history.

| Command | Purpose |
| --- | --- |
| `password-audit crack run` | Run an NTLM-only or LM-only campaign. |
| `password-audit crack estimate` | Estimate phase durations from compatible local runs. |
| `password-audit crack stats` | Review, export, or import campaign statistics. |

For combined NTLM and LM recovery, use the end-to-end
[`audit`](audit.md) workflow.
For guidance on choosing datasets and mutation rules, see
[Wordlists and rules](knowledge-base/wordlists-and-rules.md).

## Campaign configuration

!!! tip "Example campaigns"
    The repository includes separate
    [NTLM](https://github.com/CSpanias/password-audit/blob/main/example-ntlm-config.json)
    and [LM](https://github.com/CSpanias/password-audit/blob/main/example-lm-config.json)
    campaign examples. Adjust paths, wordlists, rules, and Hashcat flags for
    your system. For combined recovery with `audit`, use the
    [dual campaign example](https://github.com/CSpanias/password-audit/blob/main/example-dual-config.json).

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
The current default directory is `/mnt/c/tools/hashcat`; set both
values explicitly on systems where that path or the default `hashcat.exe`
name does not apply. 

Wordlists and rules are resolved relative to `hashcatDir/wordlists/` and 
`hashcatDir/rules/`, respectively.

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
| `statistics` | Optional public wordlist and rule labels for comparing phase statistics. |

A `loopback` phase builds a temporary wordlist from passwords already in the
Hashcat potfile. It is skipped when no passwords are available. 

Campaign configuration is validated before execution; invalid or duplicate 
phase definitions are rejected.

### Labels for statistics

Add explicit labels only for **public** assets. Both a name and a version are
required; use consistent labels across contributors. Names and versions are
identifiers containing letters, digits, `.`, `_` or `-`, up to 64 characters.
These example labels are placeholders; replace them with the versions actually
used:

```json
{
  "id": "my-phase",
  "type": "wordlist",
  "wordlist": "public-words.txt",
  "rule": "public-rule.rule",
  "statistics": {
    "wordlist": {"name": "public-words", "version": "2026-01"},
    "rule": {"name": "public-rule", "version": "v1"}
  }
}
```

Changing the phase ID does not change the statistical identity. Labels are
contributor-reported and are not checked against file contents. A changed asset
must receive a new version label. Unlabelled wordlists and rules are treated as
private; loopback wordlists are always treated separately. Private and loopback
inputs appear only in broad categories, not as identical attacks.

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

Results are written beside the hash dataset as `<campaign-name>-results.json`. 
A timestamped copy is archived under `~/.password-audit/history/`. Hashcat 
maintains its potfile in the configured Hashcat directory.

Campaigns cannot be resumed; use a new campaign name to start an interrupted 
campaign again from its first phase.

## Estimate duration

Estimates use the median duration of completed **local** phases with matching
public labels, hash mode, phase position and Hashcat settings, including
device-selection flags. Imported statistics are not used for time estimates.

Without comparable measured runs, the duration is
`Unknown`. Unlabelled inputs, loopback phases and unrecognised Hashcat flags 
are not matched. A total with missing phases is marked partial.

```bash
password-audit crack estimate --campaign campaign.json
```

Hardware is not tracked, so changing machines or devices can make local
estimates less representative. Hash counts and earlier recoveries also affect
how long a phase runs.

## Review statistics

The statistics command groups measured phases by public labels, hash mode,
attack type and optimized-kernel setting. It shows sample counts, median
recovery yield, median recoveries per minute, and observed phase positions.

Yield is the number of newly recovered Hashcat digests divided by the digests
remaining at the start of the phase. These are not account counts or
necessarily complete passwords; LM mode works with hash halves. A zero
denominator is `Unknown`.

```bash
password-audit crack stats
```

Other Hashcat flags are recorded only as an indication that additional
settings were used; phases with unrecognised flags are not treated as exact
matches. Private and loopback inputs are shown as broad categories whose
results may come from different wordlists and rules. 

Prior phases, existing potfile entries, hardware and the input population 
affect the results, so these statistics indicate trends rather than prove the 
best campaign order.

Phases without usable statistics, including older history and phases with
missing or inconsistent Hashcat recovery counts, are excluded rather than
being counted as zero. Only completed campaigns are archived for statistics;
partial campaign results remain beside the hash dataset if a run is interrupted.

## Share statistics

Sharing is manual and opt-in; the tool never uploads statistics. Export local
measured phases to a new file, review it, and share it separately:

```bash
password-audit crack stats --export stats-to-share.json
password-audit crack stats --import stats-from-a-colleague.json
```

Exports contain only a random record ID, hash mode, attack category, explicit
public labels, selected settings, phase position, recovery counts and duration.
They do **not** contain passwords, hashes, customer names, paths, campaign or
phase IDs, raw flags or exact timestamps.

Never put private information in a public label. Counts and combinations of 
fields can still be sensitive or linkable, especially for small assessments; 
review the file and your sharing requirements before sending it.

Imported records are stored locally in `~/.password-audit/imported-statistics.json`
and included in `crack stats`. Re-importing the same records does not count
them twice; conflicting records are rejected. 

Exports contain local runs only, not records imported from others. Existing 
output files are not overwritten.

Use `password-audit crack --help` or a subcommand's `--help` option for the
installed version's complete argument list.
