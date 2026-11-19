# End-to-end audit

The `audit` command is the recommended way to run a complete assessment. It
validates inputs, organises NTDS and BloodHound data, runs configured Hashcat
campaigns, maps recovered passwords, and generates analysis reports.

Use it only with data you are authorised to assess. Hashcat campaigns consume
the wordlists, rules, hardware, and other resources specified in the campaign
configuration.

## Prerequisites

- An NTDS export and a BloodHound ZIP export.
- Hashcat and the wordlists/rules referenced by the campaign.
- A campaign JSON file with an `ntlm` section. An optional `lm` section enables
  LM recovery when LM hashes are present.

See [Campaign configuration](crack.md#campaign-configuration) for the JSON
structure. The repository includes
[NTLM](https://github.com/CSpanias/password-audit/blob/main/example-ntlm-config.json)
and [dual NTLM/LM](https://github.com/CSpanias/password-audit/blob/main/example-dual-config.json)
campaign examples for `audit`. Adjust paths, wordlists, rules, and Hashcat
flags for your system.

## Run an audit

```bash
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign campaign.json \
    --campaign-name internal-audit
```

By default, the command generates:

- `password-audit-report.html`, an offline dashboard with filters and
  **Copy Markdown** controls for the report narrative
- `password-audit-findings.json`, the findings sidecar

The offline HTML report is always generated. Pass `--csacyber` to write
`password-audit-findings.xml` in SureFormat instead of the JSON sidecar.
See [Reports](analyse.md#reports) for requirements and mapping limitations.

## Company-specific terms

The organiser generates a basic `password-audit/company-words.txt` list from
domain and account data. It does not infer a realistic company vocabulary.
For more useful organisation-specific password analysis, you can optionally
create `./company-words.txt` with roughly 10–20 terms tailored to the company
under assessment. The audit automatically adds that file when present; you can
also provide another path with `--company-words`:

```text
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign campaign.json \
    --campaign-name internal-audit \
    --company-words ./company-words.txt
```

Curated terms supplement the generated list and are deduplicated
case-insensitively. The audit does not modify or regenerate your curated file.
It prints a reminder when no curated list is found and warns when the file's
name, size, and modification time appear unchanged since the previous audit.
Review the list for each assessment; using the same list can be appropriate
when reassessing the same company. Only its filename and file metadata are
stored in `password-audit/.company-words-state.json` for this reminder; the
curated terms are not copied into that state file. The curated list is optional.

## Workflow

The audit runs the following stages:

1. **Validate** the NTDS file, BloodHound export, and campaign configuration.
2. **Organise** the datasets into `password-audit/`, including NTLM hashes,
   enabled users, Domain Administrators, and policy data.
3. **Recover NTLM passwords** using the enabled NTLM campaign phases.
4. **Recover LM passwords**, when LM hashes are present and an LM campaign is
   configured. The workflow also uses Hashcat `--show` output to reconstruct
   and map recovered LM passwords.
5. **Map and analyse** recovered passwords, then write the requested reports.

If LM hashes are present but no LM campaign is configured, the LM cracking
stage is skipped. Existing LM recoveries can still be mapped when available in
the configured Hashcat potfile.

## Options

| Option | Purpose | Default |
| --- | --- | --- |
| `-N`, `--ntds` | NTDS export | Required |
| `-B`, `--bloodhound` | BloodHound ZIP export | Required |
| `-C`, `--campaign` | Campaign JSON file | Required |
| `-G`, `--campaign-name` | Identifier used for campaign results | Required |
| `-F`, `--filter` | Comma-separated usernames to exclude | None |
| `-M`, `--mapped-ntlm-passwords` | Recovered NTLM password mapping file | `password-audit/mapped-ntlm-passwords.txt` |
| `-U`, `--lm-users` | LM-hash account list | `password-audit/lm-users.txt` |
| `-L`, `--mapped-lm-passwords` | Recovered LM password mapping file | `password-audit/mapped-lm-passwords.txt` |
| `-D`, `--domain-admins` | Domain Administrator account list | `password-audit/domain-admins.txt` |
| `-P`, `--pass-policy` | Domain password policy | `password-audit/domain-policy.txt` |
| `-W`, `--company-words` | Optional curated terms added to the generated list | `./company-words.txt` when present; otherwise none |
| `-E`, `--enabled-users` | Enabled account list | `password-audit/enabled-users.txt` |
| `--csacyber` | Export SureFormat XML findings instead of JSON | Disabled |

Paths are relative to the current working directory unless given as absolute
paths. Use `password-audit audit --help` for the installed version's complete
option list.

## Outputs and advanced standalone commands

Organised datasets and campaign result files are written under
`password-audit/`. Existing files in the former `ntds-organiser/` directory
are left untouched and are not migrated or used as a fallback. An interrupted
campaign cannot be resumed; use a new campaign name to start from its first
phase. Campaign history is also archived in
`~/.password-audit/history/` for the estimate and statistics commands.

Hashcat phases display live progress, recovered counts, speed, and ETA. Status
is refreshed every five seconds.

For manual or partial workflows, these standalone commands remain available:

- [Organise](organise.md) prepares datasets and can map an existing NTLM
  potfile.
- [Crack](crack.md) runs and tracks a single campaign.
- [Analyse](analyse.md) analyses mapped password datasets and renders reports.
- [LM](lm.md) documents the standalone LM mapping and candidate-generation
  commands.
