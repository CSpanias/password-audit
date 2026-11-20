# End-to-end audit

The `audit` command is the recommended way to run a complete assessment. It
validates inputs, organises NTDS and BloodHound data, runs configured Hashcat
campaigns, maps recovered passwords, and generates analysis reports.

Use it only with data you are authorised to assess. Hashcat campaigns consume
the wordlists, rules, hardware, and other resources specified in the campaign
configuration.

## Prerequisites

!!! important "Check Paths!"
    Remember to adjust paths, wordlists, rules, and Hashcat flags for your system.

- An NTDS export and a BloodHound ZIP export.
- Hashcat and the wordlists/rules referenced by the campaign.
- A campaign JSON file with an `ntlm` section. An optional `lm` section enables
  LM recovery when LM hashes are present.

See [Campaign configuration](crack.md#campaign-configuration) for the JSON
structure. The repository includes
[NTLM](https://github.com/CSpanias/password-audit/blob/main/example-ntlm-config.json)
and [dual NTLM/LM](https://github.com/CSpanias/password-audit/blob/main/example-dual-config.json)
campaign examples for `audit`. The
[LM-only example](https://github.com/CSpanias/password-audit/blob/main/example-lm-config.json)
is for standalone `crack run`; it cannot be used with `audit` unless an `ntlm`
section is added.

## Run an audit

```bash
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign campaign.json \
    --campaign-name internal-audit
```

Each audit creates a timestamped directory under `password-audit/` and prints
its path. If that name already exists, a numeric suffix is added. Organised
datasets, campaign results and reports for that run are kept together there.
The organising summary shows the number of matched privileged accounts,
including Domain Admins, and indicates incomplete or unavailable coverage.
See `privileged-users.json` in the run directory for memberships and warnings.
By default, the reports are:

- `password-audit-report.html`, an offline dashboard with filters and
  Copy Markdown controls used for reporting (always generated)
- `password-audit-findings.json`, the findings sidecar

## Company-specific terms

The organiser generates a basic `password-audit/<run-id>/company-words.txt` list from
domain and account data. It does not infer a realistic company vocabulary.

For more useful organisation-specific password analysis, you can optionally
create `./company-words.txt` with roughly 10–20 terms tailored to the company
under assessment. 

The audit automatically adds that file when present; you can also provide 
another path with `--company-words`:

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
Only its filename and file metadata are stored in 
`password-audit/.company-words-state.json` for this reminder; the curated terms 
are not copied into that state file. The curated list is optional.

Review the list for each assessment; using the same list can be appropriate
when reassessing the same company. 

## Workflow

The audit runs the following stages:

1. Validate the NTDS file, BloodHound export, and campaign configuration.
2. Organise the datasets into the run directory, including NTLM hashes,
   enabled users, Domain Administrators, selected privileged group memberships,
   and policy data.
3. Recover NTLM passwords using the enabled NTLM, and optionally LM, campaign phases.
4. Map and analyse recovered passwords.
5. Write the requested reports.

The report includes recovered NTLM passwords belonging to members of selected
privileged groups, with group membership and masked passwords. Nested groups
are included where present in the BloodHound collection. Identifiable gaps or
ambiguous matches are reported as incomplete; group membership alone does not
cover every privileged account or attack path. See
[Analyse](analyse.md#what-is-analysed) for the group list and limitations.

If LM hashes are present but no LM campaign is configured, the LM cracking
stage is skipped. Existing LM recoveries can still be mapped when available in
the NTLM campaign's Hashcat potfile. When an LM campaign is configured, its
Hashcat binary and potfile are used to reconstruct LM recoveries.

## Options

Paths are relative to the current working directory unless given as absolute
paths. Use `password-audit audit --help` for the installed version's complete
option list.

| Option | Purpose | Default |
| --- | --- | --- |
| `-N`, `--ntds` | NTDS export | Required |
| `-B`, `--bloodhound` | BloodHound ZIP export | Required |
| `-C`, `--campaign` | Campaign JSON file | Required |
| `-G`, `--campaign-name` | Identifier used for campaign results | Required |
| `-F`, `--filter` | Comma-separated usernames to exclude | None |
| `-M`, `--mapped-ntlm-passwords` | Recovered NTLM password mapping file | `password-audit/<run-id>/mapped-ntlm-passwords.txt` |
| `-U`, `--lm-users` | LM-hash account list | `password-audit/<run-id>/lm-users.txt` |
| `-L`, `--mapped-lm-passwords` | Recovered LM password mapping file | `password-audit/<run-id>/mapped-lm-passwords.txt` |
| `-D`, `--domain-admins` | Domain Administrator account list | `password-audit/<run-id>/domain-admins.txt` |
| `-P`, `--pass-policy` | Domain password policy | `password-audit/<run-id>/domain-policy.txt` |
| `-W`, `--company-words` | Optional curated terms added to the generated list | `./company-words.txt` when present; otherwise none |
| `-E`, `--enabled-users` | Enabled account list | `password-audit/<run-id>/enabled-users.txt` |

## Outputs and advanced standalone commands

Organised datasets, campaign result files and reports are written under
`password-audit/<run-id>/`. Existing files in `password-audit/` or previous
run directories are not used as defaults. Hashcat potfiles remain in their
configured directories and may contain recoveries from previous campaigns.

An interrupted campaign cannot be resumed; a new audit starts in a new run
directory from its first phase. Hashcat session names include the run ID.
Campaign history is also archived in
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
