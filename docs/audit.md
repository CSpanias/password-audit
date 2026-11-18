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
and
[dual NTLM/LM](https://github.com/CSpanias/password-audit/blob/main/example-dual-config-small.json)
examples.

## Run an audit

```bash
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign campaign.json \
    --campaign-name internal-audit
```

By default, the command generates:

- `password-audit-report.md`
- `password-audit-report.html` — an offline dashboard with filters and
  **Copy Markdown** controls for the report narrative
- `password-audit-findings.json` — the findings sidecar

Choose a different report set with `--format`. Supported values are `markdown`,
`html`, `json`, `yaml`, and `sarif`. An explicit selection replaces the default:

```bash
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign campaign.json \
    --campaign-name internal-audit \
    --format json sarif
```

The `--format` option accepts one or more formats. The findings JSON sidecar is
written in addition to the selected report formats.

## Workflow

The audit runs the following stages:

1. **Validate** the NTDS file, BloodHound export, and campaign configuration.
2. **Organise** the datasets into `ntds-organiser/`, including NTLM hashes,
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
| `-M`, `--mapped-ntlm-passwords` | Recovered NTLM password mapping file | `ntds-organiser/mapped-ntlm-passwords.txt` |
| `-U`, `--lm-users` | LM-hash account list | `ntds-organiser/lm-users.txt` |
| `-L`, `--mapped-lm-passwords` | Recovered LM password mapping file | `ntds-organiser/mapped-lm-passwords.txt` |
| `-D`, `--domain-admins` | Domain Administrator account list | `ntds-organiser/domain-admins.txt` |
| `-P`, `--pass-policy` | Domain password policy | `ntds-organiser/domain-policy.txt` |
| `-W`, `--company-words` | Organisation-related terms | `ntds-organiser/company-words.txt` |
| `-E`, `--enabled-users` | Enabled account list | `ntds-organiser/enabled-users.txt` |
| `--format` | One or more report formats | `markdown html` |

Paths are relative to the current working directory unless given as absolute
paths. Use `password-audit audit --help` for the installed version's complete
option list.

## Outputs and standalone commands

Organised datasets and campaign result files are written under
`ntds-organiser/`. Campaign history is also archived in
`~/.password-audit/history/` for the estimate and statistics commands.

For manual or partial workflows, run the modules independently:

- [Organise](organise.md) prepares datasets and can map an existing NTLM
  potfile.
- [Crack](crack.md) runs and tracks a single campaign.
- [Analyse](analyse.md) analyses mapped password datasets and renders reports.
- [LM](lm.md) documents the standalone LM mapping and candidate-generation
  commands.
