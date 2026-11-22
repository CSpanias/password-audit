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
structure and example campaigns. An LM-only campaign is for standalone
`crack run`; it cannot be used with `audit` unless an `ntlm` section is added.

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
During analysis, progress advances as checks complete. When breach-data
matching is enabled, a separate bar tracks the required NTLM ranges.

Before password recovery, the audit checks whether a usable domain minimum
password length is available. If not, it asks whether to continue without
the password length compliance check. The report identifies the check as
unavailable. Non-interactive runs stop instead of assuming consent; supply
a policy with `--pass-policy` to run the check without a prompt.

SureFormat export also requires a domain name in the policy. If it is
unavailable, the audit stops before recovery and asks for a policy containing
the domain name.

The organising summary shows counts of enabled, unfiltered NTDS accounts matched
to each selected privileged group, including Domain Admins. Accounts in multiple
groups appear in each group's count.

Domain qualifiers are omitted, so counts combine groups with the same name 
across domains and count each matched account once per group name. Incomplete 
or unavailable coverage is reported with its reasons. See 
`privileged-users.json` in the run directory for memberships and warnings.

The report also identifies matching NTLM hashes across enabled, unfiltered
user accounts, including passwords that were not recovered. Hash-based and
recovered-password reuse findings may overlap; their counts should not be added.

If BloodHound contains multiple domains, an interactive run asks you to
confirm the NTDS source domain. See [Organise](organise.md) for matching
details and non-interactive behaviour.

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

During organisation, it prints a reminder when no curated list is found and
warns when the file's name, size, and modification time appear unchanged since
the previous audit.
Only its filename and file metadata are stored in 
`password-audit/.company-words-state.json` for this reminder; the curated terms 
are not copied into that state file. The curated list is optional.

Review the list for each assessment; using the same list can be appropriate
when reassessing the same company. 

## Workflow

See the [password audit workflow](knowledge-base/password-audits.md#workflow)
for the assessment stages and [Privileged Account Passwords](checks/privileged-accounts.md)
for the privileged findings and their limitations.

An LM campaign is optional; existing LM recoveries may still be mapped without
one. See [LM workflows](lm.md#lm-recovery-and-mapping) for how the audit
selects the Hashcat binary and potfile.

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
| `--hibp` | Local Pwned Passwords NTLM range directory for an offline comparison | None |

Pass `--hibp` with the path to a local NTLM range directory to include the
optional [Passwords in Breach Data](checks/breached-passwords.md) check:

```bash
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign campaign.json \
    --campaign-name internal-audit \
    --hibp /path/to/ntlm-ranges
```

The check uses the run's organised NTDS user records, including hashes whose
passwords were not recovered, and does not make network requests. See the
check guide for dataset download instructions, format, and limitations.

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
