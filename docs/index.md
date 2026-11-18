# Password Audit

Password Audit is a command-line toolkit for organising Active Directory
password data, running Hashcat campaigns, analysing recovered passwords, and
generating reports. Use it only with data you are authorised to assess.

## At a glance

| Command | Purpose |
| --- | --- |
| `audit` | Run the end-to-end workflow and generate reports. |
| `organise` | Parse NTDS and BloodHound exports; optionally map recovered NTLM passwords. |
| `crack` | Run Hashcat campaigns and review historical campaign statistics. |
| `analyse` | Analyse mapped passwords and export reports. |
| `lm` | Map recovered LM passwords or generate case variants for Domain Administrator passwords. |

## Quick start

Install the package and prepare an NTDS export, a BloodHound ZIP export, Hashcat,
and a campaign configuration. See [Installation](installation.md) and
[Campaign configuration](crack.md#campaign-configuration) for prerequisites.

```bash
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign campaign.json \
    --campaign-name internal-audit
```

By default, the audit writes `password-audit-report.md`,
`password-audit-report.html`, and `password-audit-findings.json`. To choose
formats explicitly, use `--format` followed by one or more of `markdown`,
`html`, `json`, `yaml`, or `sarif`.

!!! tip "Example campaigns"
    The repository includes [NTLM](https://github.com/CSpanias/password-audit/blob/main/example-ntlm-config.json),
    [LM](https://github.com/CSpanias/password-audit/blob/main/example-lm-config.json),
    and [dual NTLM/LM](https://github.com/CSpanias/password-audit/blob/main/example-dual-config-small.json)
    campaign examples.

## End-to-end workflow

The `audit` command orchestrates these stages:

1. **Organise** NTDS and BloodHound data into `ntds-organiser/` artefacts.
2. **Recover** NTLM passwords using the enabled phases in the NTLM campaign.
3. **Recover LM passwords**, when LM hashes and an LM campaign are available.
4. **Map** recovered passwords to accounts. LM results are reconstructed with
   Hashcat `--show`.
5. **Analyse** the mapped data and write the selected reports.

The campaign file must include an `ntlm` section. An optional `lm` section
enables LM recovery; see the [Audit guide](audit.md) for the workflow details.

## Choose a workflow

| Guide | Use it to |
| --- | --- |
| [End-to-end audit](audit.md) | Run the recommended workflow from input validation to reports. |
| [Organise](organise.md) | Prepare NTDS/BloodHound artefacts and map an existing Hashcat potfile. |
| [Crack](crack.md) | Configure campaigns, run phases, resume work, and inspect statistics. |
| [Analyse](analyse.md) | Review analysis coverage and select report formats. |
| [LM](lm.md) | Understand LM mapping and candidate generation. |
| [Installation](installation.md) | Install the CLI or set up a development environment. |
| [Development](development.md) | Explore the codebase and build the documentation locally. |