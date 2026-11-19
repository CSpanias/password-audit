# Password Audit

Password Audit is a command-line toolkit for authorised Active Directory
password assessments. The recommended `audit` command organises the data,
runs configured recovery campaigns, analyses recovered passwords, and
generates reports.

## Recommended workflow

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

For the strongest organisation-specific analysis, optionally prepare
`./company-words.txt` with around 10–20 terms based on what you know about the
company. The audit adds these terms to its basic domain/account-derived list
and reminds you if the curated file appears unchanged since the previous run.
This list is optional; the generated terms are still used without it. See
[Company-specific terms](audit.md#company-specific-terms).

The audit writes `password-audit-report.html` and the structured
`password-audit-findings.json` sidecar.

!!! tip "Example campaigns"
    The repository includes [NTLM](https://github.com/CSpanias/password-audit/blob/main/example-ntlm-config.json),
    [LM](https://github.com/CSpanias/password-audit/blob/main/example-lm-config.json),
    and [dual NTLM/LM](https://github.com/CSpanias/password-audit/blob/main/example-dual-config-small.json)
    campaign examples.

## End-to-end workflow

The `audit` command orchestrates these stages:

1. **Organise** NTDS and BloodHound data into `password-audit/` artefacts.
2. **Recover** NTLM passwords using the enabled phases in the NTLM campaign.
3. **Recover LM passwords**, when LM hashes and an LM campaign are available.
4. **Map** recovered passwords to accounts. LM results are reconstructed with
   Hashcat `--show`.
5. **Analyse** the mapped data and write the selected reports.

The campaign file must include an `ntlm` section. An optional `lm` section
enables LM recovery; see the [Audit guide](audit.md) for the workflow details.

## Advanced standalone workflows

Use these commands when you need to run or repeat only part of the workflow.
They remain available independently; for a typical assessment, start with
[`audit`](audit.md).

| Guide | Use it to |
| --- | --- |
| [Organise](organise.md) | Prepare NTDS/BloodHound artefacts or map an existing Hashcat potfile. |
| [Crack](crack.md) | Run a single campaign or inspect experimental campaign statistics. |
| [Analyse](analyse.md) | Re-analyse mapped passwords and regenerate reports. |
| [LM](lm.md) | Map recovered LM passwords or generate LM-derived candidates. |

## Knowledge base

For assessment background and practical resources, see the
[password audit overview](knowledge-base/password-audits.md),
[tools](knowledge-base/tools.md), and
[wordlists and rules](knowledge-base/wordlists-and-rules.md).