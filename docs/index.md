# Password Audit

Password Audit is a command-line toolkit for authorised Active Directory
password assessments. The recommended `audit` command organises the data,
runs configured recovery campaigns, analyses recovered passwords, and
generates reports.

## Recommended workflow

[Install](installation.md) the package and prepare an NTDS export, a BloodHound ZIP export, Hashcat,
and a [campaign configuration](crack.md#campaign-configuration).

!!! tip "Example campaigns"
    The repository includes
    [NTLM](https://github.com/CSpanias/password-audit/blob/main/example-ntlm-config.json),
    [LM](https://github.com/CSpanias/password-audit/blob/main/example-lm-config.json),
    and [dual NTLM/LM](https://github.com/CSpanias/password-audit/blob/main/example-dual-config.json)
    campaign examples. The campaign file must include an `ntlm` section. An 
    optional `lm` section enables LM recovery; see the [Audit guide](audit.md) 
    for the workflow details.

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
[Company-specific terms](audit.md#company-specific-terms) for more details.

Each audit writes its datasets, `password-audit-report.html` and structured
`password-audit-findings.json` sidecar to a new directory under `password-audit/`.

## End-to-end workflow

The `audit` command orchestrates the following stages:

1. Organise NTDS and BloodHound data into a new `password-audit/<run-id>/` directory.
2. Recover NTLM (and optionally LM) passwords using the enabled phases in the 
   NTLM campaign.
3. Map recovered passwords to accounts.
4. Analyse the mapped data
5. Export the selected reports.

## Advanced standalone workflows

Use these commands when you need to run or repeat only part of the workflow.
They remain available independently; for a typical assessment, start with
[`audit`](audit.md).

| Guide | Use it to |
| --- | --- |
| [Organise](organise.md) | Prepare NTDS/BloodHound artefacts or map an existing Hashcat potfile. |
| [Crack](crack.md) | Run a single campaign or review and share campaign statistics. |
| [Analyse](analyse.md) | Re-analyse mapped passwords and regenerate reports. |
| [LM](lm.md) | Map recovered LM passwords or generate LM-derived candidates. |

## Learn more

See the [workflow](knowledge-base/password-audits.md) for collection and
assessment stages, [Checks](checks/index.md) for what the analysis examines,
and [Wordlists and rules](knowledge-base/wordlists-and-rules.md) for recovery
resources.