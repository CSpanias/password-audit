# Password audit workflow

A password audit assesses the strength and reuse of passwords in an
environment by analysing password-hash datasets and recovered
credentials. The results can help prioritise improvements to password
policies, account practices, and privileged-account protection.

## Prerequisites

Collecting data for an Active Directory password audit typically requires
access to a domain controller and a Domain Administrator account. The exact
permissions and access depend on the collection method and environment.

The Password Audit workflow also requires an NTDS export, a BloodHound ZIP
export, Hashcat, a campaign configuration, and the wordlists and rules
referenced by that configuration. See the [audit guide](../audit.md) for
the tool's prerequisites.

!!! info "Use `ad-kit`!"
    [ad-kit](https://github.com/CSpanias/ad-kit) can collect both datasets 
    through its interactive `enum` command.

## Workflow

1. **Extract:** Run `ad-kit enum` and select RustHound collection and the
   NTDS dump to obtain a BloodHound ZIP and an NTDS hash export. The hashes
   provide the input for password recovery, while the domain data adds
   account and policy context. See the [ad-kit enumeration guide](https://cspanias.github.io/ad-kit/commands/enum/)
   for collection details and [Password Audits Part 1](https://mollysec.com/posts/password-audits-part-1/)
   for more on NTDS extraction methods. Password Audit consumes these exports;
   it does not run the collection tools.
2. **Organise:** Prepare the hashes and supporting account data for the
   remaining stages. The `audit` command writes them to a new
   `password-audit/<run-id>/` directory. The [Organise guide](../organise.md)
   describes the generated datasets;
   [Password Audits Part 2](https://mollysec.com/posts/password-audits-part-2/)
   provides further context on organising the data.
3. **Recover:** Run NTLM and, optionally, LM campaigns against the hashes
   using wordlists and rules suited to the assessment. The
   [Crack guide](../crack.md) covers campaign configuration, and
   [Wordlists and rules](wordlists-and-rules.md) discusses
   candidate selection. For more context on password recovery, read
   [Password Audits Part 3](https://mollysec.com/posts/password-audits-part-3/).
4. **Analyse:** Map recovered passwords back to accounts, review patterns and
   weaknesses, run applicable hash-based checks, and export the reports. The
   [Analyse guide](../analyse.md) describes the findings and reports;
   [Password Audits Part 4](https://mollysec.com/posts/password-audits-part-4/)
   provides further context on analysis.

The recommended [`audit`](../audit.md) command orchestrates organisation,
recovery, mapping, and analysis after the data has been collected.

## Recommended workflow

[Install](../installation.md) Password Audit and prepare an NTDS export, a
BloodHound ZIP export, Hashcat, and a
[campaign configuration](../crack.md#campaign-configuration).

!!! tip "Example campaigns"
    The repository includes
    [NTLM](https://github.com/CSpanias/password-audit/blob/main/example-ntlm-config.json),
    [LM](https://github.com/CSpanias/password-audit/blob/main/example-lm-config.json),
    and [dual NTLM/LM](https://github.com/CSpanias/password-audit/blob/main/example-dual-config.json)
    campaign examples. The campaign file must include an `ntlm` section. An
    optional `lm` section enables LM recovery; see the [Audit guide](../audit.md)
    for the workflow details.

```bash
password-audit audit \
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign campaign.json \
    --campaign-name internal-audit
```

For stronger organisation-specific analysis, optionally prepare
`./company-words.txt` with around 10–20 terms based on what you know about the
company. The audit adds these terms to its basic domain/account-derived list
and reminds you if the curated file appears unchanged since the previous run.
Generated terms are still used without it. See
[Company-specific terms](../audit.md#company-specific-terms) for details.

To include the optional offline Pwned Passwords check, add
`--hibp /path/to/ntlm-ranges`. It compares enabled-account NT hashes, including
those whose passwords were not recovered. See
[Passwords in Breach Data](../checks/breached-passwords.md) for the dataset
format and its limitations.

Each audit writes its datasets, `password-audit-report.html`, and structured
`password-audit-findings.json` sidecar to a new directory under `password-audit/`.

For partial or repeated stages, see the standalone
[Organise](../organise.md), [Crack](../crack.md), [Analyse](../analyse.md), and
[LM](../lm.md) guides.
