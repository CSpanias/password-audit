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
   remaining stages. The [Organise guide](../organise.md) describes the
   generated datasets; [Password Audits Part 2](https://mollysec.com/posts/password-audits-part-2/)
   provides further context on organising the data.
3. **Recover:** Run a campaign against the hashes using wordlists and rules
   suited to the assessment. The [Crack guide](../crack.md) covers campaign
   configuration, and [Wordlists and rules](wordlists-and-rules.md) discusses
   candidate selection. For more context on password recovery, read
   [Password Audits Part 3](https://mollysec.com/posts/password-audits-part-3/).
4. **Analyse:** Map recovered passwords back to accounts, review patterns and
   weaknesses, and report the results. The [Analyse guide](../analyse.md)
   describes the findings and reports; [Password Audits Part 4](https://mollysec.com/posts/password-audits-part-4/)
   provides further context on analysis.

The recommended [`audit`](../audit.md) command orchestrates organisation,
recovery, mapping, and analysis after the data has been collected.
