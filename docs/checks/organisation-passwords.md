# Organisation-Related Passwords

Identifies recovered passwords containing organisation-related terms.

## What it checks

Password Audit searches recovered passwords for terms derived from collected
domain information and any supplied organisation-specific wordlist.

## How it works

The organiser generates basic terms from domain names and NTDS account
prefixes. A curated company-word list can supplement those terms. Analysis
compares terms and passwords case-insensitively, normalises common character
substitutions, and records the longest matching term for each password.

See [Analyse](../analyse.md) for company-word input options and
[Organise](../organise.md) for the generated list.

## Why it matters

Organisation names, brands, locations, and other familiar terms can often be
discovered and used to construct targeted password guesses.

## Interpreting results

The generated list is only a starting point; a curated list can improve
coverage. The check cannot identify terms absent from its inputs or all
possible transformations. Short or common terms can match coincidentally,
so review the examples and the selected wordlist in context.

## Findings

| Finding ID | Title |
| --- | --- |
| PWD-PATTERN-002 | Organisation-Related Passwords |

## References

- [NCSC: password policy guidance](https://www.ncsc.gov.uk/collection/passwords/updating-your-approach)
- [NIST SP 800-63B: password selection](https://pages.nist.gov/800-63-4/sp800-63b.html)
