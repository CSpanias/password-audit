# Password Statistics

Summarises recovery, password frequency, length, and character composition
across the supplied datasets.

## What it checks

Password Audit reports the number of recovered and unique passwords, the
recovery rate, frequently observed passwords, password length distribution,
and adoption of lowercase, uppercase, numeric, and special characters.

## How it works

The recovery rate compares the number of mapped recovered passwords with the
supplied enabled-user count. Other statistics count recovered plaintext
values. Character-class percentages are calculated independently: a password
can contribute to more than one class.

## Why it matters

Statistics help describe the outcome of the campaign and highlight common
password-selection practices. They provide context for findings such as
[password reuse](password-reuse.md) and
[password length compliance](password-length.md).

## Interpreting results

Recovered passwords are not a representative sample by default: campaign
choices influence which passwords are recovered. Recovery rate is meaningful
only when the mapped passwords and enabled-user list cover the same population;
an absent or zero enabled-user count is not evidence that recovery failed.

Character-class percentages are descriptive, not an entropy calculation or
a separate complexity-policy compliance test. A password using several
character classes can still be predictable. Unrecovered passwords are not
necessarily strong.

Strict composition rules can encourage predictable substitutions or make
passwords harder to remember, increasing the temptation to store them
insecurely. Consider usable passphrases and screening against known weak or
compromised passwords instead of relying on character classes alone.

## Findings

| Finding ID | Title |
| --- | --- |
| PWD-AUDIT-001 | Password Audit |
| PWD-STATS-001 | Password Statistics |

## References

- [NIST SP 800-63B: password strength](https://pages.nist.gov/800-63-4/sp800-63b.html#appA)
- [NIST SP 800-63B: password complexity](https://pages.nist.gov/800-63-4/sp800-63b.html#complexity)
- [NCSC: password policy guidance](https://www.ncsc.gov.uk/collection/passwords/updating-your-approach)
