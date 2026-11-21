# Username-Derived Passwords

Identifies recovered passwords containing an account's username or a
recognised variation of it.

## What it checks

Password Audit looks for username-derived content within each recovered
password, rather than only testing whether the whole password equals the
username.

## How it works

The domain prefix is removed and the username is compared case-insensitively.
For names in `firstname.lastname` form, the check also derives variants such
as the individual components and concatenated names. Variants shorter than
three characters are excluded. Common character substitutions, such as `@`
for `a`, are normalised before substring matching.

## Why it matters

Usernames are often discoverable, and password candidates based on them are
straightforward to generate. Using account-related information can therefore
make a password easier to guess.

## Interpreting results

The check covers only its derived variants and recognised substitutions; it
does not identify every possible username-based construction. A substring
match can be coincidental, particularly for short names. Review individual
examples in context.

## Findings

| Finding ID | Title |
| --- | --- |
| PWD-PATTERN-001 | Username-Derived Passwords |

## References

- [NIST SP 800-63B: password selection](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [NCSC: password policy guidance](https://www.ncsc.gov.uk/collection/passwords/updating-your-approach)
