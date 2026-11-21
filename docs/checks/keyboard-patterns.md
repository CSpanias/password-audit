# Keyboard Patterns

Identifies recovered passwords containing selected keyboard sequences.

## What it checks

Password Audit looks for built-in patterns such as `qwerty`, `asdf`, and
`qaz` within recovered passwords.

## How it works

The check compares each password case-insensitively against a fixed list of
keyboard patterns. Patterns are considered longest first, and one matching
pattern is recorded per password.

## Why it matters

Keyboard walks are easy to remember but also easy to include in password
guessing and cracking datasets. Predictable sequences can make credentials
easier to recover.

## Interpreting results

Only the built-in sequences are checked; the absence of a match does not rule
out other keyboard patterns or weak passwords. Short sequences can also
occur coincidentally inside otherwise unrelated strings. Review the complete
password pattern rather than treating a substring alone as a strength score.

## Findings

| Finding ID | Title |
| --- | --- |
| PWD-PATTERN-005 | Keyboard Patterns |

## References

- [NIST SP 800-63B: password selection](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [NCSC: password policy guidance](https://www.ncsc.gov.uk/collection/passwords/updating-your-approach)
