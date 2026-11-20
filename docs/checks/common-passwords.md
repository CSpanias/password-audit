# Common Password Terms

Identifies recovered passwords containing selected commonly used password
terms.

## What it checks

Password Audit searches for a small built-in set of terms, including
`password`, `welcome`, and `admin`, within recovered passwords.

## How it works

The check lowercases each recovered password and normalises common character
substitutions before looking for the built-in terms as substrings. For example,
a simple substitution in a familiar term can still be detected.

## Why it matters

Common words and predictable variants are frequently represented in password
guessing and cracking datasets. Their use can reduce the effort needed to
recover credentials.

## Interpreting results

This is a fixed, limited set of terms, not a comprehensive breached-password
lookup or a test of every dictionary word. A substring match is an indicator
for review, not a complete assessment of password strength. A password without
a match is not necessarily strong.

## Findings

| Finding ID | Title |
| --- | --- |
| PWD-PATTERN-003 | Common Passwords |

## References

- [NIST SP 800-63B: password blocklists](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [NCSC: password policy guidance](https://www.ncsc.gov.uk/collection/passwords/updating-your-approach)
