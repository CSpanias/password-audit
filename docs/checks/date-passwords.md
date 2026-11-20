# Date-Related Passwords

Identifies recovered passwords containing selected days, months, or seasons.

## What it checks

Password Audit looks for English day names, month names, and seasonal terms
within recovered passwords.

## How it works

The check performs a case-insensitive substring search using built-in lists of
days, months, and seasons. A password can match more than one term.

## Why it matters

Date-related words are memorable and can be used in predictable password
construction. Common seasonal or calendar terms are also easy to include in
guessing candidates.

## Interpreting results

The check does not detect every date format: numeric dates or years alone are
not evaluated by this check. Substring matches can be coincidental, especially
for short terms such as `may` or `fall`. The presence of a term alone does
not measure the strength of the entire password.

## Findings

| Finding ID | Title |
| --- | --- |
| PWD-PATTERN-004 | Date-Based Passwords |

## References

- [NCSC: the logic behind three random words](https://www.ncsc.gov.uk/blog-post/the-logic-behind-three-random-words)
- [NIST SP 800-63B: password selection](https://pages.nist.gov/800-63-4/sp800-63b.html)
